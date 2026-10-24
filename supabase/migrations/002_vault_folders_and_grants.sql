-- ============================================================
-- ACCESS VAULT - 002: encrypted folders and key grants (vault folder at registration)
-- Run once in: Supabase dashboard > SQL Editor > New query. Safe to re-run.
-- Run AFTER 001_auth_integration.sql.
--
-- WHY
--  authFlow.js (src/services/) creates the user's top-level "Vault" folder when they register.
--  Its name is encrypted in the browser and its AES key is wrapped to the user's own public
--  key. The old tables could not hold that:
--   - folders.name / folders.path were NOT NULL plaintext columns
--   - key_envelopes had no place for the ECDH ephemeral public key that unwrapping needs
--
-- WHAT CHANGES
--  folders:        + name_enc (encrypted name, base64 IV||ciphertext)
--                  + wrapped_key (a subfolder's key wrapped under its parent; null for the vault root)
--                  name and path become optional (the old Backend-check panel still fills them)
--  key_envelopes:  + ephemeral_public_key (base64 raw P-256 point, needed by unwrapFromUser)
--                  + role OWNER | VIEWER
-- The RLS policies in policies.sql already cover these tables; no policy changes are needed.
-- ============================================================

alter table public.folders
  alter column name drop not null,
  alter column path drop not null;

alter table public.folders
  add column if not exists name_enc text,
  add column if not exists wrapped_key text;

alter table public.key_envelopes
  add column if not exists ephemeral_public_key text,
  add column if not exists role text not null default 'OWNER';

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'key_envelopes_role_check') then
    alter table public.key_envelopes
      add constraint key_envelopes_role_check check (role in ('OWNER', 'VIEWER'));
  end if;
end $$;

-- One key per person per resource version. Stops the same grant being saved twice.
create unique index if not exists key_envelopes_unique_grant
  on public.key_envelopes (resource_type, resource_id, recipient_id, key_version);

-- Speeds up getVault(): "my root folders".
create index if not exists folders_owner_root_idx
  on public.folders (owner_id) where parent_id is null;
