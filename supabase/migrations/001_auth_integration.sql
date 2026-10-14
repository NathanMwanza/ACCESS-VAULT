-- ============================================================
-- ACCESS VAULT - 001: connect the React frontend to Supabase Auth
-- Run once in: Supabase dashboard > SQL Editor > New query.
--
-- WHAT CHANGES
--  1. The browser no longer sends the real password. It sends authSecret
--     (derived in the browser) as the Supabase Auth "password".
--  2. Registration stores the crypto fields (salt, KDF params, public key,
--     wrapped private key) via a trigger, so it works even when email
--     confirmation is on (no session exists yet at sign-up).
--  3. get_auth_params(email) lets the login screen fetch the salt BEFORE it
--     can compute authSecret (docs/OPEN_QUESTIONS.md #1).
--  4. Users can no longer edit their own role, keys or email.
--
-- BEFORE YOU RUN: find the trigger you already have on auth.users.
--   select tgname, pg_get_triggerdef(oid)
--   from pg_trigger
--   where tgrelid = 'auth.users'::regclass and not tgisinternal;
-- If its name is not on_auth_user_created, add a matching
--   drop trigger if exists <that name> on auth.users;
-- below. Two triggers inserting the same user would make sign-up fail.
-- ============================================================

-- ---------- 1. users table ----------
-- Supabase Auth already stores the password hash (of authSecret) in auth.users.
-- A second copy here is redundant, so stop requiring it.
alter table public.users alter column password_hash drop not null;

-- ---------- 2. sign-up trigger ----------
drop trigger if exists on_auth_user_created on auth.users;

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  meta jsonb := coalesce(new.raw_user_meta_data, '{}'::jsonb);
begin
  if coalesce(meta->>'kdf_salt', '') = ''
     or coalesce(meta->>'public_key', '') = ''
     or coalesce(meta->>'wrapped_private_key', '') = ''
     or coalesce(meta->>'kdf_iterations', '') !~ '^[0-9]+$' then
    raise exception 'missing_crypto_fields';
  end if;

  insert into public.users
    (user_id, name, email, salt, kdf_params, public_key, wrapped_private_key)
  values (
    new.id,
    coalesce(nullif(meta->>'name', ''), split_part(new.email, '@', 1)),
    lower(new.email),
    meta->>'kdf_salt',
    jsonb_build_object(
      'iterations', (meta->>'kdf_iterations')::int,
      'prf', 'PBKDF2-HMAC-SHA-256'
    ),
    meta->>'public_key',
    meta->>'wrapped_private_key'
  );
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------- 3. login: fetch salt before computing authSecret ----------
-- Unknown emails get a deterministic fake salt so the response cannot be used
-- to discover which emails have accounts.
-- CHANGE THE PEPPER below to any long random string of your own.
create or replace function public.get_auth_params(p_email text)
returns table (kdf_salt text, kdf_iterations integer)
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_email  text := lower(trim(p_email));
  v_salt   text;
  v_iter   integer;
  v_pepper constant text := 'CHANGE-ME-av-fake-salt-pepper-2026';
begin
  select u.salt, nullif(u.kdf_params->>'iterations', '')::int
    into v_salt, v_iter
  from public.users u
  where lower(u.email) = v_email;

  if v_salt is null then
    v_salt := encode(
      substring(sha256(convert_to(v_pepper || ':' || v_email, 'utf8')) from 1 for 16),
      'base64'
    );
    v_iter := 600000;
  end if;

  return query select v_salt, coalesce(v_iter, 600000);
end;
$$;

revoke all on function public.get_auth_params(text) from public;
grant execute on function public.get_auth_params(text) to anon, authenticated;

-- ---------- 4. stop users editing their own role / keys / email ----------
-- The existing UPDATE policy lets a signed-in user change ANY column of their
-- own row, including role. Limit it to the display name.
revoke update on public.users from anon, authenticated;
grant update (name) on public.users to authenticated;

-- ============================================================
-- OPTIONAL CLEAN-UP: delete accounts made with the old HTML test pages.
-- They were registered with a plain password and have placeholder keys, so
-- they cannot log in through the new flow. THIS DELETES ALL DATA. Test data only.
--
-- truncate public.audit_logs, public.key_envelopes, public.shares,
--          public.file_chunks, public.files, public.folders, public.users cascade;
-- delete from auth.users;
-- ============================================================
