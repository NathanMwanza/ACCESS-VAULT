-- ============================================================
-- ACCESS VAULT - 005: sharing folders (read-only) with another user, and revoking
-- Run once in: Supabase dashboard > SQL Editor. Safe to re-run. Run AFTER 004.
--
-- HOW SHARING WORKS (zero-trust)
--   The owner's browser wraps the folder's AES key to the recipient's public key (ECDH, Algorithm 4.3)
--   and sends only that wrapped key. This file adds what the server must enforce:
--    - who may read what: a share on a folder covers every subfolder and file under it
--    - an atomic "share" (share row + key grant together) and "revoke" (cut access + delete the grant)
--    - narrow lookups so users can find a recipient and see their own shares without reading other users' rows
--   Shares are read-only (VIEWER) and may expire. The server never sees a key.
--   Non-owners can read files only once their upload is complete.
--
-- SECURITY FIXES (from the Supabase security advisor)
--   - handle_new_user() was callable through the API by anyone; it is only meant to be the sign-up trigger
--   - get_user_public_key() was callable by signed-out users (account-enumeration risk)
--   - public.shares could be INSERTed/UPDATEd directly by clients. An UPDATE could re-point a share at
--     someone else's folder, so shares are now written only through the functions below.
-- ============================================================

-- ---------- 1. lock down functions ----------
revoke execute on function public.handle_new_user() from public, anon, authenticated;
revoke execute on function public.get_user_public_key(text) from public, anon;
grant execute on function public.get_user_public_key(text) to authenticated;

-- ---------- 2. shares are written only by the functions below ----------
revoke insert, update, delete on public.shares from anon, authenticated;

-- 002 created key_envelopes_unique_grant, but the table already had an identical unique index
-- (key_envelopes_unique_version), so keep just one.
drop index if exists public.key_envelopes_unique_grant;

create unique index if not exists shares_one_active_per_recipient
  on public.shares (resource_type, resource_id, shared_with)
  where revoked_at is null;

-- ---------- 3. a share on a folder covers everything below it ----------
create or replace function public.has_folder_access(p_folder_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  with recursive up as (
    select f.folder_id, f.parent_id, 1 as depth
    from public.folders f where f.folder_id = p_folder_id
    union all
    select f.folder_id, f.parent_id, up.depth + 1
    from public.folders f join up on f.folder_id = up.parent_id
    where up.depth < 50
  )
  select exists (
    select 1
    from up
    join public.shares s on s.resource_id = up.folder_id and s.resource_type = 'folder'
    where s.shared_with = auth.uid()
      and s.revoked_at is null
      and (s.expires_at is null or s.expires_at > now())
  );
$$;
revoke execute on function public.has_folder_access(uuid) from public, anon;
grant execute on function public.has_folder_access(uuid) to authenticated;

-- folders: owner, or shared on this folder or any parent
drop policy if exists "Users can view own or shared folders" on public.folders;
create policy "Users can view own or shared folders"
on public.folders for select to authenticated
using (auth.uid() = owner_id or public.has_folder_access(folder_id));

-- files: owner, or (once the upload is complete) a shared file or a file in a shared folder (or under one)
drop policy if exists "Users can view own or shared files" on public.files;
create policy "Users can view own or shared files"
on public.files for select to authenticated
using (
  auth.uid() = owner_id
  or (status = 'complete' and (public.has_active_share(file_id, 'file') or public.has_folder_access(folder_id)))
);

-- encrypted chunks: readable by anyone who can see the file row (the sub-query goes through the files policy above)
drop policy if exists "chunks owner can read" on storage.objects;
drop policy if exists "chunks readable when the file is visible" on storage.objects;
create policy "chunks readable when the file is visible"
on storage.objects for select to authenticated
using (
  bucket_id = 'chunks'
  and (storage.foldername(objects.name))[1] = 'files'
  and exists (
    select 1 from public.files f
    where f.file_id::text = (storage.foldername(objects.name))[2]
  )
);

-- ---------- 4. functions ----------
-- Find someone to share with. Returns nothing for unknown emails and for yourself.
create or replace function public.find_user_for_share(p_email text)
returns table (user_id uuid, public_key text, name text)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then raise exception 'not_signed_in'; end if;
  return query
    select u.user_id, u.public_key, u.name
    from public.users u
    where lower(u.email) = lower(trim(p_email)) and u.user_id <> auth.uid();
end;
$$;

-- Share a folder: the share row and the wrapped key are saved together or not at all.
create or replace function public.share_resource(
  p_resource_type text,
  p_resource_id uuid,
  p_recipient_id uuid,
  p_level text,
  p_wrapped_key text,
  p_ephemeral_public_key text,
  p_expires_at timestamptz default null
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_share uuid;
  v_parent uuid;
begin
  if auth.uid() is null then raise exception 'not_signed_in'; end if;
  if p_resource_type <> 'folder' then raise exception 'only_folders_can_be_shared'; end if;
  if p_level <> 'VIEWER' then raise exception 'only_read_only_sharing'; end if;
  if p_recipient_id = auth.uid() then raise exception 'cannot_share_with_yourself'; end if;
  if coalesce(p_wrapped_key, '') = '' or coalesce(p_ephemeral_public_key, '') = '' then raise exception 'missing_key'; end if;
  if not exists (select 1 from public.users where user_id = p_recipient_id) then raise exception 'recipient_not_found'; end if;
  if p_expires_at is not null and p_expires_at <= now() then raise exception 'expiry_in_past'; end if;
  if not public.owns_resource(p_resource_id, p_resource_type) then raise exception 'not_your_folder'; end if;

  select parent_id into v_parent from public.folders where folder_id = p_resource_id;
  if v_parent is null then raise exception 'cannot_share_vault_root'; end if;

  if exists (
    select 1 from public.shares
    where resource_type = p_resource_type and resource_id = p_resource_id
      and shared_with = p_recipient_id and revoked_at is null
  ) then raise exception 'already_shared'; end if;

  insert into public.shares (resource_id, resource_type, shared_by, shared_with, level, expires_at)
  values (p_resource_id, p_resource_type, auth.uid(), p_recipient_id, p_level, p_expires_at)
  returning share_id into v_share;

  -- replace any stale grant left from an earlier share
  delete from public.key_envelopes
  where resource_type = p_resource_type and resource_id = p_resource_id and recipient_id = p_recipient_id;

  insert into public.key_envelopes (resource_id, resource_type, recipient_id, wrapped_key, ephemeral_public_key, role, expires_at)
  values (p_resource_id, p_resource_type, p_recipient_id, p_wrapped_key, p_ephemeral_public_key, p_level, p_expires_at);

  return v_share;
end;
$$;

-- Revoke: the server stops serving the folder to them and deletes their wrapped key.
create or replace function public.revoke_share(p_share_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  s public.shares%rowtype;
begin
  if auth.uid() is null then raise exception 'not_signed_in'; end if;
  select * into s from public.shares
  where share_id = p_share_id and shared_by = auth.uid() and revoked_at is null
  for update;
  if not found then raise exception 'share_not_found'; end if;

  update public.shares set revoked_at = now() where share_id = p_share_id;
  delete from public.key_envelopes
  where resource_type = s.resource_type and resource_id = s.resource_id and recipient_id = s.shared_with;
end;
$$;

-- Who a folder is currently shared with (only for its owner).
create or replace function public.list_shares_for_resource(p_resource_id uuid, p_resource_type text default 'folder')
returns table (share_id uuid, shared_with uuid, recipient_email text, recipient_name text, level text, created_at timestamptz, expires_at timestamptz)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then raise exception 'not_signed_in'; end if;
  if not public.owns_resource(p_resource_id, p_resource_type) then raise exception 'not_your_folder'; end if;
  return query
    select s.share_id, s.shared_with, u.email, u.name, s.level, s.created_at, s.expires_at
    from public.shares s join public.users u on u.user_id = s.shared_with
    where s.resource_id = p_resource_id and s.resource_type = p_resource_type and s.revoked_at is null
      and (s.expires_at is null or s.expires_at > now())
    order by s.created_at;
end;
$$;

-- What has been shared with me, and by whom.
create or replace function public.get_shared_with_me()
returns table (share_id uuid, resource_type text, resource_id uuid, level text, created_at timestamptz,
               owner_id uuid, owner_name text, owner_email text, expires_at timestamptz)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then raise exception 'not_signed_in'; end if;
  return query
    select s.share_id, s.resource_type, s.resource_id, s.level, s.created_at, s.shared_by, u.name, u.email, s.expires_at
    from public.shares s join public.users u on u.user_id = s.shared_by
    where s.shared_with = auth.uid() and s.revoked_at is null
      and (s.expires_at is null or s.expires_at > now())
    order by s.created_at desc;
end;
$$;

revoke execute on function public.find_user_for_share(text) from public, anon;
revoke execute on function public.share_resource(text, uuid, uuid, text, text, text, timestamptz) from public, anon;
revoke execute on function public.revoke_share(uuid) from public, anon;
revoke execute on function public.list_shares_for_resource(uuid, text) from public, anon;
revoke execute on function public.get_shared_with_me() from public, anon;
grant execute on function public.find_user_for_share(text) to authenticated;
grant execute on function public.share_resource(text, uuid, uuid, text, text, text, timestamptz) to authenticated;
grant execute on function public.revoke_share(uuid) to authenticated;
grant execute on function public.list_shares_for_resource(uuid, text) to authenticated;
grant execute on function public.get_shared_with_me() to authenticated;
