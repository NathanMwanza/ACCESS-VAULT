-- ============================================================
-- ACCESS VAULT - 003: folders can only hold encrypted names, and only nest under your own folders
-- Run once in: Supabase dashboard > SQL Editor. Safe to re-run. Run AFTER 002.
--
-- 1. Zero-trust guard: a folder row must carry an encrypted name (name_enc) and must NOT carry
--    a plaintext name or path. This stops the old "Test folder" style rows from coming back.
-- 2. Nesting guard: the INSERT/UPDATE policies only checked owner_id, so a user could set
--    parent_id to a folder they do not own. Now parent_id must be null or one of their own folders.
-- ============================================================

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'folders_encrypted_name_only') then
    alter table public.folders
      add constraint folders_encrypted_name_only
      check (name is null and path is null and name_enc is not null);
  end if;
end $$;

drop policy if exists "Owners can insert folders" on public.folders;
create policy "Owners can insert folders"
on public.folders for insert
with check (
  auth.uid() = owner_id
  and (
    parent_id is null
    or exists (
      select 1 from public.folders p
      where p.folder_id = folders.parent_id and p.owner_id = auth.uid()
    )
  )
);

drop policy if exists "Owners can update own folders" on public.folders;
create policy "Owners can update own folders"
on public.folders for update
using (auth.uid() = owner_id)
with check (
  auth.uid() = owner_id
  and (
    parent_id is null
    or exists (
      select 1 from public.folders p
      where p.folder_id = folders.parent_id and p.owner_id = auth.uid()
    )
  )
);
