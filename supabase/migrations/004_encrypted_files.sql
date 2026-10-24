-- ============================================================
-- ACCESS VAULT - 004: encrypted files (names, chunk storage rules)
-- Run once in: Supabase dashboard > SQL Editor. Safe to re-run. Run AFTER 003.
--
-- 1. files.name_enc: the file name is encrypted in the browser (with the file's own key).
--    files.name / files.type become optional and must stay empty, like folders (migration 003).
-- 2. file_chunks: one row per (file, index), and a size cap that matches the 'chunks' bucket.
-- 3. FIX storage policies on the 'chunks' bucket. They looked up the file with
--    storage.foldername(f.name), but inside that sub-query `name` means files.name (the file's name),
--    not the storage object's path, so even the owner's own upload was denied. Now qualified as objects.name.
--
-- Object path convention: files/<file_id>/<chunk_index>   (e.g. files/3f2c.../0)
-- ============================================================

-- ---------- 1. encrypted file names ----------
alter table public.files
  alter column name drop not null;

alter table public.files
  add column if not exists name_enc text;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'files_encrypted_name_only') then
    alter table public.files
      add constraint files_encrypted_name_only
      check (name is null and type is null and name_enc is not null);
  end if;
end $$;

-- ---------- 2. chunks ----------
create unique index if not exists file_chunks_unique_index
  on public.file_chunks (file_id, chunk_index);

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'file_chunks_size_check') then
    -- 5 MiB of plaintext + 16-byte GCM tag; the bucket limit is 5,243,904.
    alter table public.file_chunks
      add constraint file_chunks_size_check check (size >= 16 and size <= 5243904);
  end if;
end $$;

create index if not exists files_folder_idx on public.files (folder_id);

-- ---------- 3. storage policies (bucket 'chunks') ----------
drop policy if exists "chunks owner can upload" on storage.objects;
create policy "chunks owner can upload"
on storage.objects for insert to authenticated
with check (
  bucket_id = 'chunks'
  and (storage.foldername(objects.name))[1] = 'files'
  and exists (
    select 1 from public.files f
    where f.file_id::text = (storage.foldername(objects.name))[2]
      and f.owner_id = auth.uid()
      and f.status = 'uploading'
  )
);

drop policy if exists "chunks owner can read" on storage.objects;
create policy "chunks owner can read"
on storage.objects for select to authenticated
using (
  bucket_id = 'chunks'
  and (storage.foldername(objects.name))[1] = 'files'
  and exists (
    select 1 from public.files f
    where f.file_id::text = (storage.foldername(objects.name))[2]
      and f.owner_id = auth.uid()
  )
);

drop policy if exists "chunks owner can update" on storage.objects;
create policy "chunks owner can update"
on storage.objects for update to authenticated
using (
  bucket_id = 'chunks'
  and (storage.foldername(objects.name))[1] = 'files'
  and exists (
    select 1 from public.files f
    where f.file_id::text = (storage.foldername(objects.name))[2]
      and f.owner_id = auth.uid() and f.status = 'uploading'
  )
)
with check (
  bucket_id = 'chunks'
  and (storage.foldername(objects.name))[1] = 'files'
  and exists (
    select 1 from public.files f
    where f.file_id::text = (storage.foldername(objects.name))[2]
      and f.owner_id = auth.uid() and f.status = 'uploading'
  )
);

drop policy if exists "chunks owner can delete" on storage.objects;
create policy "chunks owner can delete"
on storage.objects for delete to authenticated
using (
  bucket_id = 'chunks'
  and (storage.foldername(objects.name))[1] = 'files'
  and exists (
    select 1 from public.files f
    where f.file_id::text = (storage.foldername(objects.name))[2]
      and f.owner_id = auth.uid()
  )
);
