-- ============================================================
-- ACCESS VAULT – PHASE 1 RLS POLICIES (OWNER-ONLY)
-- ============================================================

-- USERS
CREATE POLICY "Users can view own profile"
ON public.users FOR SELECT
USING (auth.uid() = user_id);

CREATE POLICY "Users can update own profile"
ON public.users FOR UPDATE
USING (auth.uid() = user_id)
WITH CHECK (auth.uid() = user_id);

-- No client INSERT/DELETE; backend service_role handles registration.

-- FOLDERS
CREATE POLICY "Owners can view own folders"
ON public.folders FOR SELECT
USING (auth.uid() = owner_id);

-- Insert/update also require parent_id to be null or one of the user's own folders (migration 003).
CREATE POLICY "Owners can insert folders"
ON public.folders FOR INSERT
WITH CHECK (
  auth.uid() = owner_id
  AND (parent_id IS NULL OR EXISTS (
    SELECT 1 FROM public.folders p WHERE p.folder_id = folders.parent_id AND p.owner_id = auth.uid()
  ))
);

CREATE POLICY "Owners can update own folders"
ON public.folders FOR UPDATE
USING (auth.uid() = owner_id)
WITH CHECK (
  auth.uid() = owner_id
  AND (parent_id IS NULL OR EXISTS (
    SELECT 1 FROM public.folders p WHERE p.folder_id = folders.parent_id AND p.owner_id = auth.uid()
  ))
);

CREATE POLICY "Owners can delete own folders"
ON public.folders FOR DELETE
USING (auth.uid() = owner_id);

-- FILES
CREATE POLICY "Owners can view own files"
ON public.files FOR SELECT
USING (auth.uid() = owner_id);

CREATE POLICY "Owners can insert files"
ON public.files FOR INSERT
WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "Owners can update own files"
ON public.files FOR UPDATE
USING (auth.uid() = owner_id)
WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "Owners can delete own files"
ON public.files FOR DELETE
USING (auth.uid() = owner_id);

-- FILE_CHUNKS (access via file ownership)
CREATE POLICY "Owners can view chunks of own files"
ON public.file_chunks FOR SELECT
USING (
  EXISTS (
    SELECT 1 FROM public.files f
    WHERE f.file_id = file_chunks.file_id
      AND f.owner_id = auth.uid()
  )
);

CREATE POLICY "Owners can insert chunks of own files"
ON public.file_chunks FOR INSERT
WITH CHECK (
  EXISTS (
    SELECT 1 FROM public.files f
    WHERE f.file_id = file_chunks.file_id
      AND f.owner_id = auth.uid()
  )
);

CREATE POLICY "Owners can update chunks of own files"
ON public.file_chunks FOR UPDATE
USING (
  EXISTS (
    SELECT 1 FROM public.files f
    WHERE f.file_id = file_chunks.file_id
      AND f.owner_id = auth.uid()
  )
);

CREATE POLICY "Owners can delete chunks of own files"
ON public.file_chunks FOR DELETE
USING (
  EXISTS (
    SELECT 1 FROM public.files f
    WHERE f.file_id = file_chunks.file_id
      AND f.owner_id = auth.uid()
  )
);

-- SHARES
CREATE POLICY "Users can view shares involving them"
ON public.shares FOR SELECT
USING (auth.uid() = shared_by OR auth.uid() = shared_with);

CREATE POLICY "Users can create shares they own"
ON public.shares FOR INSERT
WITH CHECK (auth.uid() = shared_by);

CREATE POLICY "Users can update shares they created"
ON public.shares FOR UPDATE
USING (auth.uid() = shared_by)
WITH CHECK (auth.uid() = shared_by);

CREATE POLICY "Users can delete shares they created"
ON public.shares FOR DELETE
USING (auth.uid() = shared_by);

-- KEY_ENVELOPES
CREATE POLICY "Recipients can view own key envelopes"
ON public.key_envelopes FOR SELECT
USING (auth.uid() = recipient_id);

CREATE POLICY "Owners can insert key envelopes for own resources"
ON public.key_envelopes FOR INSERT
WITH CHECK (
  EXISTS (
    SELECT 1 FROM public.folders f
    WHERE f.folder_id = key_envelopes.resource_id
      AND key_envelopes.resource_type = 'folder'
      AND f.owner_id = auth.uid()
  )
  OR EXISTS (
    SELECT 1 FROM public.files f
    WHERE f.file_id = key_envelopes.resource_id
      AND key_envelopes.resource_type = 'file'
      AND f.owner_id = auth.uid()
  )
);

CREATE POLICY "Owners can delete key envelopes for own resources"
ON public.key_envelopes FOR DELETE
USING (
  EXISTS (
    SELECT 1 FROM public.folders f
    WHERE f.folder_id = key_envelopes.resource_id
      AND key_envelopes.resource_type = 'folder'
      AND f.owner_id = auth.uid()
  )
  OR EXISTS (
    SELECT 1 FROM public.files f
    WHERE f.file_id = key_envelopes.resource_id
      AND key_envelopes.resource_type = 'file'
      AND f.owner_id = auth.uid()
  )
);

-- AUDIT_LOGS
CREATE POLICY "Users can view own audit logs"
ON public.audit_logs FOR SELECT
USING (auth.uid() = user_id);