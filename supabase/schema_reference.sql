-- WARNING: This schema is for context only and is not meant to be run.
-- Table order and constraints may not be valid for execution.

CREATE TABLE public.users (
  user_id uuid NOT NULL,
  name text NOT NULL,
  email text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  salt text NOT NULL,
  kdf_params jsonb NOT NULL,
  public_key text NOT NULL,
  wrapped_private_key text NOT NULL,
  role text NOT NULL DEFAULT 'STANDARD_USER'::text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT users_pkey PRIMARY KEY (user_id),
  CONSTRAINT users_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.folders (
  folder_id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL,
  parent_id uuid,
  name text,
  path text,
  name_enc text,
  wrapped_key text,
  is_shared boolean NOT NULL DEFAULT false,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT folders_encrypted_name_only CHECK (name IS NULL AND path IS NULL AND name_enc IS NOT NULL),
  CONSTRAINT folders_pkey PRIMARY KEY (folder_id),
  CONSTRAINT folders_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES public.users(user_id),
  CONSTRAINT folders_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.folders(folder_id)
);
CREATE TABLE public.files (
  file_id uuid NOT NULL DEFAULT gen_random_uuid(),
  folder_id uuid NOT NULL,
  owner_id uuid NOT NULL,
  name text,
  name_enc text,
  size bigint NOT NULL,
  type text,
  encrypted boolean NOT NULL DEFAULT true,
  chunk_count integer NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT files_encrypted_name_only CHECK (name IS NULL AND type IS NULL AND name_enc IS NOT NULL),
  CONSTRAINT files_pkey PRIMARY KEY (file_id),
  CONSTRAINT files_folder_id_fkey FOREIGN KEY (folder_id) REFERENCES public.folders(folder_id),
  CONSTRAINT files_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES public.users(user_id)
);
CREATE TABLE public.file_chunks (
  chunk_id uuid NOT NULL DEFAULT gen_random_uuid(),
  file_id uuid NOT NULL,
  chunk_index integer NOT NULL,
  iv text NOT NULL,
  storage_ref text NOT NULL,
  size integer NOT NULL,
  checksum text,
  CONSTRAINT file_chunks_pkey PRIMARY KEY (chunk_id),
  CONSTRAINT file_chunks_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.files(file_id)
);
CREATE TABLE public.shares (
  share_id uuid NOT NULL DEFAULT gen_random_uuid(),
  resource_id uuid NOT NULL,
  resource_type text NOT NULL CHECK (resource_type = ANY (ARRAY['folder'::text, 'file'::text])),
  shared_by uuid NOT NULL,
  shared_with uuid NOT NULL,
  level text NOT NULL CHECK (level = ANY (ARRAY['VIEWER'::text, 'OWNER'::text])),
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  expires_at timestamp with time zone,
  revoked_at timestamp with time zone,
  CONSTRAINT shares_pkey PRIMARY KEY (share_id),
  CONSTRAINT shares_shared_by_fkey FOREIGN KEY (shared_by) REFERENCES public.users(user_id),
  CONSTRAINT shares_shared_with_fkey FOREIGN KEY (shared_with) REFERENCES public.users(user_id)
);
CREATE TABLE public.key_envelopes (
  envelope_id uuid NOT NULL DEFAULT gen_random_uuid(),
  resource_id uuid NOT NULL,
  resource_type text NOT NULL CHECK (resource_type = ANY (ARRAY['folder'::text, 'file'::text])),
  recipient_id uuid NOT NULL,
  wrapped_key text NOT NULL,
  ephemeral_public_key text,
  role text NOT NULL DEFAULT 'OWNER'::text CHECK (role = ANY (ARRAY['OWNER'::text, 'VIEWER'::text])),
  key_version integer NOT NULL DEFAULT 1,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  expires_at timestamp with time zone,
  CONSTRAINT key_envelopes_pkey PRIMARY KEY (envelope_id),
  CONSTRAINT key_envelopes_recipient_id_fkey FOREIGN KEY (recipient_id) REFERENCES public.users(user_id)
);
CREATE TABLE public.audit_logs (
  log_id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  action text NOT NULL,
  resource_id uuid,
  resource_type text,
  timestamp timestamp with time zone NOT NULL DEFAULT now(),
  details jsonb,
  CONSTRAINT audit_logs_pkey PRIMARY KEY (log_id),
  CONSTRAINT audit_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id)
);