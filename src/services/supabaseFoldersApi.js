// Minimal folder calls, used by the "Backend check" panel to prove that the signed-in
// session works with Row Level Security. The real file explorer (Phase 3) replaces this.

import { ApiError } from './apiClient.js';
import { ERROR_CODES } from './contract.js';
import { getSupabase } from './supabaseClient.js';

function fail(error) {
  console.error('[supabase]', error);
  return new ApiError(ERROR_CODES.UNKNOWN, error.message || 'Something went wrong. Please try again.', error.status ?? 0);
}

export async function listFolders() {
  const { data, error } = await getSupabase()
    .from('folders')
    .select('folder_id, name, path, created_at')
    .order('created_at', { ascending: false });
  if (error) throw fail(error);
  return data;
}

export async function createFolder(ownerId, name) {
  const { data, error } = await getSupabase()
    .from('folders')
    .insert({ owner_id: ownerId, name, path: `/${name}` })
    .select('folder_id, name, path, created_at')
    .single();
  if (error) throw fail(error);
  return data;
}
