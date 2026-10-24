// File calls used by fileFlow.js. Everything stored is ciphertext: the name is encrypted (name_enc),
// the file key is wrapped under the folder key, and every chunk is AES-GCM ciphertext in the private
// 'chunks' Storage bucket at   files/<fileId>/<chunkIndex>.
//
// Needs supabase/migrations/004_encrypted_files.sql. RLS and the Storage policies are the real boundary:
// only the file's owner can write chunks (and only while status = 'uploading') or read them.

import { ApiError } from './apiClient.js';
import { ERROR_CODES } from './contract.js';
import { getSupabase } from './supabaseClient.js';

const BUCKET = 'chunks';
export const chunkPath = (fileId, index) => `files/${fileId}/${index}`;

function fail(error) {
  console.error('[supabase]', error);
  const network = error?.name === 'AuthRetryableFetchError' || /failed to fetch|network/i.test(String(error?.message ?? ''));
  return network
    ? new ApiError(ERROR_CODES.NETWORK_ERROR, 'Could not reach the server. Check your connection and try again.')
    : new ApiError(ERROR_CODES.UNKNOWN, 'Something went wrong. Please try again.', error?.status ?? error?.statusCode ?? 0);
}

async function currentUserId() {
  const { data, error } = await getSupabase().auth.getSession();
  const id = data?.session?.user?.id;
  if (error || !id) throw new ApiError(ERROR_CODES.INVALID_CREDENTIALS, 'Please sign in again.', 401);
  return id;
}

const toFile = (r) => ({
  id: r.file_id,
  folderId: r.folder_id,
  nameEnc: r.name_enc,
  size: r.size,
  chunkCount: r.chunk_count,
  wrappedFileKey: r.wrapped_file_key,
  baseNonce: r.base_nonce,
  createdAt: r.created_at,
});
const FILE_COLUMNS = 'file_id, folder_id, name_enc, size, chunk_count, wrapped_file_key, base_nonce, created_at';

/** Starts an upload: saves the file row with status 'uploading'. The browser picks fileId (it is bound into every chunk's AAD). */
export async function createFile({ fileId, folderId, nameEnc, size, chunkCount, wrappedFileKey, baseNonce }) {
  const ownerId = await currentUserId();
  const { error } = await getSupabase().from('files').insert({
    file_id: fileId,
    folder_id: folderId,
    owner_id: ownerId,
    name_enc: nameEnc,
    size,
    chunk_count: chunkCount,
    wrapped_file_key: wrappedFileKey,
    base_nonce: baseNonce,
  });
  if (error) throw fail(error);
  return { fileId };
}

/** Stores one encrypted chunk (bytes) and its row. `iv` is the chunk's 12-byte GCM nonce, base64. */
export async function uploadChunk({ fileId, index, bytes, iv, checksum }) {
  const supabase = getSupabase();
  const path = chunkPath(fileId, index);
  const { error: uploadError } = await supabase.storage
    .from(BUCKET)
    .upload(path, bytes, { contentType: 'application/octet-stream', upsert: false });
  if (uploadError) throw fail(uploadError);

  const { error } = await supabase
    .from('file_chunks')
    .insert({ file_id: fileId, chunk_index: index, iv, storage_ref: path, size: bytes.byteLength, checksum });
  if (error) throw fail(error);
}

/** Marks the upload finished. Only complete files are listed and downloadable. */
export async function completeFile(fileId) {
  const { error } = await getSupabase().from('files').update({ status: 'complete' }).eq('file_id', fileId);
  if (error) throw fail(error);
}

/** Complete files in one folder that the user owns. */
export async function listFiles(folderId) {
  const me = await currentUserId();
  const { data, error } = await getSupabase()
    .from('files')
    .select(FILE_COLUMNS)
    .eq('folder_id', folderId)
    .eq('owner_id', me)
    .eq('status', 'complete')
    .order('created_at', { ascending: true });
  if (error) throw fail(error);
  return (data ?? []).map(toFile);
}

/** One complete file row, or null. */
export async function getFile(fileId) {
  const { data, error } = await getSupabase()
    .from('files')
    .select(FILE_COLUMNS)
    .eq('file_id', fileId)
    .eq('status', 'complete')
    .maybeSingle();
  if (error) throw fail(error);
  return data ? toFile(data) : null;
}

/** The encrypted bytes of one chunk, as a Uint8Array. */
export async function downloadChunk({ fileId, index }) {
  const { data, error } = await getSupabase().storage.from(BUCKET).download(chunkPath(fileId, index));
  if (error || !data) throw fail(error ?? new Error('chunk missing'));
  return new Uint8Array(await data.arrayBuffer());
}

/** Deletes the stored chunks, the chunk rows and the file row. Safe to call on a half-finished upload. */
export async function deleteFile(fileId) {
  const supabase = getSupabase();
  const { data: chunks, error: listError } = await supabase.from('file_chunks').select('storage_ref').eq('file_id', fileId);
  if (listError) throw fail(listError);
  if (chunks?.length) {
    const { error } = await supabase.storage.from(BUCKET).remove(chunks.map((c) => c.storage_ref));
    if (error) throw fail(error);
  }
  const { error: chunkRowsError } = await supabase.from('file_chunks').delete().eq('file_id', fileId);
  if (chunkRowsError) throw fail(chunkRowsError);
  const { error } = await supabase.from('files').delete().eq('file_id', fileId);
  if (error) throw fail(error);
}
