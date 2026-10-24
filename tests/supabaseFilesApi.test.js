import { beforeEach, describe, expect, it, vi } from 'vitest';

const fake = { auth: {}, from: vi.fn(), storage: { from: vi.fn() } };
vi.mock('../src/services/supabaseClient.js', () => ({ getSupabase: () => fake }));

const api = await import('../src/services/supabaseFilesApi.js');
const ME = '11111111-1111-1111-1111-111111111111';

/** Chainable query stub; awaiting it yields `result`. */
function query(result) {
  const q = {};
  for (const m of ['select', 'eq', 'order', 'insert', 'update', 'delete']) q[m] = vi.fn(() => q);
  q.maybeSingle = vi.fn(() => Promise.resolve(result));
  q.then = (resolve, reject) => Promise.resolve(result).then(resolve, reject);
  return q;
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(console, 'error').mockImplementation(() => {});
  fake.auth.getSession = vi.fn().mockResolvedValue({ data: { session: { user: { id: ME } } }, error: null });
  fake.from = vi.fn();
  fake.storage.from = vi.fn();
});

describe('createFile', () => {
  it('saves the encrypted name and wrapped key under the browser-chosen id, owned by the user', async () => {
    const q = query({ error: null });
    fake.from.mockReturnValue(q);
    await api.createFile({ fileId: 'F1', folderId: 'D1', nameEnc: 'N', size: 5, chunkCount: 1, wrappedFileKey: 'WK', baseNonce: 'BN' });
    expect(fake.from).toHaveBeenCalledWith('files');
    expect(q.insert).toHaveBeenCalledWith({
      file_id: 'F1', folder_id: 'D1', owner_id: ME, name_enc: 'N', size: 5, chunk_count: 1, wrapped_file_key: 'WK', base_nonce: 'BN',
    });
  });
  it('needs a signed-in session', async () => {
    fake.auth.getSession.mockResolvedValue({ data: { session: null }, error: null });
    await expect(api.createFile({ fileId: 'F1' })).rejects.toMatchObject({ code: 'invalid_credentials' });
  });
});

describe('uploadChunk', () => {
  it('uploads to files/<id>/<index> in the private bucket without overwriting, then records the chunk', async () => {
    const upload = vi.fn().mockResolvedValue({ error: null });
    fake.storage.from.mockReturnValue({ upload });
    const q = query({ error: null });
    fake.from.mockReturnValue(q);
    const bytes = new Uint8Array(32);
    await api.uploadChunk({ fileId: 'F1', index: 2, bytes, iv: 'IV', checksum: 'abc' });
    expect(fake.storage.from).toHaveBeenCalledWith('chunks');
    expect(upload).toHaveBeenCalledWith('files/F1/2', bytes, { contentType: 'application/octet-stream', upsert: false });
    expect(q.insert).toHaveBeenCalledWith({ file_id: 'F1', chunk_index: 2, iv: 'IV', storage_ref: 'files/F1/2', size: 32, checksum: 'abc' });
  });
  it('keeps raw storage errors out of the UI message', async () => {
    fake.storage.from.mockReturnValue({ upload: vi.fn().mockResolvedValue({ error: { message: 'new row violates row-level security policy', statusCode: '403' } }) });
    await expect(api.uploadChunk({ fileId: 'F1', index: 0, bytes: new Uint8Array(16), iv: 'IV' })).rejects.toMatchObject({
      code: 'unknown_error', message: expect.not.stringContaining('row-level'),
    });
  });
});

describe('listFiles / getFile', () => {
  const row = { file_id: 'F1', folder_id: 'D1', name_enc: 'N', size: 5, chunk_count: 1, wrapped_file_key: 'WK', base_nonce: 'BN', created_at: 't' };
  it('lists complete files in the folder (RLS limits it to own or shared), mapped to camelCase', async () => {
    const q = query({ data: [row], error: null });
    fake.from.mockReturnValue(q);
    expect(await api.listFiles('D1')).toEqual([{ id: 'F1', folderId: 'D1', nameEnc: 'N', size: 5, chunkCount: 1, wrappedFileKey: 'WK', baseNonce: 'BN', createdAt: 't' }]);
    expect(q.eq).toHaveBeenCalledWith('folder_id', 'D1');
    expect(q.eq).toHaveBeenCalledWith('status', 'complete');
  });
  it('returns null for a missing file', async () => {
    fake.from.mockReturnValue(query({ data: null, error: null }));
    expect(await api.getFile('nope')).toBeNull();
  });
});

describe('downloadChunk / deleteFile', () => {
  it('returns the stored bytes', async () => {
    const blob = { arrayBuffer: async () => new Uint8Array([1, 2, 3]).buffer };
    const download = vi.fn().mockResolvedValue({ data: blob, error: null });
    fake.storage.from.mockReturnValue({ download });
    expect(Array.from(await api.downloadChunk({ fileId: 'F1', index: 0 }))).toEqual([1, 2, 3]);
    expect(download).toHaveBeenCalledWith('files/F1/0');
  });
  it('removes stored chunks, chunk rows, then the file row', async () => {
    const remove = vi.fn().mockResolvedValue({ error: null });
    fake.storage.from.mockReturnValue({ remove });
    const calls = [];
    fake.from.mockImplementation((table) => {
      const q = query({ data: table === 'file_chunks' ? [{ storage_ref: 'files/F1/0' }] : null, error: null });
      const del = q.delete;
      q.delete = vi.fn((...a) => { calls.push(`delete ${table}`); return del(...a); });
      return q;
    });
    await api.deleteFile('F1');
    expect(remove).toHaveBeenCalledWith(['files/F1/0']);
    expect(calls).toEqual(['delete file_chunks', 'delete files']);
  });
});
