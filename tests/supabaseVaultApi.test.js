import { beforeEach, describe, expect, it, vi } from 'vitest';

// Fake Supabase client: we test what OUR code sends and how it maps rows, not Supabase itself.
const fake = { auth: {}, from: vi.fn() };
vi.mock('../src/services/supabaseClient.js', () => ({ getSupabase: () => fake }));

const { createFolder, createGrant, getVault, listFolders } = await import('../src/services/supabaseVaultApi.js');

const ME = '11111111-1111-1111-1111-111111111111';

/** A chainable query stub: every builder method returns itself; awaiting it yields `result`. */
function query(result) {
  const q = {};
  for (const m of ['select', 'eq', 'is', 'not', 'in', 'order', 'insert']) q[m] = vi.fn(() => q);
  q.single = vi.fn(() => Promise.resolve(result));
  q.then = (resolve, reject) => Promise.resolve(result).then(resolve, reject);
  return q;
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(console, 'error').mockImplementation(() => {});
  fake.auth.getSession = vi.fn().mockResolvedValue({ data: { session: { user: { id: ME } } }, error: null });
  fake.from = vi.fn();
});

describe('createFolder', () => {
  it('inserts only ciphertext and the owner id, and maps the id back to camelCase', async () => {
    const q = query({ data: { folder_id: 'F1' }, error: null });
    fake.from.mockReturnValue(q);
    const res = await createFolder({ nameEnc: 'ENC', parentId: null, wrappedKey: null });
    expect(fake.from).toHaveBeenCalledWith('folders');
    expect(q.insert).toHaveBeenCalledWith({ owner_id: ME, parent_id: null, name_enc: 'ENC', wrapped_key: null });
    expect(res).toEqual({ folderId: 'F1' });
  });

  it('refuses when there is no signed-in session', async () => {
    fake.auth.getSession.mockResolvedValue({ data: { session: null }, error: null });
    await expect(createFolder({ nameEnc: 'ENC' })).rejects.toMatchObject({ code: 'invalid_credentials' });
  });

  it('keeps raw database errors out of the UI message', async () => {
    fake.from.mockReturnValue(query({ data: null, error: { message: 'new row violates row-level security policy', status: 403 } }));
    await expect(createFolder({ nameEnc: 'ENC' })).rejects.toMatchObject({
      code: 'unknown_error',
      message: expect.not.stringContaining('row-level'),
    });
  });
});

describe('createGrant', () => {
  it('writes a key_envelopes row with the ephemeral public key and lower-case resource type', async () => {
    const q = query({ data: { envelope_id: 'G1' }, error: null });
    fake.from.mockReturnValue(q);
    const res = await createGrant({
      resourceType: 'FOLDER', resourceId: 'F1', granteeId: ME, role: 'OWNER', wrappedKey: 'WK', ephemeralPublicKey: 'EPK',
    });
    expect(fake.from).toHaveBeenCalledWith('key_envelopes');
    expect(q.insert).toHaveBeenCalledWith({
      resource_type: 'folder', resource_id: 'F1', recipient_id: ME, role: 'OWNER', wrapped_key: 'WK', ephemeral_public_key: 'EPK',
    });
    expect(res).toEqual({ grantId: 'G1' });
  });
});

describe('getVault', () => {
  it('returns null when there is no encrypted root folder', async () => {
    fake.from.mockReturnValue(query({ data: [], error: null }));
    expect(await getVault()).toBeNull();
  });

  it('returns the oldest root folder that has a key for this user', async () => {
    const folders = query({ data: [{ folder_id: 'ORPHAN', name_enc: 'A' }, { folder_id: 'F1', name_enc: 'B' }], error: null });
    const envelopes = query({ data: [{ resource_id: 'F1', wrapped_key: 'WK', ephemeral_public_key: 'EPK' }], error: null });
    fake.from.mockImplementation((table) => (table === 'folders' ? folders : envelopes));

    expect(await getVault()).toEqual({ id: 'F1', nameEnc: 'B', myGrant: { wrappedKey: 'WK', ephemeralPublicKey: 'EPK' } });
    expect(folders.not).toHaveBeenCalledWith('name_enc', 'is', null); // ignores plaintext test folders
    expect(envelopes.eq).toHaveBeenCalledWith('recipient_id', ME);
  });

  it('returns null when a root folder exists but its key grant was never saved', async () => {
    const folders = query({ data: [{ folder_id: 'ORPHAN', name_enc: 'A' }], error: null });
    const envelopes = query({ data: [], error: null });
    fake.from.mockImplementation((table) => (table === 'folders' ? folders : envelopes));
    expect(await getVault()).toBeNull();
  });
});

describe('listFolders', () => {
  it('lists only folders the user owns that have an encrypted name, mapped to camelCase', async () => {
    const q = query({
      data: [{ folder_id: 'F1', parent_id: null, name_enc: 'A', wrapped_key: null }, { folder_id: 'F2', parent_id: 'F1', name_enc: 'B', wrapped_key: 'WK' }],
      error: null,
    });
    fake.from.mockReturnValue(q);
    expect(await listFolders()).toEqual([
      { id: 'F1', parentId: null, nameEnc: 'A', wrappedKey: null },
      { id: 'F2', parentId: 'F1', nameEnc: 'B', wrappedKey: 'WK' },
    ]);
    expect(q.eq).toHaveBeenCalledWith('owner_id', ME); // shared folders are excluded
    expect(q.not).toHaveBeenCalledWith('name_enc', 'is', null);
  });
});
