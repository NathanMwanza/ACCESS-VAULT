import { beforeEach, describe, expect, it, vi } from 'vitest';

const fake = { auth: {}, rpc: vi.fn(), from: vi.fn() };
vi.mock('../src/services/supabaseClient.js', () => ({ getSupabase: () => fake }));

const api = await import('../src/services/supabaseSharingApi.js');
const ME = '11111111-1111-1111-1111-111111111111';

function query(result) {
  const q = {};
  for (const m of ['select', 'eq', 'neq', 'not', 'in', 'order']) q[m] = vi.fn(() => q);
  q.then = (resolve, reject) => Promise.resolve(result).then(resolve, reject);
  return q;
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(console, 'error').mockImplementation(() => {});
  fake.auth.getSession = vi.fn().mockResolvedValue({ data: { session: { user: { id: ME } } }, error: null });
  fake.rpc = vi.fn();
  fake.from = vi.fn();
});

describe('findShareTarget', () => {
  it('maps the row, and returns null when nobody matches', async () => {
    fake.rpc.mockResolvedValueOnce({ data: [{ user_id: 'U2', public_key: 'PK', name: 'Bob' }], error: null });
    expect(await api.findShareTarget('bob@x.co')).toEqual({ userId: 'U2', publicKey: 'PK', name: 'Bob' });
    expect(fake.rpc).toHaveBeenCalledWith('find_user_for_share', { p_email: 'bob@x.co' });
    fake.rpc.mockResolvedValueOnce({ data: [], error: null });
    expect(await api.findShareTarget('nobody@x.co')).toBeNull();
  });
});

describe('shareResource / revokeShare', () => {
  it('sends only the wrapped key, with the type lower-cased and the expiry', async () => {
    fake.rpc.mockResolvedValue({ data: 'S1', error: null });
    const res = await api.shareResource({ resourceType: 'FOLDER', resourceId: 'F1', recipientId: 'U2', wrappedKey: 'WK', ephemeralPublicKey: 'EPK', expiresAt: '2026-11-01T00:00:00.000Z' });
    expect(res).toEqual({ shareId: 'S1' });
    expect(fake.rpc).toHaveBeenCalledWith('share_resource', {
      p_resource_type: 'folder', p_resource_id: 'F1', p_recipient_id: 'U2', p_level: 'VIEWER',
      p_wrapped_key: 'WK', p_ephemeral_public_key: 'EPK', p_expires_at: '2026-11-01T00:00:00.000Z',
    });
  });
  it.each([
    ['already_shared', /already shared/],
    ['cannot_share_vault_root', /whole vault/],
    ['not_your_folder', /only share folders you own/],
    ['expiry_in_past', /future/],
  ])('turns %s into a friendly message', async (token, message) => {
    fake.rpc.mockResolvedValue({ data: null, error: { message: `ERROR: ${token}` } });
    await expect(api.shareResource({ resourceType: 'folder', resourceId: 'F1', recipientId: 'U2', wrappedKey: 'a', ephemeralPublicKey: 'b' }))
      .rejects.toMatchObject({ code: 'invalid_request', message: expect.stringMatching(message) });
  });
  it('keeps unknown database errors out of the UI message', async () => {
    fake.rpc.mockResolvedValue({ data: null, error: { message: 'relation public.shares does not exist', status: 500 } });
    await expect(api.revokeShare('S1')).rejects.toMatchObject({ code: 'unknown_error', message: expect.not.stringContaining('relation') });
  });
  it('revokes through the function', async () => {
    fake.rpc.mockResolvedValue({ data: null, error: null });
    await api.revokeShare('S1');
    expect(fake.rpc).toHaveBeenCalledWith('revoke_share', { p_share_id: 'S1' });
  });
});

describe('listShares', () => {
  it('maps recipients, including expiry', async () => {
    fake.rpc.mockResolvedValue({ data: [{ share_id: 'S1', shared_with: 'U2', recipient_email: 'b@x.co', recipient_name: 'Bob', level: 'VIEWER', created_at: 't', expires_at: null }], error: null });
    expect(await api.listShares('F1')).toEqual([{ shareId: 'S1', recipientId: 'U2', email: 'b@x.co', name: 'Bob', level: 'VIEWER', createdAt: 't', expiresAt: null }]);
    expect(fake.rpc).toHaveBeenCalledWith('list_shares_for_resource', { p_resource_id: 'F1', p_resource_type: 'folder' });
  });
});

describe('listSharedWithMe', () => {
  it('joins each share with its encrypted name and MY key grant, skipping shares without both', async () => {
    fake.rpc.mockResolvedValue({
      data: [
        { share_id: 'S1', resource_type: 'folder', resource_id: 'F1', level: 'VIEWER', created_at: 't', owner_name: 'Alice', owner_email: 'a@x.co', expires_at: null },
        { share_id: 'S2', resource_type: 'folder', resource_id: 'F2', level: 'VIEWER', created_at: 't', owner_name: 'Alice', owner_email: 'a@x.co', expires_at: null },
      ],
      error: null,
    });
    const folders = query({ data: [{ folder_id: 'F1', name_enc: 'N1' }, { folder_id: 'F2', name_enc: 'N2' }], error: null });
    const envelopes = query({ data: [{ resource_id: 'F1', wrapped_key: 'WK', ephemeral_public_key: 'EPK' }], error: null });
    fake.from.mockImplementation((t) => (t === 'folders' ? folders : envelopes));

    expect(await api.listSharedWithMe()).toEqual([
      { shareId: 'S1', folderId: 'F1', level: 'VIEWER', createdAt: 't', expiresAt: null, ownerName: 'Alice', ownerEmail: 'a@x.co', nameEnc: 'N1', wrappedKey: 'WK', ephemeralPublicKey: 'EPK' },
    ]);
    expect(envelopes.eq).toHaveBeenCalledWith('recipient_id', ME);
  });
  it('returns nothing without querying tables when nothing is shared', async () => {
    fake.rpc.mockResolvedValue({ data: [], error: null });
    expect(await api.listSharedWithMe()).toEqual([]);
    expect(fake.from).not.toHaveBeenCalled();
  });
});

describe('listSharedSubtree', () => {
  it('returns the root (parentId null) and its descendants only', async () => {
    const q = query({
      data: [
        { folder_id: 'R', parent_id: 'ownerParent', name_enc: 'a', wrapped_key: null },
        { folder_id: 'C', parent_id: 'R', name_enc: 'b', wrapped_key: 'wk1' },
        { folder_id: 'G', parent_id: 'C', name_enc: 'c', wrapped_key: 'wk2' },
        { folder_id: 'OTHER', parent_id: 'X', name_enc: 'd', wrapped_key: 'wk3' },
      ],
      error: null,
    });
    fake.from.mockReturnValue(q);
    const rows = await api.listSharedSubtree('R');
    expect(rows.map((r) => r.id)).toEqual(['R', 'C', 'G']);
    expect(rows[0].parentId).toBeNull();
    expect(q.neq).toHaveBeenCalledWith('owner_id', ME);
  });
  it('is empty when the folder is not shared with the user', async () => {
    fake.from.mockReturnValue(query({ data: [], error: null }));
    expect(await api.listSharedSubtree('R')).toEqual([]);
  });
});
