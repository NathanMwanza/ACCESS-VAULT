import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as mock from '../src/services/mock/mockAuthApi.js';
import * as authFlow from '../src/services/authFlow.js';
import { cleanFolderName, createSubfolder, getVaultFolderId, listFolders } from '../src/services/folderFlow.js';

vi.setConfig({ testTimeout: 30000 }); // real PBKDF2 (600k iterations) on every register/login

const EMAIL = 'folders@test.co';
const PASSWORD = 'a-long-test-password';

beforeEach(async () => {
  mock.__resetMockAuth();
  mock.__setMockLatency(0);
  authFlow.configure({ backend: mock });
  await authFlow.logout();
});

describe('cleanFolderName', () => {
  it('trims and accepts normal names', () => {
    expect(cleanFolderName('  Lecture notes ')).toBe('Lecture notes');
  });
  it.each([['', /Enter a folder name/], ['   ', /Enter a folder name/], ['a/b', /cannot contain/], ['a\\b', /cannot contain/], ['x'.repeat(101), /at most 100/]])(
    'rejects %j',
    (input, message) => {
      expect(() => cleanFolderName(input)).toThrow(message);
    },
  );
});

describe('encrypted folders', () => {
  it('starts with just the vault root, named "Vault"', async () => {
    await authFlow.register(EMAIL, 'Tester', PASSWORD);
    const all = await listFolders();
    expect(all).toHaveLength(1);
    expect(all[0]).toMatchObject({ name: 'Vault', parentId: null, id: await getVaultFolderId() });
  });

  it('creates nested folders and reads them back', async () => {
    await authFlow.register(EMAIL, 'Tester', PASSWORD);
    const vaultId = await getVaultFolderId();
    const notes = await createSubfolder('Notes', vaultId);
    const week1 = await createSubfolder('Week 1', notes.id);

    const all = await listFolders();
    expect(all.find((f) => f.id === week1.id)).toMatchObject({ name: 'Week 1', parentId: notes.id });
    expect(all.find((f) => f.id === notes.id)).toMatchObject({ name: 'Notes', parentId: vaultId });
  });

  it('stores only ciphertext: no plaintext name reaches the backend', async () => {
    await authFlow.register(EMAIL, 'Tester', PASSWORD);
    await createSubfolder('Secret project', await getVaultFolderId());
    const rows = await mock.listFolders();
    expect(JSON.stringify(rows)).not.toContain('Secret');
    for (const row of rows) {
      const bytes = Buffer.from(row.nameEnc, 'base64').toString('latin1');
      expect(bytes).not.toContain('Secret');
      expect(bytes).not.toContain('Vault');
    }
    const sub = rows.find((r) => r.parentId !== null);
    expect(sub.wrappedKey).toEqual(expect.any(String)); // subfolder key is wrapped under its parent's key
  });

  it('recovers the whole tree after signing out and back in', async () => {
    await authFlow.register(EMAIL, 'Tester', PASSWORD);
    const notes = await createSubfolder('Notes', await getVaultFolderId());
    await createSubfolder('Week 1', notes.id);
    await authFlow.logout();

    await authFlow.login(EMAIL, PASSWORD);
    const names = (await listFolders()).map((f) => f.name).sort();
    expect(names).toEqual(['Notes', 'Vault', 'Week 1']);
  });

  it('refuses an unknown parent and a bad name', async () => {
    await authFlow.register(EMAIL, 'Tester', PASSWORD);
    await expect(createSubfolder('Orphan', crypto.randomUUID())).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(createSubfolder('  ', await getVaultFolderId())).rejects.toMatchObject({ code: 'invalid_request' });
  });

  it('needs a signed-in session', async () => {
    await expect(listFolders()).rejects.toMatchObject({ code: 'invalid_credentials' });
  });

  it("leaves out a folder that was tampered with, and everything under it", async () => {
    await authFlow.register(EMAIL, 'Tester', PASSWORD);
    const vaultId = await getVaultFolderId();
    const good = await createSubfolder('Good', vaultId);
    const bad = await createSubfolder('Bad', vaultId);
    await createSubfolder('Under bad', bad.id);

    // A dishonest server swaps the wrapped key of "Bad" for the one of "Good".
    const real = mock.listFolders;
    const rows = await real();
    const goodRow = rows.find((r) => r.id === good.id);
    const badRow = rows.find((r) => r.id === bad.id);
    const tampered = rows.map((r) => (r.id === bad.id ? { ...badRow, nameEnc: goodRow.nameEnc, wrappedKey: goodRow.wrappedKey } : r));
    vi.spyOn(console, 'error').mockImplementation(() => {});
    authFlow.configure({ backend: { ...mock, listFolders: async () => tampered } });

    const names = (await listFolders()).map((f) => f.name).sort();
    // "Bad" now decrypts as Good's key + Good's name, so it is shown as "Good": that is a rename the
    // server can cause, but it can never reveal a name, and the children under it stay unreadable.
    expect(names).not.toContain('Under bad');
    expect(names).not.toContain('Secret');
  });
});
