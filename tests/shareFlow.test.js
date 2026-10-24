import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as mock from '../src/services/mock/mockAuthApi.js';
import * as authFlow from '../src/services/authFlow.js';
import { createSubfolder, getVaultFolderId } from '../src/services/folderFlow.js';
import { downloadFile, listFiles, uploadFile } from '../src/services/fileFlow.js';
import {
  fingerprint, listShares, listSharedWithMe, lookupRecipient, openSharedFolder, revokeShare, shareFolder,
} from '../src/services/shareFlow.js';

vi.setConfig({ testTimeout: 60000 }); // each register/login runs real PBKDF2 (600k iterations)

const ALICE = { email: 'alice@test.co', name: 'Alice', password: 'alice-long-password' };
const BOB = { email: 'bob@test.co', name: 'Bob', password: 'bob-long-password-1' };

const make = (text, name) => new File([text], name);
const text = (blob) =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new TextDecoder().decode(new Uint8Array(reader.result)));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(blob);
  });

const signUp = (u) => authFlow.register(u.email, u.name, u.password);
const signIn = async (u) => {
  await authFlow.logout();
  await authFlow.login(u.email, u.password);
};

let projects; // Alice's folder "Projects", with "Reports" inside it and a file in each
let reports;
beforeEach(async () => {
  mock.__resetMockAuth();
  mock.__setMockLatency(0);
  authFlow.configure({ backend: mock });
  await authFlow.logout();

  await signUp(BOB);
  await authFlow.logout();
  await signUp(ALICE);
  const vault = await getVaultFolderId();
  projects = await createSubfolder('Projects', vault);
  reports = await createSubfolder('Reports', projects.id);
  await uploadFile(make('plan v1', 'plan.txt'), projects.id);
  await uploadFile(make('q3 numbers', 'q3.txt'), reports.id);
});

describe('fingerprint', () => {
  it('is stable, grouped and different per key', async () => {
    const a = await fingerprint(btoa('a'.repeat(65)));
    expect(a).toMatch(/^([0-9A-F]{4} ){7}[0-9A-F]{4}$/);
    expect(await fingerprint(btoa('a'.repeat(65)))).toBe(a);
    expect(await fingerprint(btoa('b'.repeat(65)))).not.toBe(a);
  });
});

describe('lookupRecipient', () => {
  it('finds an account and shows its key fingerprint', async () => {
    const bob = await lookupRecipient(' BOB@test.co ');
    expect(bob).toMatchObject({ name: 'Bob', fingerprint: expect.stringMatching(/^[0-9A-F ]{39}$/) });
  });
  it('rejects bad emails, unknown accounts and yourself', async () => {
    await expect(lookupRecipient('nope')).rejects.toThrow(/valid email/);
    await expect(lookupRecipient('ghost@test.co')).rejects.toThrow(/No Access Vault account/);
    await expect(lookupRecipient(ALICE.email)).rejects.toThrow(/No Access Vault account/);
  });
});

describe('sharing a folder', () => {
  it('lets the recipient browse the whole shared tree and download files, and nothing else', async () => {
    const bob = await lookupRecipient(BOB.email);
    await shareFolder(projects.id, bob);
    expect(await listShares(projects.id)).toMatchObject([{ email: BOB.email, name: 'Bob', level: 'VIEWER' }]);

    await signIn(BOB);
    const shared = await listSharedWithMe();
    expect(shared).toMatchObject([{ folderId: projects.id, name: 'Projects', ownerName: 'Alice', ownerEmail: ALICE.email }]);

    const tree = await openSharedFolder(projects.id);
    expect(tree.map((f) => f.name).sort()).toEqual(['Projects', 'Reports']);
    expect(tree.find((f) => f.name === 'Projects').parentId).toBeNull();

    const top = await listFiles(projects.id);
    expect(top.map((f) => f.name)).toEqual(['plan.txt']);
    expect(await text((await downloadFile(top[0].id, projects.id)).blob)).toBe('plan v1');

    const deep = await listFiles(reports.id); // a file two levels down, reached through the parent's key
    expect(await text((await downloadFile(deep[0].id, reports.id)).blob)).toBe('q3 numbers');

    // Read-only, and the owner's vault root stays private.
    await expect(createSubfolder('Mine', projects.id)).rejects.toThrow();
    await expect(uploadFile(make('x', 'x.txt'), projects.id)).rejects.toThrow();
    expect(await mock.listFolders()).toEqual([expect.objectContaining({ parentId: null })]); // only Bob's own vault
  });

  it('sends only a wrapped key: it cannot be opened by anyone but the recipient', async () => {
    await shareFolder(projects.id, await lookupRecipient(BOB.email));
    const [row] = await (async () => { await signIn(BOB); return mock.listSharedWithMe(); })();
    expect(row.wrappedKey).toEqual(expect.any(String));
    const { unwrapFromUser } = await import('../src/crypto/keyManager.js');
    await signIn(ALICE); // the owner's own private key must NOT open the recipient's grant
    await expect(unwrapFromUser(row.wrappedKey, row.ephemeralPublicKey, authFlow.getSession().privateKey)).rejects.toThrow();
  });

  it('refuses the vault root, duplicates and shares by non-owners', async () => {
    const bob = await lookupRecipient(BOB.email);
    await expect(shareFolder(await getVaultFolderId(), bob)).rejects.toThrow(/whole vault/);
    await shareFolder(projects.id, bob);
    await expect(shareFolder(projects.id, bob)).rejects.toThrow(/already shared/);
    await signIn(BOB);
    await listSharedWithMe();
    const alice = { userId: crypto.randomUUID(), publicKey: bob.publicKey }; // Bob tries to re-share Alice's folder
    await expect(shareFolder(projects.id, alice)).rejects.toThrow();
  });
});

describe('revoking', () => {
  it('cuts access immediately and deletes the recipient key grant', async () => {
    const bob = await lookupRecipient(BOB.email);
    const { shareId } = await shareFolder(projects.id, bob);
    await revokeShare(shareId);
    expect(await listShares(projects.id)).toEqual([]);

    await signIn(BOB);
    expect(await listSharedWithMe()).toEqual([]);
    await expect(openSharedFolder(projects.id)).rejects.toThrow(/could not be found|no longer shared/);
    expect(await mock.listSharedSubtree(projects.id)).toEqual([]);
    expect(await mock.listFiles(projects.id)).toEqual([]);
    await expect(mock.downloadChunk({ fileId: crypto.randomUUID(), index: 0 })).rejects.toThrow();
  });

  it('a revoked recipient can be shared with again, and a stranger cannot revoke', async () => {
    const bob = await lookupRecipient(BOB.email);
    const first = await shareFolder(projects.id, bob);
    await revokeShare(first.shareId);
    const second = await shareFolder(projects.id, bob);
    expect(second.shareId).not.toBe(first.shareId);

    await signIn(BOB);
    await expect(revokeShare(second.shareId)).rejects.toThrow(/no longer exists/);
    expect(await listSharedWithMe()).toHaveLength(1); // still shared
  });
});

describe('expiry and unfinished uploads', () => {
  it('an expired share stops working by itself, and a past expiry is refused', async () => {
    const bob = await lookupRecipient(BOB.email);
    await expect(shareFolder(projects.id, bob, { expiresAt: new Date(Date.now() - 1000) })).rejects.toThrow(/future/);

    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      await shareFolder(projects.id, bob, { expiresAt: new Date(Date.now() + 60_000) });
      expect(await listShares(projects.id)).toMatchObject([{ email: BOB.email, expiresAt: expect.any(String) }]);
      await signIn(BOB);
      expect(await listSharedWithMe()).toHaveLength(1);
      expect((await listFiles(projects.id)).map((f) => f.name)).toEqual(['plan.txt']);

      vi.setSystemTime(Date.now() + 120_000);
      expect(await listSharedWithMe()).toEqual([]);
      expect(await listFiles(projects.id)).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('a recipient cannot read a file that is still uploading', async () => {
    const bob = await lookupRecipient(BOB.email);
    await shareFolder(projects.id, bob);
    // Alice starts an upload but never completes it.
    const fileId = crypto.randomUUID();
    await mock.createFile({ fileId, folderId: projects.id, nameEnc: 'x', size: 1, chunkCount: 1, wrappedFileKey: 'k', baseNonce: 'n' });
    await mock.uploadChunk({ fileId, index: 0, bytes: new Uint8Array(32), iv: 'iv' });
    await signIn(BOB);
    await expect(mock.downloadChunk({ fileId, index: 0 })).rejects.toThrow();
    expect(await mock.getFile(fileId)).toBeNull();
  });
});
