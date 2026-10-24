import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as mock from '../src/services/mock/mockAuthApi.js';
import * as authFlow from '../src/services/authFlow.js';
import { createSubfolder, getVaultFolderId } from '../src/services/folderFlow.js';
import { cleanFileName, deleteFile, downloadFile, listFiles, uploadFile } from '../src/services/fileFlow.js';

vi.setConfig({ testTimeout: 30000 }); // real PBKDF2 (600k iterations) on every register/login

const EMAIL = 'files@test.co';
const PASSWORD = 'a-long-test-password';
const small = { chunkSize: 16 }; // tiny chunks so a short file spans several

const make = (text, name = 'notes.txt') => new File([text], name);
// jsdom's Blob has no arrayBuffer(); real browsers do.
const text = (blob) =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new TextDecoder().decode(new Uint8Array(reader.result)));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(blob);
  });

let vaultId;
beforeEach(async () => {
  mock.__resetMockAuth();
  mock.__setMockLatency(0);
  authFlow.configure({ backend: mock });
  await authFlow.logout();
  await authFlow.register(EMAIL, 'Tester', PASSWORD);
  vaultId = await getVaultFolderId();
});

describe('cleanFileName', () => {
  it('trims and rejects bad names', () => {
    expect(cleanFileName(' a.pdf ')).toBe('a.pdf');
    expect(() => cleanFileName('')).toThrow(/no name/);
    expect(() => cleanFileName('a/b.txt')).toThrow(/cannot contain/);
    expect(() => cleanFileName('x'.repeat(256))).toThrow(/at most 255/);
  });
});

describe('upload and download', () => {
  it('round-trips a file that spans several chunks', async () => {
    const body = 'The quick brown fox jumps over the lazy dog. '.repeat(5); // 225 bytes -> 15 chunks of 16
    const progress = vi.fn();
    const saved = await uploadFile(make(body), vaultId, { ...small, onProgress: progress });
    expect(progress).toHaveBeenLastCalledWith(15, 15);

    const [listed] = await listFiles(vaultId);
    expect(listed).toMatchObject({ id: saved.id, name: 'notes.txt', size: body.length });
    const { name, blob } = await downloadFile(saved.id, vaultId);
    expect(name).toBe('notes.txt');
    expect(await text(blob)).toBe(body);
  });

  it('handles an empty file and an exact multiple of the chunk size', async () => {
    const empty = await uploadFile(make('', 'empty.txt'), vaultId, small);
    expect(await text((await downloadFile(empty.id, vaultId)).blob)).toBe('');
    const exact = await uploadFile(make('x'.repeat(32), 'exact.txt'), vaultId, small);
    expect(await text((await downloadFile(exact.id, vaultId)).blob)).toBe('x'.repeat(32));
  });

  it('stores only ciphertext: no file name or content reaches the backend', async () => {
    const saved = await uploadFile(make('top secret payroll numbers', 'payroll.xlsx'), vaultId, small);
    const [row] = await mock.listFiles(vaultId);
    expect(JSON.stringify(row)).not.toContain('payroll');
    expect(Buffer.from(row.nameEnc, 'base64').toString('latin1')).not.toContain('payroll');
    for (const [key, bytes] of mock.__chunkStore) {
      if (key.startsWith(saved.id)) expect(Buffer.from(bytes).toString('latin1')).not.toContain('secret');
    }
  });

  it('files in a subfolder are readable after signing out and back in', async () => {
    const folder = await createSubfolder('Docs', vaultId);
    const saved = await uploadFile(make('hello again'), folder.id, small);
    await authFlow.logout();
    await authFlow.login(EMAIL, PASSWORD);
    expect((await listFiles(folder.id)).map((f) => f.name)).toEqual(['notes.txt']);
    expect(await text((await downloadFile(saved.id, folder.id)).blob)).toBe('hello again');
  });

  it('deletes a file and its chunks', async () => {
    const saved = await uploadFile(make('bye'), vaultId, small);
    await deleteFile(saved.id);
    expect(await listFiles(vaultId)).toEqual([]);
    expect([...mock.__chunkStore.keys()].some((k) => k.startsWith(saved.id))).toBe(false);
  });

  it('refuses oversize files and unknown folders', async () => {
    const big = { name: 'big.bin', size: 50 * 1024 * 1024 + 1, slice: () => new Blob([]) };
    await expect(uploadFile(big, vaultId)).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(uploadFile(make('x'), crypto.randomUUID())).rejects.toMatchObject({ code: 'invalid_request' });
  });

  it('cleans up if an upload fails half way', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    let calls = 0;
    const flaky = {
      ...mock,
      uploadChunk: async (args) => {
        if (++calls === 3) throw new Error('network dropped');
        return mock.uploadChunk(args);
      },
    };
    authFlow.configure({ backend: flaky });
    await expect(uploadFile(make('y'.repeat(100)), vaultId, small)).rejects.toThrow('network dropped');
    expect(await listFiles(vaultId)).toEqual([]);
    expect(mock.__chunkStore.size).toBe(0);
  });
});

describe('a dishonest server is detected', () => {
  async function stored(body) {
    const saved = await uploadFile(make(body), vaultId, small);
    return saved.id;
  }
  const tampered = /corrupted or has been tampered/;

  it('flipped bits in a chunk', async () => {
    const id = await stored('a'.repeat(64));
    const bytes = mock.__chunkStore.get(`${id}/1`);
    bytes[0] ^= 1;
    await expect(downloadFile(id, vaultId)).rejects.toThrow(tampered);
  });

  it('chunks swapped (reordered)', async () => {
    const id = await stored('a'.repeat(64));
    const a = mock.__chunkStore.get(`${id}/0`);
    mock.__chunkStore.set(`${id}/0`, mock.__chunkStore.get(`${id}/1`));
    mock.__chunkStore.set(`${id}/1`, a);
    await expect(downloadFile(id, vaultId)).rejects.toThrow(tampered);
  });

  it('a chunk replaced by one from another file', async () => {
    const id = await stored('a'.repeat(64));
    const other = await stored('b'.repeat(64));
    mock.__chunkStore.set(`${id}/1`, mock.__chunkStore.get(`${other}/1`));
    await expect(downloadFile(id, vaultId)).rejects.toThrow(tampered);
  });

  it('the last chunk dropped (truncation)', async () => {
    const id = await stored('a'.repeat(64)); // 4 chunks
    const real = mock.getFile;
    authFlow.configure({ backend: { ...mock, getFile: async (fid) => ({ ...(await real(fid)), chunkCount: 3 }) } });
    await expect(downloadFile(id, vaultId)).rejects.toThrow(tampered);
  });

  it('a missing chunk', async () => {
    const id = await stored('a'.repeat(64));
    mock.__chunkStore.delete(`${id}/2`);
    await expect(downloadFile(id, vaultId)).rejects.toMatchObject({ code: 'unknown_error' });
  });
});
