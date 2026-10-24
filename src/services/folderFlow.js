// Encrypted folders. Pages call THESE functions and never see a key.
//
//   pages -> folderFlow.js (keys, wrapping, names) -> backend (mock or Supabase, via authFlow's configure())
//
// Key hierarchy (Chapter 4):
//   vault folder key   random; stored only as a grant wrapped to the user's own public key (authFlow.js)
//   subfolder key      random; stored wrapped (AES-GCM) under its PARENT folder's key in folders.wrapped_key
//   folder name        encrypted with that folder's own key and stored in folders.name_enc
// So the server holds only ciphertext, and holding the vault key is enough to open the whole tree.
// Decrypted keys are cached on the in-memory auth session, which logout() throws away.

import { getBackend, getSession, loadVault } from './authFlow.js';
import { ApiError } from './apiClient.js';
import { ERROR_CODES } from './contract.js';
import { generateAesKey, encryptMetadata, decryptMetadata } from '../crypto/cryptoEngine.js';
import { wrapKey, unwrapKey } from '../crypto/keyManager.js';
import { packBlob, unpackBlob } from '../crypto/encoding.js';

export const FOLDER_NAME_MAX = 100;

const AES = { name: 'AES-GCM' };
const USAGES = ['encrypt', 'decrypt'];

/** Returns the signed-in session, with the vault key loaded and a folder-key cache ready. */
async function readySession() {
  const session = getSession();
  if (!session) throw new ApiError(ERROR_CODES.INVALID_CREDENTIALS, 'Please sign in again.', 401);
  if (!session.vaultFolderKey) {
    // Registration saved the account but not the vault (e.g. a network drop). Try to pick it up now.
    const found = await loadVault();
    if (!found) throw new ApiError(ERROR_CODES.UNKNOWN, 'Your vault is not ready yet. Sign out and sign in again.', 0);
  }
  if (!session.folderKeys) session.folderKeys = new Map();
  session.folderKeys.set(session.vaultFolderId, session.vaultFolderKey);
  return session;
}

/** Trim and check a folder name. Returns the clean name or throws a friendly ApiError. */
export function cleanFolderName(raw) {
  const name = String(raw ?? '').trim();
  if (!name) throw new ApiError(ERROR_CODES.INVALID_REQUEST, 'Enter a folder name.', 400);
  if (name.length > FOLDER_NAME_MAX) {
    throw new ApiError(ERROR_CODES.INVALID_REQUEST, `Folder names can be at most ${FOLDER_NAME_MAX} characters.`, 400);
  }
  if (/[\\/]/.test(name)) throw new ApiError(ERROR_CODES.INVALID_REQUEST, 'Folder names cannot contain / or \\.', 400);
  return name;
}

export async function getVaultFolderId() {
  return (await readySession()).vaultFolderId;
}

/**
 * Decrypts a folder tree. `rows` holds the root row plus its descendants ([{ id, parentId, nameEnc, wrappedKey }]).
 * The root's name is encrypted with the root's own key (`rootKey`); every other folder's key is unwrapped from
 * its parent's key. Keys are cached on the session. A folder that cannot be decrypted (wrong key or tampered
 * data) is left out, along with everything under it. Returns [{ id, parentId, name }] with the root's parentId null.
 */
export async function decryptTree(session, rows, rootId, rootKey) {
  if (!session.folderKeys) session.folderKeys = new Map();
  session.folderKeys.set(rootId, rootKey);

  const byParent = new Map();
  for (const row of rows) {
    if (!byParent.has(row.parentId)) byParent.set(row.parentId, []);
    byParent.get(row.parentId).push(row);
  }

  const out = [];
  const root = rows.find((r) => r.id === rootId);
  if (root) {
    const { iv, ciphertext } = unpackBlob(root.nameEnc);
    out.push({ id: root.id, parentId: null, name: await decryptMetadata(rootKey, iv, ciphertext) });
  }

  const queue = [rootId];
  while (queue.length) {
    const parentId = queue.shift();
    const parentKey = session.folderKeys.get(parentId);
    for (const row of byParent.get(parentId) ?? []) {
      try {
        const wrapped = unpackBlob(row.wrappedKey);
        const key = await unwrapKey(wrapped.ciphertext, wrapped.iv, parentKey, AES, true, USAGES);
        const { iv, ciphertext } = unpackBlob(row.nameEnc);
        const name = await decryptMetadata(key, iv, ciphertext);
        session.folderKeys.set(row.id, key);
        out.push({ id: row.id, parentId, name });
        queue.push(row.id);
      } catch {
        console.error('[folderFlow] skipped a folder that could not be decrypted', row.id);
      }
    }
  }
  return out;
}

/**
 * Loads every folder the user owns and decrypts the names, walking down from the vault key.
 * Returns [{ id, parentId, name }] for the vault root and all readable subfolders.
 */
export async function listFolders() {
  const session = await readySession();
  const rows = await getBackend().listFolders();
  return decryptTree(session, rows, session.vaultFolderId, session.vaultFolderKey);
}

/** Creates an encrypted subfolder under `parentId` (the vault id or any folder returned by listFolders). */
export async function createSubfolder(rawName, parentId) {
  const name = cleanFolderName(rawName);
  const session = await readySession();
  const parentKey = session.folderKeys.get(parentId);
  if (!parentKey) {
    // Not cached yet (e.g. the page never listed folders). Load the tree once, then look again.
    await listFolders();
  }
  const key = session.folderKeys.get(parentId);
  if (!key) throw new ApiError(ERROR_CODES.INVALID_REQUEST, 'That folder could not be found.', 404);

  const folderKey = await generateAesKey();
  const nameBlob = await encryptMetadata(folderKey, name);
  const wrapped = await wrapKey(folderKey, key);

  const { folderId } = await getBackend().createFolder({
    nameEnc: packBlob(nameBlob.iv, nameBlob.ciphertext),
    parentId,
    wrappedKey: packBlob(wrapped.iv, wrapped.wrapped),
  });
  session.folderKeys.set(folderId, folderKey);
  return { id: folderId, parentId, name };
}


/** The decrypted AES key of a folder the user owns (used by fileFlow.js to wrap file keys). Loads the tree if needed. */
export async function getFolderKey(folderId) {
  const session = await readySession();
  if (!session.folderKeys.get(folderId)) await listFolders();
  const key = session.folderKeys.get(folderId);
  if (!key) throw new ApiError(ERROR_CODES.INVALID_REQUEST, 'That folder could not be found.', 404);
  return key;
}
