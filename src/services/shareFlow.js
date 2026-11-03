// Sharing folders (read-only) between users, and revoking.
//
//   pages -> shareFlow.js (wrap/unwrap keys) -> backend (mock or Supabase) -> server rules (migration 005)
//
// Algorithm 4.3: to share, the owner's browser wraps the FOLDER's AES key to the recipient's public key
// (ephemeral ECDH + HKDF + AES-GCM) and uploads only the wrapped key. Holding a folder key is enough to open
// everything under it, because subfolder keys and file keys are wrapped under their parent's key.
// The recipient's browser unwraps the grant with their private key; the server never sees a key.
//
// Revoking: the server stops serving the folder to that person and deletes their wrapped key. It cannot
// recall anything they already downloaded and decrypted, and the folder key is not rotated (see docs).
//
// Trust note: the recipient's public key comes from the server, so a dishonest server could substitute its own.
// That is why the UI shows a key fingerprint before sharing, so the two people can compare it out of band.

import { getBackend, getSession } from "./authFlow.js";
import { decryptTree, getFolderKey } from "./folderFlow.js";
import { ApiError } from "./apiClient.js";
import { ERROR_CODES } from "./contract.js";
import { decryptMetadata } from "../crypto/cryptoEngine.js";
import { wrapToUser, unwrapFromUser } from "../crypto/keyManager.js";
import { base64ToBuf, unpackBlob } from "../crypto/encoding.js";

const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function signedIn() {
  const session = getSession();
  if (!session)
    throw new ApiError(
      ERROR_CODES.INVALID_CREDENTIALS,
      "Please sign in again.",
      401,
    );
  if (!session.folderKeys) session.folderKeys = new Map();
  return session;
}

/** "3FA9 C2D1 …": first 16 bytes of SHA-256 of a public key, for people to compare. */
export async function fingerprint(publicKeyBase64) {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", base64ToBuf(publicKeyBase64)),
  );
  return Array.from(digest.slice(0, 16), (b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase()
    .replace(/(.{4})(?=.)/g, "$1 ");
}

/** Finds a recipient by email. Returns { userId, name, publicKey, fingerprint }. */
export async function lookupRecipient(rawEmail) {
  signedIn();
  const email = String(rawEmail ?? "").trim();
  if (!EMAIL_SHAPE.test(email))
    throw new ApiError(
      ERROR_CODES.INVALID_REQUEST,
      "Enter a valid email address.",
      400,
    );
  const target = await getBackend().findShareTarget(email);
  if (!target) {
    throw new ApiError(
      ERROR_CODES.INVALID_REQUEST,
      "No Access Vault account was found for that email, or it is your own.",
      404,
    );
  }
  return { ...target, fingerprint: await fingerprint(target.publicKey) };
}

/**
 * Shares folder `folderId` read-only with `recipient` (from lookupRecipient). `expiresAt` is an optional Date or
 * ISO string after which access stops by itself. Returns { shareId }.
 */
export async function shareFolder(
  folderId,
  recipient,
  { expiresAt = null } = {},
) {
  const session = signedIn();
  if (folderId === session.vaultFolderId) {
    throw new ApiError(
      ERROR_CODES.INVALID_REQUEST,
      "Your whole vault cannot be shared. Share a folder inside it.",
      400,
    );
  }
  const folderKey = await getFolderKey(folderId);
  const grant = await wrapToUser(folderKey, base64ToBuf(recipient.publicKey));
  return getBackend().shareResource({
    resourceType: "FOLDER",
    resourceId: folderId,
    recipientId: recipient.userId,
    level: "VIEWER",
    wrappedKey: grant.wrappedKey,
    ephemeralPublicKey: grant.ephemeralPublicKey,
    expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
  });
}

/** Who this folder is shared with: [{ shareId, email, name, level, createdAt, expiresAt }]. */
export async function listShares(folderId) {
  signedIn();
  return getBackend().listShares(folderId);
}

export async function revokeShare(shareId) {
  signedIn();
  await getBackend().revokeShare(shareId);
}

/**
 * Folders other people shared with me, with decrypted names: [{ shareId, folderId, name, ownerName, ownerEmail, createdAt, expiresAt }].
 * Unwrapping the key grant also caches the folder key so the folder can be opened and its files read.
 */
export async function listSharedWithMe() {
  const session = signedIn();
  const rows = await getBackend().listSharedWithMe();
  const out = [];
  for (const row of rows) {
    try {
      const key = await unwrapFromUser(
        row.wrappedKey,
        row.ephemeralPublicKey,
        session.privateKey,
      );
      const { iv, ciphertext } = unpackBlob(row.nameEnc);
      const name = await decryptMetadata(key, iv, ciphertext);
      session.folderKeys.set(row.folderId, key);
      out.push({
        shareId: row.shareId,
        folderId: row.folderId,
        name,
        ownerName: row.ownerName,
        ownerEmail: row.ownerEmail,
        createdAt: row.createdAt,
        expiresAt: row.expiresAt ?? null,
      });
    } catch {
      console.error(
        "[shareFlow] skipped a share that could not be decrypted",
        row.shareId,
      );
    }
  }
  return out;
}

/**
 * The shared folder and everything under it, decrypted: [{ id, parentId, name }] (root parentId null).
 * Call listSharedWithMe() first so the folder key is loaded.
 */
export async function openSharedFolder(rootId) {
  const session = signedIn();
  const rootKey = session.folderKeys.get(rootId);
  if (!rootKey)
    throw new ApiError(
      ERROR_CODES.INVALID_REQUEST,
      "That shared folder could not be found.",
      404,
    );
  const rows = await getBackend().listSharedSubtree(rootId);
  if (!rows.length)
    throw new ApiError(
      ERROR_CODES.INVALID_REQUEST,
      "This folder is no longer shared with you.",
      403,
    );
  return decryptTree(session, rows, rootId, rootKey);
}
