// src/services/authFlow.js
// The crypto layer for registration and login. Pages call THESE functions.
//
//   pages  ->  authFlow.js (this file: keys, wrapping, vault folder)  ->  backend (Prince's Supabase layer)
//
// This file never talks to Supabase itself. It receives a `backend` object (see configure() below),
// so the same code runs against the mock backend and the real Supabase one.
//
// The password never leaves this file. Only values derived from it are passed to the backend.
// Unwrapped keys live in `session` (memory only): a page refresh means logging in again.

import { setupAccount, deriveKeys, unwrapPrivateKey, wrapToUser, unwrapFromUser } from "../crypto/keyManager.js";
import { generateAesKey, encryptMetadata } from "../crypto/cryptoEngine.js";
import { bufToBase64, base64ToBuf, concatBytes, packBlob } from "../crypto/encoding.js";
import { ApiError } from "./apiClient.js";
import { ERROR_CODES } from "./contract.js";

export { ApiError, ERROR_CODES };

// ---------- backend wiring ----------
// backend must provide:
//   getAuthParams(email)            -> { kdfSalt, kdfIterations }
//   register(payload)               -> { userId, sessionToken }
//   login({ email, authSecret })    -> { userId, sessionToken, kdfSalt, wrappedPrivateKey, displayName? }
//   logout()                        -> void
//   createFolder({ nameEnc, parentId, wrappedKey }) -> { folderId }          (PROPOSED, Prince to build)
//   createGrant({ resourceType, resourceId, granteeId, role, wrappedKey, ephemeralPublicKey }) -> { grantId }  (PROPOSED)
//   getVault()                      -> null | { id, nameEnc, myGrant: { wrappedKey, ephemeralPublicKey } }     (PROPOSED)
let backend = null;
export function configure(options) {
  if (options.backend) backend = options.backend;
}
function be() {
  if (!backend) throw new Error("authFlow is not configured. Call configure({ backend }) once at app start.");
  return backend;
}

// ---------- session (memory only) ----------
let session = null;
export const getSession = () => session;
export const isLoggedIn = () => session !== null;

export async function logout() {
  session = null; // drop the private key, vault key and token first
  try { await be().logout(); } catch { /* the local session is already gone */ }
}

// ---------- helpers ----------
function b64urlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64url.length + 3) % 4);
  return new Uint8Array(base64ToBuf(b64));
}

// Rebuild the raw public key (0x04 || x || y) from the unwrapped private key,
// so we never depend on the server handing our own public key back to us.
async function publicKeyFromPrivate(privateKey) {
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  return bufToBase64(concatBytes(new Uint8Array([4]), b64urlToBytes(jwk.x), b64urlToBytes(jwk.y)));
}

// ---------- vault folder ----------
// Chapter 4: the top-level "vault" folder is created at registration. Its key is random and is
// stored only as a grant wrapped to the user's own public key.
async function createVaultFolder() {
  const folderKey = await generateAesKey();
  const { iv, ciphertext } = await encryptMetadata(folderKey, "Vault");
  const { folderId } = await be().createFolder({ nameEnc: packBlob(iv, ciphertext), parentId: null, wrappedKey: null });
  const grant = await wrapToUser(folderKey, base64ToBuf(session.publicKey));
  await be().createGrant({
    resourceType: "FOLDER",
    resourceId: folderId,
    granteeId: session.userId,
    role: "OWNER",
    wrappedKey: grant.wrappedKey,
    ephemeralPublicKey: grant.ephemeralPublicKey,
  });
  session.vaultFolderId = folderId;
  session.vaultFolderKey = folderKey;
}

export async function loadVault() {
  const vault = await be().getVault();
  if (!vault) return false;
  session.vaultFolderKey = await unwrapFromUser(vault.myGrant.wrappedKey, vault.myGrant.ephemeralPublicKey, session.privateKey);
  session.vaultFolderId = vault.id;
  return true;
}

// ---------- register ----------
export async function register(email, displayName, password) {
  const account = await setupAccount(password);
  const { _localOnly, ...payload } = account; // _localOnly holds keys: it must NEVER be sent

  const { userId, sessionToken } = await be().register({ email, displayName, ...payload });

  session = {
    userId, sessionToken, email, displayName,
    privateKey: _localOnly.userKeyPair.privateKey,
    publicKey: payload.publicKey,
    vaultFolderId: null,
    vaultFolderKey: null,
  };
  // The account already exists at this point. If saving the vault fails (network drop, say), don't
  // report the whole registration as failed: a retry would only say "email taken". login() creates
  // the vault on the next sign-in (see below), and session.vaultFolderKey stays null until then.
  try {
    await createVaultFolder();
  } catch (err) {
    console.error("[authFlow] vault folder was not created during registration", err);
  }
  return { userId, email, displayName, vaultReady: session.vaultFolderKey !== null };
}

// ---------- login ----------
// options.loadVault = false lets you test login before the vault backend functions exist.
export async function login(email, password, options = {}) {
  const wantVault = options.loadVault !== false;

  // 1. Get the salt and iteration count we need to re-derive the keys.
  const { kdfSalt, kdfIterations } = await be().getAuthParams(email);
  const { authSecret, kek } = await deriveKeys(password, new Uint8Array(base64ToBuf(kdfSalt)), kdfIterations);

  // 2. Prove who we are with authSecret (never the password).
  const res = await be().login({ email, authSecret: bufToBase64(authSecret) });

  // 3. Unwrap the private key locally. A wrong password fails here even if a dishonest
  //    server accepted the login, because the key encryption key would be wrong.
  let privateKey;
  try {
    privateKey = await unwrapPrivateKey(res.wrappedPrivateKey, kek);
  } catch {
    throw new ApiError(ERROR_CODES.INVALID_CREDENTIALS, "Incorrect email or password.", 400);
  }

  session = {
    userId: res.userId, sessionToken: res.sessionToken, email, displayName: res.displayName ?? null,
    privateKey,
    publicKey: await publicKeyFromPrivate(privateKey),
    vaultFolderId: null,
    vaultFolderKey: null,
  };

  if (wantVault) {
    try {
      const found = await loadVault();
      if (!found) await createVaultFolder(); // e.g. registration was interrupted before the vault was saved
    } catch (err) {
      session = null;
      throw err;
    }
  }
  return { userId: res.userId, email, displayName: session.displayName };
}
