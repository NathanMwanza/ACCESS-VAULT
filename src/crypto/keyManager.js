// keyManager.js
// Implements the KeyManager module from Table 4.6:
//   deriveKeys(password, salt) -> { authSecret, kek }
//   generateUserKeyPair()
//   wrapKey(key, wrappingKey) / unwrapKey(blob, wrappingKey)
//   wrapToUser(key, publicKey) / unwrapFromUser(blob, privateKey)
//
// Matches Algorithm 4.1 (Key derivation and account key setup):
//   password --PBKDF2(salt, 600000, SHA-256)--> master secret (512 bit)
//   master secret --HKDF info="av-auth"--> authSecret (sent to server, as proof of identity)
//   master secret --HKDF info="av-kek"--> KEK (stays in browser memory, wraps the private key)

import { bufToBase64, base64ToBuf, concatBytes } from "./encoding.js";

export const KDF_ITERATIONS = 600000; // per Table 4.4 / Algorithm 4.1, follows OWASP guidance

/**
 * Derive the master secret from a password + salt via PBKDF2, per Algorithm 4.1.
 * The password itself is never transmitted or stored anywhere - only values
 * derived from it (authSecret to the server, kek kept in memory).
 */
async function deriveMasterSecret(password, salt /* Uint8Array */, iterations = KDF_ITERATIONS) {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  // 512 bits, per "master <- PBKDF2(password, salt, iterations=600000, hash=SHA-256, bits=512)"
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    passwordKey,
    512
  );
  return bits; // ArrayBuffer, 64 bytes
}

/**
 * Split the master secret into authSecret and kek using HKDF with distinct
 * info labels, per Algorithm 4.1: HKDF(master, info="av-auth"/"av-kek", bits=256).
 */
async function hkdfSplit(masterSecretBytes, infoLabel) {
  const hkdfKey = await crypto.subtle.importKey("raw", masterSecretBytes, "HKDF", false, ["deriveBits"]);
  const info = new TextEncoder().encode(infoLabel);
  const salt = new Uint8Array(0); // HKDF salt not reused here; master secret is already high-entropy
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info },
    hkdfKey,
    256
  );
  return bits; // ArrayBuffer, 32 bytes
}

/**
 * deriveKeys(password, salt): the public entry point other modules use when
 * a user is logging in (salt already known from the server) rather than
 * registering fresh.
 * @returns {Promise<{authSecret: ArrayBuffer, kek: CryptoKey}>}
 */
export async function deriveKeys(password, saltBytes) {
  const master = await deriveMasterSecret(password, saltBytes);
  const authSecretBits = await hkdfSplit(master, "av-auth");
  const kekBits = await hkdfSplit(master, "av-kek");
  const kek = await crypto.subtle.importKey("raw", kekBits, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  return { authSecret: authSecretBits, kek };
}

/** Generate a fresh ECDH P-256 key pair for a new user, per 4.4.1.3 step 3. */
export async function generateUserKeyPair() {
  return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
}

/**
 * Wrap (encrypt) a CryptoKey with another CryptoKey (e.g. wrap the private
 * key with the KEK). Returns { iv, wrapped } - both needed to unwrap later,
 * and both are safe to store/transmit since the plaintext key never appears.
 */
export async function wrapKey(keyToWrap, wrappingKey) {
  // Export + AES-GCM encrypt (instead of subtle.wrapKey) so the wrapping key only needs
  // the normal "encrypt"/"decrypt" usages that generateAesKey() gives every key.
  const raw = await crypto.subtle.exportKey("raw", keyToWrap);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrappingKey, raw);
  return { iv, wrapped };
}

/** Unwrap a previously wrapped CryptoKey. `format`/`algorithm` must match how it was wrapped. */
export async function unwrapKey(wrappedBytes, iv, wrappingKey, unwrappedAlgorithm, extractable, usages) {
  let raw;
  try {
    raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, wrappingKey, wrappedBytes);
  } catch {
    throw new Error("Could not unwrap key (wrong wrapping key or corrupted data).");
  }
  return crypto.subtle.importKey("raw", raw, unwrappedAlgorithm, extractable, usages);
}

/**
 * setupAccount(password): full Algorithm 4.1 flow for a NEW registration.
 * Generates a fresh random salt, derives keys, generates the ECDH key pair,
 * wraps the private key with the KEK, and returns exactly the fields
 * /auth/register expects (see Table 4.7 / the request-shape agreement),
 * all already base64-encoded for JSON transport.
 *
 * The plaintext password and master secret are never returned or retained.
 */
export async function setupAccount(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const { authSecret, kek } = await deriveKeys(password, salt);

  const userKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );

  const publicKeyRaw = await crypto.subtle.exportKey("raw", userKeyPair.publicKey);
  const { iv: privKeyIv, wrapped: wrappedPrivateKeyRaw } = await wrapPrivateKeyRaw(userKeyPair.privateKey, kek);

  return {
    // --- goes to POST /auth/register, matches the field-by-field agreement ---
    kdfSalt: bufToBase64(salt),
    kdfIterations: KDF_ITERATIONS,
    authSecret: bufToBase64(authSecret),
    publicKey: bufToBase64(publicKeyRaw),
    // IV is prepended so wrappedPrivateKey is a single self-contained blob
    wrappedPrivateKey: bufToBase64(concatBytes(privKeyIv, wrappedPrivateKeyRaw)),
    // --- kept locally, never sent anywhere ---
    _localOnly: { kek, userKeyPair },
  };
}

/**
 * Private keys can't be wrapped with subtle.wrapKey the same simple way as
 * AES keys in every browser implementation for ECDH, so we export to raw
 * PKCS8 bytes and encrypt those directly with AES-GCM - functionally
 * identical to Algorithm 4.1's "wrappedPriv <- AES-GCM-Encrypt(kek, randomIV, export(priv))".
 */
async function wrapPrivateKeyRaw(privateKey, kek) {
  const exported = await crypto.subtle.exportKey("pkcs8", privateKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, kek, exported);
  return { iv, wrapped: new Uint8Array(wrapped) };
}

/**
 * The inverse, used at login: given the wrapped-private-key blob (iv + ciphertext)
 * fetched from the server and the freshly re-derived kek, recover a usable
 * ECDH CryptoKey. Throws if the password was wrong (AES-GCM tag won't verify).
 */
export async function unwrapPrivateKey(wrappedPrivateKeyBase64, kek) {
  const combined = new Uint8Array(base64ToBuf(wrappedPrivateKeyBase64));
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  let pkcs8;
  try {
    pkcs8 = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, kek, ciphertext);
  } catch {
    throw new Error("Incorrect password (could not unwrap private key).");
  }
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
}

/**
 * wrapToUser / unwrapFromUser: Algorithm 4.3's sharing step.
 * An ephemeral ECDH exchange with the recipient's public key derives a
 * one-time wrapping key (via HKDF), which wraps the item key (a folder or
 * file key). The server only ever sees the wrapped result + the ephemeral
 * public key - never the item key itself.
 */
export async function wrapToUser(itemKey, recipientPublicKeyRaw) {
  const recipientPublicKey = await crypto.subtle.importKey(
    "raw", recipientPublicKeyRaw, { name: "ECDH", namedCurve: "P-256" }, true, []
  );
  const ephemeralPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: recipientPublicKey }, ephemeralPair.privateKey, 256
  );
  const wrapKeyMaterial = await hkdfSplit(sharedBits, "av-grant");
  const wrapKeyObj = await crypto.subtle.importKey("raw", wrapKeyMaterial, { name: "AES-GCM" }, false, ["encrypt"]);

  const itemKeyRaw = await crypto.subtle.exportKey("raw", itemKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrapKeyObj, itemKeyRaw);
  const ephemeralPublicKeyRaw = await crypto.subtle.exportKey("raw", ephemeralPair.publicKey);

  return {
    wrappedKey: bufToBase64(concatBytes(iv, wrapped)),
    ephemeralPublicKey: bufToBase64(ephemeralPublicKeyRaw),
  };
}

export async function unwrapFromUser(wrappedKeyBase64, ephemeralPublicKeyBase64, myPrivateKey) {
  const ephemeralPublicKey = await crypto.subtle.importKey(
    "raw", base64ToBuf(ephemeralPublicKeyBase64), { name: "ECDH", namedCurve: "P-256" }, true, []
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: ephemeralPublicKey }, myPrivateKey, 256
  );
  const wrapKeyMaterial = await hkdfSplit(sharedBits, "av-grant");
  const wrapKeyObj = await crypto.subtle.importKey("raw", wrapKeyMaterial, { name: "AES-GCM" }, false, ["decrypt"]);

  const combined = new Uint8Array(base64ToBuf(wrappedKeyBase64));
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const itemKeyRaw = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, wrapKeyObj, ciphertext);
  return crypto.subtle.importKey("raw", itemKeyRaw, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
}
