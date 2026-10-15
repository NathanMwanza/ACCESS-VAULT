// cryptoEngine.js
// Implements the CryptoEngine module from Table 4.6:
//   encryptChunk(key, nonce, index, isLast, bytes)
//   decryptChunk(key, nonce, index, isLast, ciphertext)
//   encryptMetadata(key, text) / decryptMetadata(key, blob)
//
// Matches Algorithm 4.2 (Chunked file encryption):
//   - AES-256-GCM
//   - nonce = baseNonce (8 bytes) || chunkIndex (4 bytes, uint32)  => 12-byte GCM IV
//   - AAD = fileId || chunkIndex || isLastChunk   (binds position + finality to the ciphertext,
//     so reordering/removing/truncating chunks is detected on decrypt)

import { concatBytes, uint32BE } from "./encoding.js";

const AES_ALG = "AES-GCM";

/**
 * Build the 12-byte GCM nonce for chunk `index` under one file's baseNonce.
 * Per 4.4.2.4: "a nonce is never reused under one key" because the counter
 * portion is unique per chunk and the key is unique per file.
 */
function chunkNonce(baseNonce /* 8 bytes */, index /* integer */) {
  const nonce = concatBytes(baseNonce, uint32BE(index));
  if (nonce.byteLength !== 12) {
    throw new Error(`Expected 12-byte nonce, got ${nonce.byteLength}`);
  }
  return nonce;
}

/**
 * Build the Additional Authenticated Data for a chunk: fileId || index || isLast.
 * This does not need to be secret, only authenticated - it stops an attacker
 * (or a buggy server) from reordering, dropping, or truncating chunks without
 * decryption failing.
 */
function chunkAAD(fileId, index, isLast) {
  const enc = new TextEncoder();
  return concatBytes(enc.encode(fileId), uint32BE(index), new Uint8Array([isLast ? 1 : 0]));
}

/**
 * Encrypt one chunk of plaintext bytes.
 * @param {CryptoKey} fileKey - AES-256-GCM key for this file
 * @param {Uint8Array} baseNonce - 8-byte random value generated once per file
 * @param {string} fileId
 * @param {number} index - zero-based chunk index
 * @param {boolean} isLast - true for the final chunk of the file
 * @param {ArrayBuffer|Uint8Array} plaintextBytes
 * @returns {Promise<ArrayBuffer>} ciphertext (includes the GCM auth tag)
 */
export async function encryptChunk(fileKey, baseNonce, fileId, index, isLast, plaintextBytes) {
  const iv = chunkNonce(baseNonce, index);
  const aad = chunkAAD(fileId, index, isLast);
  return crypto.subtle.encrypt(
    { name: AES_ALG, iv, additionalData: aad, tagLength: 128 },
    fileKey,
    plaintextBytes
  );
}

/**
 * Decrypt one chunk. Throws (rejects) if the GCM tag does not verify -
 * per 4.4.2.5: "If any chunk fails authentication, the download is aborted
 * and the user is told that the file is corrupted or has been tampered with."
 */
export async function decryptChunk(fileKey, baseNonce, fileId, index, isLast, ciphertextBytes) {
  const iv = chunkNonce(baseNonce, index);
  const aad = chunkAAD(fileId, index, isLast);
  try {
    return await crypto.subtle.decrypt(
      { name: AES_ALG, iv, additionalData: aad, tagLength: 128 },
      fileKey,
      ciphertextBytes
    );
  } catch (err) {
    throw new Error("Chunk failed authentication - file is corrupted or has been tampered with.");
  }
}

/**
 * Encrypt a short piece of metadata (e.g. a file or folder name) with a
 * random IV stored alongside the ciphertext (IV does not need to be secret).
 * Returns { iv, ciphertext } ready to concatenate/store as one blob.
 */
export async function encryptMetadata(key, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(text);
  const ciphertext = await crypto.subtle.encrypt({ name: AES_ALG, iv }, key, plaintext);
  return { iv, ciphertext };
}

export async function decryptMetadata(key, iv, ciphertext) {
  const plaintext = await crypto.subtle.decrypt({ name: AES_ALG, iv }, key, ciphertext);
  return new TextDecoder().decode(plaintext);
}

/** Generate a fresh random 256-bit AES-GCM key (used for file keys, folder keys, the KEK). */
export async function generateAesKey() {
  return crypto.subtle.generateKey({ name: AES_ALG, length: 256 }, true, ["encrypt", "decrypt"]);
}
