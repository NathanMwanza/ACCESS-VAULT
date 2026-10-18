// FAKE crypto for Phase 1 so the UI can run before Nathan's module lands.
// Produces values with the right SHAPE and SIZE only. Nothing here is secure.
// Replaced by Nathan's setupAccount() in Phase 2 (see services/cryptoBridge.js).

import { bytesToBase64 } from '../../utils/base64.js';

export function randomBase64(byteLength) {
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(byteLength)));
}

/** Deterministic 32-byte "auth secret" so a wrong password fails to log in against the mock. */
export async function deriveMockAuthSecret(password, email) {
  const data = new TextEncoder().encode(`mock-auth:${email.trim().toLowerCase()}:${password}`);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return bytesToBase64(new Uint8Array(digest));
}
