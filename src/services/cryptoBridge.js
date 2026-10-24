// Thin wrapper over Nathan's crypto module (src/crypto/), kept for tests and tooling that only need
// the request-shaped values. The app itself goes through authFlow.js, which also keeps the unwrapped
// keys in memory and creates the vault folder.
//
// The password is only ever used inside these functions and is never sent anywhere.

import { setupAccount, deriveKeys } from '../crypto/keyManager.js';
import { base64ToBuf, bufToBase64 } from '../crypto/encoding.js';

/**
 * @returns the crypto half of the register request:
 *   { authSecret, kdfSalt, kdfIterations, publicKey, wrappedPrivateKey }  (all base64)
 * The local-only key objects are dropped; use authFlow.register() if you need them.
 */
export async function prepareRegistration(password) {
  const { _localOnly, ...payload } = await setupAccount(password);
  return payload;
}

/**
 * @param params { kdfSalt, kdfIterations } from authApi.getAuthParams(email), fetched BEFORE this call.
 * @returns { authSecret } base64, for the login request.
 */
export async function prepareLogin(password, params) {
  const { authSecret } = await deriveKeys(password, new Uint8Array(base64ToBuf(params.kdfSalt)), params.kdfIterations);
  return { authSecret: bufToBase64(authSecret) };
}
