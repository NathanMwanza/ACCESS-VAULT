// The ONLY place the UI touches cryptography.
//
// Pages call prepareRegistration() / prepareLogin() and never see keys, salts or
// hashing details (usability requirement: users and UI code never handle keys directly).
//
// Phase 1: backed by fake values (mock/mockCrypto.js) shaped like the contract.
// Phase 2: swap the bodies below to call Nathan's module in src/crypto/ (Algorithm 4.1).
//
// The password is only ever used inside these functions and is never sent anywhere.

import { deriveMockAuthSecret, randomBase64 } from './mock/mockCrypto.js';

const KDF_ITERATIONS = 600000; // Algorithm 4.1

/**
 * @returns the crypto half of the POST /auth/register body:
 *   { authSecret, kdfSalt, kdfIterations, publicKey, wrappedPrivateKey }
 */
export async function prepareRegistration(password, email) {
  // TODO(Phase 2): const out = await setupAccount(password);  // from '../crypto'
  //                return out;  // already base64, already in contract shape
  return {
    authSecret: await deriveMockAuthSecret(password, email),
    kdfSalt: randomBase64(16),
    kdfIterations: KDF_ITERATIONS,
    publicKey: randomBase64(65),
    wrappedPrivateKey: randomBase64(166), // 12-byte IV + ciphertext
  };
}

/**
 * @param params { kdfSalt, kdfIterations } from authApi.getAuthParams(email), fetched BEFORE this call.
 * @returns { authSecret } for the login request.
 *
 * Real scheme: authSecret = HKDF(PBKDF2(password, params.kdfSalt, params.kdfIterations)).
 * The mock ignores params. When Nathan's module lands, use them here (and only here).
 */
export async function prepareLogin(password, email, params = null) {
  // TODO(Phase 2): derive with params.kdfSalt / params.kdfIterations using Nathan's module.
  void params;
  return { authSecret: await deriveMockAuthSecret(password, email) };
}
