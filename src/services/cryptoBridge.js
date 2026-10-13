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
 * @returns { authSecret } for POST /auth/login.
 *
 * OPEN QUESTION FOR THE TEAM (raise before Phase 2): in the real scheme
 * authSecret = HKDF(PBKDF2(password, kdfSalt)), but the salt is only returned BY
 * login, after the authSecret has been sent. The browser needs the salt first.
 * See docs/OPEN_QUESTIONS.md.
 */
export async function prepareLogin(password, email) {
  return { authSecret: await deriveMockAuthSecret(password, email) };
}
