// Single place that encodes the Access Vault API & Data Agreements sheet.
// Everything here is camelCase and every binary value is a base64 string.
// Prince owns the camelCase <-> snake_case conversion at the API boundary (#3),
// so the frontend never sees snake_case.

import { base64ByteLength, isBase64 } from '../utils/base64.js';

/** Stable error codes the UI branches on (#4). Add new ones to the sheet first. */
export const ERROR_CODES = {
  INVALID_CREDENTIALS: 'invalid_credentials',
  EMAIL_TAKEN: 'email_taken',
  INVALID_REQUEST: 'invalid_request',
  NETWORK_ERROR: 'network_error', // frontend-only: request never reached the server
  UNKNOWN: 'unknown_error', // frontend-only: server replied in an unexpected shape
};

/** Expected decoded sizes, from the agreements sheet. */
export const SIZES = {
  authSecret: 32,
  kdfSalt: 16,
  publicKey: 65, // raw ECDH P-256 export (uncompressed point)
};

/**
 * POST /auth/register request
 * { email, displayName, authSecret, kdfSalt, kdfIterations, publicKey, wrappedPrivateKey }
 * Returns problems[] (empty array = shape is valid).
 */
export function checkRegisterRequest(p) {
  const problems = [];
  if (!p || typeof p !== 'object') return ['body must be an object'];
  if (typeof p.email !== 'string') problems.push('email must be a string');
  if (typeof p.displayName !== 'string') problems.push('displayName must be a string');
  if (base64ByteLength(p.authSecret) !== SIZES.authSecret) problems.push('authSecret must be base64 of 32 bytes');
  if (base64ByteLength(p.kdfSalt) !== SIZES.kdfSalt) problems.push('kdfSalt must be base64 of 16 bytes');
  if (!Number.isInteger(p.kdfIterations)) problems.push('kdfIterations must be an integer');
  if (base64ByteLength(p.publicKey) !== SIZES.publicKey) problems.push('publicKey must be base64 of a raw P-256 key (65 bytes)');
  if (!isBase64(p.wrappedPrivateKey)) problems.push('wrappedPrivateKey must be a base64 string (IV + ciphertext)');
  return problems;
}

/** POST /auth/login request: { email, authSecret } */
export function checkLoginRequest(p) {
  const problems = [];
  if (!p || typeof p !== 'object') return ['body must be an object'];
  if (typeof p.email !== 'string') problems.push('email must be a string');
  if (base64ByteLength(p.authSecret) !== SIZES.authSecret) problems.push('authSecret must be base64 of 32 bytes');
  return problems;
}

/** Register response: { userId, sessionToken } */
export function isRegisterResponse(r) {
  return !!r && typeof r.userId === 'string' && typeof r.sessionToken === 'string';
}

/** Login response: { userId, sessionToken, kdfSalt, wrappedPrivateKey } */
export function isLoginResponse(r) {
  return (
    !!r &&
    typeof r.userId === 'string' &&
    typeof r.sessionToken === 'string' &&
    isBase64(r.kdfSalt) &&
    isBase64(r.wrappedPrivateKey)
  );
}
