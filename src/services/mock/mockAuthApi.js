// Mock of /auth/register and /auth/login (Phase 1).
// Responses are shaped EXACTLY like the API Agreements sheet, and requests are
// checked against the contract, so a drift between UI and contract fails loudly
// here instead of surfacing in Phase 2.
//
// State lives in module memory only: refresh the page and registered mock users
// are gone. A demo user is pre-seeded (see DEMO_USER below).

import { ApiError } from '../apiClient.js';
import { ERROR_CODES, checkLoginRequest, checkRegisterRequest } from '../contract.js';
import { bytesToBase64 } from '../../utils/base64.js';
import { deriveMockAuthSecret, randomBase64 } from './mockCrypto.js';

let latencyMs = 500;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** For tests: make the mock instant. */
export function __setMockLatency(ms) {
  latencyMs = ms;
}

export const DEMO_USER = {
  email: 'demo@accessvault.test',
  password: 'correct horse battery staple',
  displayName: 'Demo User',
};

const users = new Map(); // email -> { userId, displayName, authSecret, kdfSalt, wrappedPrivateKey }
let seeded = false;

async function seedDemoUser() {
  if (seeded) return;
  seeded = true;
  users.set(DEMO_USER.email, {
    userId: crypto.randomUUID(),
    displayName: DEMO_USER.displayName,
    authSecret: await deriveMockAuthSecret(DEMO_USER.password, DEMO_USER.email),
    kdfSalt: randomBase64(16),
    wrappedPrivateKey: randomBase64(166),
  });
}

/** For tests: wipe state. */
export function __resetMockAuth() {
  users.clear();
  seeded = false;
}

function newSessionToken() {
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(32)));
}

const normalise = (email) => email.trim().toLowerCase();

/** Mirrors supabaseAuthApi.getAuthParams: the salt the browser needs before it can build authSecret. */
export async function getAuthParams(email) {
  await seedDemoUser();
  await sleep(latencyMs);
  const record = users.get(normalise(email));
  // Unknown emails get a fake salt too, like the real endpoint, so existence is not revealed.
  return { kdfSalt: record?.kdfSalt ?? randomBase64(16), kdfIterations: 600000 };
}

export async function logout() {
  /* nothing to end in the mock */
}

export async function register(payload) {
  await seedDemoUser();
  await sleep(latencyMs);

  const problems = checkRegisterRequest(payload);
  if (problems.length) {
    throw new ApiError(ERROR_CODES.INVALID_REQUEST, `Request does not match the API contract: ${problems.join('; ')}`, 400);
  }

  const email = normalise(payload.email);
  if (users.has(email)) {
    throw new ApiError(ERROR_CODES.EMAIL_TAKEN, 'An account with this email already exists.', 409);
  }

  const userId = crypto.randomUUID();
  users.set(email, {
    userId,
    displayName: payload.displayName,
    authSecret: payload.authSecret,
    kdfSalt: payload.kdfSalt,
    wrappedPrivateKey: payload.wrappedPrivateKey,
  });

  // Contract: { userId: uuid, sessionToken: string }
  return { userId, sessionToken: newSessionToken() };
}

export async function login(payload) {
  await seedDemoUser();
  await sleep(latencyMs);

  const problems = checkLoginRequest(payload);
  if (problems.length) {
    throw new ApiError(ERROR_CODES.INVALID_REQUEST, `Request does not match the API contract: ${problems.join('; ')}`, 400);
  }

  const record = users.get(normalise(payload.email));
  // Same error for "no such user" and "wrong password" so the response never reveals which was wrong.
  if (!record || record.authSecret !== payload.authSecret) {
    throw new ApiError(ERROR_CODES.INVALID_CREDENTIALS, 'Incorrect email or password.', 401);
  }

  // Contract: { userId, sessionToken, kdfSalt, wrappedPrivateKey }
  return {
    userId: record.userId,
    sessionToken: newSessionToken(),
    kdfSalt: record.kdfSalt,
    wrappedPrivateKey: record.wrappedPrivateKey,
    displayName: record.displayName,
  };
}
