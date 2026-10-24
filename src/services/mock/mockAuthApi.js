// Mock of /auth/register and /auth/login (Phase 1).
// Responses are shaped EXACTLY like the API Agreements sheet, and requests are
// checked against the contract, so a drift between UI and contract fails loudly
// here instead of surfacing in Phase 2.
//
// State lives in module memory only: refresh the page and registered mock users
// are gone. A demo user is pre-seeded (see DEMO_USER below).
//
// The mock now behaves like the real server: it stores whatever crypto fields the browser
// sends (real keys from src/crypto) and checks authSecret on login. It also implements the
// vault calls authFlow.js needs (createFolder, createGrant, getVault) so the whole
// zero-trust flow runs in mock mode and in tests.

import { ApiError } from '../apiClient.js';
import { ERROR_CODES, checkLoginRequest, checkRegisterRequest } from '../contract.js';
import { bytesToBase64 } from '../../utils/base64.js';
import { setupAccount } from '../../crypto/keyManager.js';

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

const users = new Map(); // email -> { userId, displayName, authSecret, kdfSalt, kdfIterations, publicKey, wrappedPrivateKey }
const folders = []; // { folderId, ownerId, parentId, nameEnc, wrappedKey }
const files = []; // { fileId, folderId, ownerId, nameEnc, size, chunkCount, wrappedFileKey, baseNonce, status, createdAt }
const chunkStore = new Map(); // `${fileId}/${index}` -> Uint8Array
const grants = []; // { grantId, resourceType, resourceId, granteeId, role, wrappedKey, ephemeralPublicKey }
let currentUserId = null; // like the Supabase client's own session
let seeded = false;
let seeding = null;

async function seedDemoUser() {
  if (seeded) return;
  if (!seeding) {
    seeding = (async () => {
      // Real keys, so the demo account works with the real login flow.
      const { _localOnly, ...account } = await setupAccount(DEMO_USER.password);
      users.set(DEMO_USER.email, { userId: crypto.randomUUID(), displayName: DEMO_USER.displayName, ...account });
      seeded = true;
    })();
  }
  await seeding;
}

/** For tests: wipe state. */
export function __resetMockAuth() {
  users.clear();
  folders.length = 0;
  grants.length = 0;
  files.length = 0;
  chunkStore.clear();
  currentUserId = null;
  seeded = false;
  seeding = null;
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
  if (record) return { kdfSalt: record.kdfSalt, kdfIterations: record.kdfIterations };
  // Unknown emails get a stable fake salt too, like the real endpoint, so existence is not revealed.
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`mock-pepper:${normalise(email)}`));
  return { kdfSalt: bytesToBase64(new Uint8Array(digest).slice(0, 16)), kdfIterations: 600000 };
}

export async function logout() {
  currentUserId = null;
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
    kdfIterations: payload.kdfIterations,
    publicKey: payload.publicKey,
    wrappedPrivateKey: payload.wrappedPrivateKey,
  });
  currentUserId = userId;

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

  currentUserId = record.userId;
  // Contract: { userId, sessionToken, kdfSalt, wrappedPrivateKey }
  return {
    userId: record.userId,
    sessionToken: newSessionToken(),
    kdfSalt: record.kdfSalt,
    wrappedPrivateKey: record.wrappedPrivateKey,
    displayName: record.displayName,
  };
}

// ---------- vault calls (mirror supabaseVaultApi.js) ----------

function requireSignedIn() {
  if (!currentUserId) throw new ApiError(ERROR_CODES.INVALID_CREDENTIALS, 'Please sign in again.', 401);
  return currentUserId;
}

export async function createFolder({ nameEnc, parentId, wrappedKey }) {
  await sleep(latencyMs);
  const ownerId = requireSignedIn();
  // Same rule as the RLS policy: a folder can only be nested under one of your own.
  if (parentId && !folders.some((f) => f.folderId === parentId && f.ownerId === ownerId)) {
    throw new ApiError(ERROR_CODES.UNKNOWN, 'Something went wrong. Please try again.', 403);
  }
  const folderId = crypto.randomUUID();
  folders.push({ folderId, ownerId, parentId: parentId ?? null, nameEnc, wrappedKey: wrappedKey ?? null });
  return { folderId };
}

export async function createGrant({ resourceType, resourceId, granteeId, role, wrappedKey, ephemeralPublicKey }) {
  await sleep(latencyMs);
  const me = requireSignedIn();
  const folder = folders.find((f) => f.folderId === resourceId);
  // Same rule as the RLS policy: only the owner of a resource can hand out keys to it.
  if (resourceType === 'FOLDER' && (!folder || folder.ownerId !== me)) {
    throw new ApiError(ERROR_CODES.UNKNOWN, 'Something went wrong. Please try again.', 403);
  }
  const grantId = crypto.randomUUID();
  grants.push({ grantId, resourceType, resourceId, granteeId, role, wrappedKey, ephemeralPublicKey });
  return { grantId };
}

export async function getVault() {
  await sleep(latencyMs);
  const me = requireSignedIn();
  for (const f of folders) {
    if (f.ownerId !== me || f.parentId !== null) continue;
    const g = grants.find((x) => x.resourceType === 'FOLDER' && x.resourceId === f.folderId && x.granteeId === me);
    if (g) return { id: f.folderId, nameEnc: f.nameEnc, myGrant: { wrappedKey: g.wrappedKey, ephemeralPublicKey: g.ephemeralPublicKey } };
  }
  return null;
}

export async function listFolders() {
  await sleep(latencyMs);
  const me = requireSignedIn();
  return folders
    .filter((f) => f.ownerId === me)
    .map((f) => ({ id: f.folderId, parentId: f.parentId, nameEnc: f.nameEnc, wrappedKey: f.wrappedKey }));
}

// ---------- file calls (mirror supabaseFilesApi.js) ----------

const MAX_FILE_BYTES = 50 * 1024 * 1024; // files.size check in the database
const MAX_CHUNK_BYTES = 5243904; // storage bucket limit

const publicFile = (f) => ({
  id: f.fileId, folderId: f.folderId, nameEnc: f.nameEnc, size: f.size, chunkCount: f.chunkCount,
  wrappedFileKey: f.wrappedFileKey, baseNonce: f.baseNonce, createdAt: f.createdAt,
});

function ownFile(fileId, { requireUploading = false } = {}) {
  const me = requireSignedIn();
  const f = files.find((x) => x.fileId === fileId && x.ownerId === me);
  if (!f || (requireUploading && f.status !== 'uploading')) {
    throw new ApiError(ERROR_CODES.UNKNOWN, 'Something went wrong. Please try again.', 403);
  }
  return f;
}

export async function createFile({ fileId, folderId, nameEnc, size, chunkCount, wrappedFileKey, baseNonce }) {
  await sleep(latencyMs);
  const ownerId = requireSignedIn();
  if (!folders.some((f) => f.folderId === folderId && f.ownerId === ownerId) || size < 0 || size > MAX_FILE_BYTES || !nameEnc) {
    throw new ApiError(ERROR_CODES.UNKNOWN, 'Something went wrong. Please try again.', 403);
  }
  files.push({ fileId, folderId, ownerId, nameEnc, size, chunkCount, wrappedFileKey, baseNonce, status: 'uploading', createdAt: new Date().toISOString() });
  return { fileId };
}

export async function uploadChunk({ fileId, index, bytes }) {
  await sleep(latencyMs);
  ownFile(fileId, { requireUploading: true }); // same rule as the Storage policy
  if (bytes.byteLength > MAX_CHUNK_BYTES || chunkStore.has(`${fileId}/${index}`)) {
    throw new ApiError(ERROR_CODES.UNKNOWN, 'Something went wrong. Please try again.', 409);
  }
  chunkStore.set(`${fileId}/${index}`, new Uint8Array(bytes));
}

export async function completeFile(fileId) {
  await sleep(latencyMs);
  ownFile(fileId).status = 'complete';
}

export async function listFiles(folderId) {
  await sleep(latencyMs);
  const me = requireSignedIn();
  return files.filter((f) => f.folderId === folderId && f.ownerId === me && f.status === 'complete').map(publicFile);
}

export async function getFile(fileId) {
  await sleep(latencyMs);
  const me = requireSignedIn();
  const f = files.find((x) => x.fileId === fileId && x.ownerId === me && x.status === 'complete');
  return f ? publicFile(f) : null;
}

export async function downloadChunk({ fileId, index }) {
  await sleep(latencyMs);
  ownFile(fileId);
  const bytes = chunkStore.get(`${fileId}/${index}`);
  if (!bytes) throw new ApiError(ERROR_CODES.UNKNOWN, 'Something went wrong. Please try again.', 404);
  return new Uint8Array(bytes);
}

export async function deleteFile(fileId) {
  await sleep(latencyMs);
  const f = ownFile(fileId);
  for (const key of [...chunkStore.keys()]) if (key.startsWith(`${fileId}/`)) chunkStore.delete(key);
  files.splice(files.indexOf(f), 1);
}

/** For tests: lets a test corrupt, swap or drop stored chunks like a dishonest server could. */
export const __chunkStore = chunkStore;
