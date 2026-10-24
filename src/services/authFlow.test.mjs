// src/services/authFlow.test.mjs  (run: node src/services/authFlow.test.mjs)
// Tests register()/login() against an in-memory mock of the backend interface
// (same function names as supabaseAuthApi.js), so they run without Supabase.
// Uses the repo's real apiClient.js and contract.js.

import { configure, register, login, logout, getSession, isLoggedIn, ApiError, ERROR_CODES } from "./authFlow.js";
import { encryptChunk, decryptChunk } from "../crypto/cryptoEngine.js";

let passed = 0, failed = 0;
function check(label, cond) {
  if (cond) { console.log(`  PASS  ${label}`); passed++; }
  else { console.log(`  FAIL  ${label}`); failed++; }
}
async function rejectsWith(promise, code) {
  try { await promise; return false; }
  catch (e) { return e instanceof ApiError && e.code === code; }
}

// ---------------- mock backend ----------------
const calls = [];                                   // every call the flow made, with its arguments
const db = { users: [], folders: [], grants: [] };
let currentUserId = null;                           // like the Supabase client's own session
const mock = { acceptAnyAuth: false };

const sha256hex = async (s) => Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))).toString("hex");
const fakeSalt = async (email) =>                   // stable fake salt for unknown emails
  Buffer.from((await crypto.subtle.digest("SHA-256", new TextEncoder().encode("server-secret:" + email))).slice(0, 16)).toString("base64");

const backend = {
  async getAuthParams(email) {
    calls.push({ fn: "getAuthParams", args: { email } });
    const u = db.users.find((x) => x.email === email);
    return { kdfSalt: u ? u.kdfSalt : await fakeSalt(email), kdfIterations: u ? u.kdfIterations : 600000 };
  },
  async register(payload) {
    calls.push({ fn: "register", args: payload });
    if (db.users.find((u) => u.email === payload.email)) throw new ApiError(ERROR_CODES.EMAIL_TAKEN, "exists", 409);
    const { authSecret, ...rest } = payload;
    const user = { id: crypto.randomUUID(), ...rest, authHash: await sha256hex(authSecret) }; // server keeps only a hash
    db.users.push(user);
    currentUserId = user.id;
    return { userId: user.id, sessionToken: "token-" + user.id };
  },
  async login({ email, authSecret }) {
    calls.push({ fn: "login", args: { email, authSecret } });
    const u = db.users.find((x) => x.email === email);
    if (!u || !(mock.acceptAnyAuth || u.authHash === (await sha256hex(authSecret)))) {
      throw new ApiError(ERROR_CODES.INVALID_CREDENTIALS, "bad", 400);
    }
    currentUserId = u.id;
    return { userId: u.id, sessionToken: "token-" + u.id, kdfSalt: u.kdfSalt, wrappedPrivateKey: u.wrappedPrivateKey, displayName: u.displayName };
  },
  async logout() { calls.push({ fn: "logout", args: {} }); currentUserId = null; },
  async createFolder(args) {
    calls.push({ fn: "createFolder", args });
    const f = { id: crypto.randomUUID(), ownerId: currentUserId, ...args };
    db.folders.push(f);
    return { folderId: f.id };
  },
  async createGrant(args) {
    calls.push({ fn: "createGrant", args });
    db.grants.push({ id: crypto.randomUUID(), ...args });
    return { grantId: "g" };
  },
  async getVault() {
    calls.push({ fn: "getVault", args: {} });
    for (const f of db.folders) {
      const g = db.grants.find((x) => x.resourceId === f.id && x.granteeId === currentUserId);
      if (g && f.parentId === null) return { id: f.id, nameEnc: f.nameEnc, myGrant: { wrappedKey: g.wrappedKey, ephemeralPublicKey: g.ephemeralPublicKey } };
    }
    return null;
  },
};

configure({ backend });

// ---------------- tests ----------------
const EMAIL = "nathan@example.com";
const PW = "correct horse battery staple";

async function main() {
  console.log("1. register()");
  const user = await register(EMAIL, "Nathan", PW);
  check("returns a userId", typeof user.userId === "string" && user.userId.length > 0);
  check("user is logged in after registering", isLoggedIn());
  check("session holds an unwrapped private key and a vault folder key", !!getSession().privateKey && !!getSession().vaultFolderKey);

  console.log("\n2. What the backend was sent");
  const regArgs = calls.find((c) => c.fn === "register").args;
  check("register payload has exactly the 7 agreed fields",
    Object.keys(regArgs).sort().join(",") === "authSecret,displayName,email,kdfIterations,kdfSalt,publicKey,wrappedPrivateKey");
  const everything = JSON.stringify(calls);
  check("the password never appears in any call", !everything.includes(PW));
  check("_localOnly (keys) never appears in any call", !everything.includes("_localOnly") && !everything.includes("userKeyPair"));
  check("vault folder name is stored encrypted, not as 'Vault'",
    !Buffer.from(db.folders[0].nameEnc, "base64").toString("latin1").includes("Vault"));
  check("one OWNER grant for the vault folder was saved for this user",
    db.grants.length === 1 && db.grants[0].role === "OWNER" && db.grants[0].granteeId === user.userId);

  console.log("\n3. login() after logout recovers the same keys");
  const baseNonce = crypto.getRandomValues(new Uint8Array(8));
  const probe = new TextEncoder().encode("secret vault data");
  const probeCt = await encryptChunk(getSession().vaultFolderKey, baseNonce, "probe", 0, true, probe);
  await logout();
  check("logout clears the session", !isLoggedIn() && getSession() === null);
  check("logout also called the backend", calls.some((c) => c.fn === "logout"));

  const back = await login(EMAIL, PW);
  check("login with the right password works", isLoggedIn());
  check("login returns the display name from the backend", back.displayName === "Nathan");
  const probePt = await decryptChunk(getSession().vaultFolderKey, baseNonce, "probe", 0, true, probeCt);
  check("recovered vault key decrypts data encrypted before logout", Buffer.from(probePt).equals(Buffer.from(probe)));
  check("public key rebuilt from the private key matches the registered one", getSession().publicKey === regArgs.publicKey);
  check("login did not create a second vault folder", db.folders.length === 1);
  await logout();

  console.log("\n4. Failure cases");
  check("wrong password is refused with INVALID_CREDENTIALS", await rejectsWith(login(EMAIL, "wrong password"), ERROR_CODES.INVALID_CREDENTIALS));
  check("no session after a failed login", !isLoggedIn());
  check("unknown email gets the same INVALID_CREDENTIALS error", await rejectsWith(login("nobody@example.com", PW), ERROR_CODES.INVALID_CREDENTIALS));
  const s1 = await backend.getAuthParams("nobody@example.com"), s2 = await backend.getAuthParams("nobody@example.com");
  check("auth params give a stable fake salt for unknown emails", s1.kdfSalt === s2.kdfSalt);
  check("duplicate email is refused with EMAIL_TAKEN", await rejectsWith(register(EMAIL, "Again", "another password"), ERROR_CODES.EMAIL_TAKEN));
  await logout();

  console.log("\n5. Zero-trust check: a dishonest backend that accepts ANY login");
  mock.acceptAnyAuth = true;
  check("wrong password still fails, because the private key cannot be unwrapped",
    await rejectsWith(login(EMAIL, "wrong password"), ERROR_CODES.INVALID_CREDENTIALS));
  check("no session was created", !isLoggedIn());
  mock.acceptAnyAuth = false;

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => { console.error("Unexpected error:", e); process.exit(1); });
