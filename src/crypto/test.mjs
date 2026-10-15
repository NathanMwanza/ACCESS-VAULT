// test.mjs — run with: node test.mjs
// Exercises setupAccount, login round-trip, chunk encrypt/decrypt (incl. tamper
// detection), and the full share/unwrap flow between two "users".

import { setupAccount, deriveKeys, unwrapPrivateKey, wrapToUser, unwrapFromUser, wrapKey, unwrapKey } from "./keyManager.js";
import { generateAesKey, encryptChunk, decryptChunk } from "./cryptoEngine.js";
import { base64ToBuf } from "./encoding.js";

let passed = 0, failed = 0;
function check(label, cond) {
  if (cond) { console.log(`  PASS  ${label}`); passed++; }
  else { console.log(`  FAIL  ${label}`); failed++; }
}

async function main() {
  console.log("1. setupAccount() — registration");
  const reg = await setupAccount("correct horse battery staple");
  check("returns base64 kdfSalt", typeof reg.kdfSalt === "string" && reg.kdfSalt.length > 0);
  check("returns base64 authSecret", typeof reg.authSecret === "string");
  check("returns base64 publicKey", typeof reg.publicKey === "string");
  check("returns base64 wrappedPrivateKey", typeof reg.wrappedPrivateKey === "string");
  check("kdfIterations is 600000 per Table 4.4", reg.kdfIterations === 600000);
  // Simulate: these 5 fields are exactly what gets POSTed to /auth/register
  const serverRow = {
    kdf_salt: reg.kdfSalt,
    kdf_iterations: reg.kdfIterations,
    public_key: reg.publicKey,
    wrapped_private_key: reg.wrappedPrivateKey,
    // auth_secret would be hashed server-side before storage, per 4.4.1.3 step 2
  };

  console.log("\n2. Login — correct password re-derives the same private key");
  const saltBytes = new Uint8Array(base64ToBuf(serverRow.kdf_salt));
  const { kek: kekLogin } = await deriveKeys("correct horse battery staple", saltBytes);
  const recoveredPrivateKey = await unwrapPrivateKey(serverRow.wrapped_private_key, kekLogin);
  check("private key recovered without throwing", !!recoveredPrivateKey);

  console.log("\n3. Login — wrong password must fail to unwrap (not silently succeed)");
  const { kek: kekWrong } = await deriveKeys("totally wrong password", saltBytes);
  let wrongPasswordRejected = false;
  try {
    await unwrapPrivateKey(serverRow.wrapped_private_key, kekWrong);
  } catch (e) {
    wrongPasswordRejected = true;
  }
  check("wrong password throws instead of unwrapping", wrongPasswordRejected);

  console.log("\n4. Chunk encrypt/decrypt round-trip (Algorithm 4.2)");
  const fileKey = await generateAesKey();
  const baseNonce = crypto.getRandomValues(new Uint8Array(8));
  const fileId = "file-123";
  const plaintext = new TextEncoder().encode("This is a test chunk of a confidential document.");

  const ciphertext = await encryptChunk(fileKey, baseNonce, fileId, 0, true, plaintext);
  check("ciphertext differs from plaintext", Buffer.from(ciphertext).toString("hex") !== Buffer.from(plaintext).toString("hex"));

  const decrypted = await decryptChunk(fileKey, baseNonce, fileId, 0, true, ciphertext);
  check("decrypted chunk matches original plaintext", Buffer.from(decrypted).equals(Buffer.from(plaintext)));

  console.log("\n5. Tamper detection — a flipped ciphertext byte must be rejected");
  const tampered = new Uint8Array(ciphertext);
  tampered[0] ^= 0xff; // flip a bit
  let tamperDetected = false;
  try {
    await decryptChunk(fileKey, baseNonce, fileId, 0, true, tampered);
  } catch (e) {
    tamperDetected = true;
  }
  check("tampered chunk throws on decrypt (GCM tag fails)", tamperDetected);

  console.log("\n6. Wrong chunk index (simulating reordering) must be rejected");
  let reorderDetected = false;
  try {
    await decryptChunk(fileKey, baseNonce, fileId, 1 /* wrong index */, true, ciphertext);
  } catch (e) {
    reorderDetected = true;
  }
  check("decrypting with the wrong index fails (AAD mismatch)", reorderDetected);

  console.log("\n7. Sharing flow (Algorithm 4.3) — owner shares a folder key with a recipient");
  const ownerFolderKey = await generateAesKey();
  const recipient = await setupAccount("recipient's password");
  const recipientPublicKeyRaw = base64ToBuf(recipient.publicKey);

  const grant = await wrapToUser(ownerFolderKey, recipientPublicKeyRaw);
  check("grant has wrappedKey", typeof grant.wrappedKey === "string");
  check("grant has ephemeralPublicKey", typeof grant.ephemeralPublicKey === "string");

  const recipientPrivateKey = recipient._localOnly.userKeyPair.privateKey;
  const recoveredFolderKey = await unwrapFromUser(grant.wrappedKey, grant.ephemeralPublicKey, recipientPrivateKey);

  // Prove the recovered key actually decrypts something encrypted with the original
  const sharedPlaintext = new TextEncoder().encode("shared folder content");
  const sharedCipher = await encryptChunk(ownerFolderKey, baseNonce, "shared-file", 0, true, sharedPlaintext);
  const sharedDecrypted = await decryptChunk(recoveredFolderKey, baseNonce, "shared-file", 0, true, sharedCipher);
  check("recipient's unwrapped key decrypts owner-encrypted content", Buffer.from(sharedDecrypted).equals(Buffer.from(sharedPlaintext)));


  console.log("\n8. File key wrapped under a folder key (used by every upload)");
  const folderKey2 = await generateAesKey();
  const fileKey2 = await generateAesKey();
  const { iv: wIv, wrapped: wBytes } = await wrapKey(fileKey2, folderKey2);
  const fileKeyBack = await unwrapKey(wBytes, wIv, folderKey2, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
  const probe = new TextEncoder().encode("probe");
  const probeCt = await encryptChunk(fileKey2, baseNonce, "f-wrap", 0, true, probe);
  const probePt = await decryptChunk(fileKeyBack, baseNonce, "f-wrap", 0, true, probeCt);
  check("unwrapped file key decrypts data encrypted with the original", Buffer.from(probePt).equals(Buffer.from(probe)));
  let wrongFolderRejected = false;
  try { await unwrapKey(wBytes, wIv, await generateAesKey(), { name: "AES-GCM" }, true, ["encrypt", "decrypt"]); }
  catch { wrongFolderRejected = true; }
  check("unwrapping with the wrong folder key is rejected", wrongFolderRejected);

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error("Unexpected error:", e);
  process.exit(1);
});
