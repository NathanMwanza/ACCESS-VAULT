// encoding.js
// Small helpers for converting between ArrayBuffer/Uint8Array and base64 strings,
// since the server (per Table 4.7) expects base64 strings in JSON, not raw bytes.

export function bufToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function base64ToBuf(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

export function concatBytes(...parts) {
  const total = parts.reduce((sum, p) => sum + p.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(new Uint8Array(p), offset);
    offset += p.byteLength;
  }
  return out;
}

export function uint32BE(n) {
  const buf = new ArrayBuffer(4);
  new DataView(buf).setUint32(0, n, false);
  return new Uint8Array(buf);
}

// Agreed blob format (Phase 2/3 decision 10): one base64 string = 12-byte IV followed by the ciphertext.
export function packBlob(iv, ciphertext) {
  return bufToBase64(concatBytes(iv, ciphertext));
}

export function unpackBlob(b64) {
  const all = new Uint8Array(base64ToBuf(b64));
  return { iv: all.slice(0, 12), ciphertext: all.slice(12) };
}
