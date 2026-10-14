// All binary values cross the API as base64 strings (API Agreements #2).

export function bytesToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function isBase64(value) {
  if (typeof value !== 'string' || value.length === 0) return false;
  if (value.length % 4 !== 0) return false;
  return /^[A-Za-z0-9+/]*={0,2}$/.test(value);
}

/** Decoded byte length of a base64 string, or -1 if it is not valid base64. */
export function base64ByteLength(value) {
  if (!isBase64(value)) return -1;
  try {
    return base64ToBytes(value).length;
  } catch {
    return -1;
  }
}
