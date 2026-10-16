// Small byte helpers shared by browser code and tests (no Node APIs).

const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** Standard, padded base64 (RFC 4648 section 4), non-empty. */
export function isBase64(str) {
  return typeof str === 'string' && str.length > 0 && B64_RE.test(str);
}

export function base64ToBytes(str) {
  if (!isBase64(str)) throw new TypeError('invalid base64');
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToBase64(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = '';
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin);
}

export function bytesToHex(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let hex = '';
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, '0');
  return hex;
}

export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new TypeError('invalid hex');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

/** Returns a standalone ArrayBuffer for any ArrayBuffer / typed array / Node Buffer. */
export function toArrayBuffer(data) {
  if (data instanceof ArrayBuffer) return data;
  if (ArrayBuffer.isView(data)) {
    return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
  }
  throw new TypeError('expected binary data');
}

/** KDBX file signature 03 D9 A2 9A 67 FB 4B B5. */
export function hasKdbxSignature(data) {
  const b = new Uint8Array(toArrayBuffer(data), 0, Math.min(8, data.byteLength));
  const sig = [0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5];
  return b.length === 8 && sig.every((v, i) => b[i] === v);
}
