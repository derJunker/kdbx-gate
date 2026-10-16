// Auth token derivation and verifier format (see docs/SPEC.md "Authentication scheme").
//   token    = Argon2id(password_utf8, salt, m, t, p, len = 32)  -> 64 lowercase hex chars
//   verifier = v1$argon2id$m=<m>,t=<t>,p=<p>$<salt base64>$<sha256(token) hex>
import { argon2id } from 'hash-wasm';
import { base64ToBytes, bytesToBase64, bytesToHex, hexToBytes, isBase64 } from './bytes.js';

export const DEFAULT_PARAMS = Object.freeze({ m: 65536, t: 3, p: 1 });
export const SALT_BYTES = 16;
export const TOKEN_RE = /^[0-9a-f]{64}$/;

// Sanity limits so a broken or hostile server cannot make the browser allocate absurd memory.
const LIMITS = { m: [8, 4 * 1024 * 1024], t: [1, 100], p: [1, 16] };

function checkInt(name, value) {
  const [min, max] = LIMITS[name];
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new RangeError(`Argon2 parameter ${name} out of range: ${value}`);
  }
}

/** Validates {m,t,p,salt[,kdf]} and returns a normalised copy. Throws on bad input. */
export function checkParams(params) {
  if (!params || typeof params !== 'object') throw new TypeError('missing KDF params');
  if (params.kdf !== undefined && params.kdf !== 'argon2id') {
    throw new TypeError(`unsupported KDF: ${params.kdf}`);
  }
  const m = Number(params.m);
  const t = Number(params.t);
  const p = Number(params.p);
  checkInt('m', m);
  checkInt('t', t);
  checkInt('p', p);
  if (m < 8 * p) throw new RangeError('Argon2 memory must be at least 8 * p KiB');
  if (typeof params.salt !== 'string' || !isBase64(params.salt)) {
    throw new TypeError('salt must be standard padded base64');
  }
  const saltLen = base64ToBytes(params.salt).length;
  if (saltLen < 8 || saltLen > 64) throw new RangeError('salt must be 8..64 bytes');
  return { kdf: 'argon2id', m, t, p, salt: params.salt };
}

/** Derives the 64-char lowercase hex gate token from the master password. */
export async function deriveAuthToken(password, params) {
  if (typeof password !== 'string') throw new TypeError('password must be a string');
  const { m, t, p, salt } = checkParams(params);
  const hex = await argon2id({
    password: new TextEncoder().encode(password),
    salt: base64ToBytes(salt),
    iterations: t,
    memorySize: m, // KiB
    parallelism: p,
    hashLength: 32,
    outputType: 'hex',
  });
  return hex.toLowerCase();
}

export async function sha256Hex(bytes) {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return bytesToHex(new Uint8Array(digest));
}

export function randomSalt(len = SALT_BYTES) {
  const salt = new Uint8Array(len);
  globalThis.crypto.getRandomValues(salt);
  return bytesToBase64(salt);
}

/** Builds the verifier string stored on the server from a token (hex) and its params. */
export async function buildVerifier(tokenHex, params) {
  if (typeof tokenHex !== 'string' || !TOKEN_RE.test(tokenHex)) {
    throw new TypeError('token must be 64 lowercase hex chars');
  }
  const { m, t, p, salt } = checkParams(params);
  const hash = await sha256Hex(hexToBytes(tokenHex));
  return `v1$argon2id$m=${m},t=${t},p=${p}$${salt}$${hash}`;
}

const VERIFIER_RE = /^v1\$argon2id\$m=([1-9][0-9]*),t=([1-9][0-9]*),p=([1-9][0-9]*)\$([A-Za-z0-9+/=]+)\$([0-9a-f]{64})$/;

/** Parses a verifier string. Returns {version, kdf, m, t, p, salt, hash}; throws on malformed input. */
export function parseVerifier(str) {
  if (typeof str !== 'string') throw new TypeError('verifier must be a string');
  const match = VERIFIER_RE.exec(str);
  if (!match) throw new TypeError('malformed verifier');
  const params = checkParams({ m: +match[1], t: +match[2], p: +match[3], salt: match[4] });
  return { version: 'v1', ...params, hash: match[5] };
}

/** True if SHA-256(token) matches the verifier (client-side mirror of the server check). */
export async function checkTokenAgainstVerifier(tokenHex, verifier) {
  const parsed = parseVerifier(verifier);
  if (!TOKEN_RE.test(tokenHex)) return false;
  return (await sha256Hex(hexToBytes(tokenHex))) === parsed.hash;
}
