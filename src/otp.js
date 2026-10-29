// 2FA (OTP) tokens: reading authenticator exports and mapping them to KeePass fields (no DOM, no Node APIs).
//
// Inputs: 2FAS backups (.2fas JSON, optionally password-encrypted) and otpauth:// links.
// A token is {type: 'totp'|'hotp'|'steam', title, issuer, account, secret (base32), algorithm, digits,
// period (totp/steam), counter (hotp)}.
import { base64ToBytes, hexToBytes } from './bytes.js';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const ALGORITHMS = ['SHA1', 'SHA256', 'SHA512', 'SHA224', 'SHA384', 'MD5'];
// KeePass 2's TimeOtp-Algorithm values; other algorithms only go into the otp link.
const KEEPASS_ALGORITHMS = { SHA1: 'HMAC-SHA-1', SHA256: 'HMAC-SHA-256', SHA512: 'HMAC-SHA-512' };

/** RFC 4648 base32, upper case, no padding. */
export function base32Encode(bytes) {
  let out = '';
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = ((value << 8) | b) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

/** Decodes base32, ignoring case, spaces, dashes and padding. */
export function base32Decode(str) {
  const clean = String(str ?? '').replace(/[\s=-]+/g, '').toUpperCase();
  if (/[^A-Z2-7]/.test(clean)) throw new Error('The secret is not valid base32.');
  const out = [];
  let bits = 0;
  let value = 0;
  for (const c of clean) {
    value = ((value << 5) | B32.indexOf(c)) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

function optionalNumber(value, fallback) {
  return value === undefined || value === null || value === '' ? fallback : Number(value);
}

/** Validates and normalises a token; the secret is re-encoded so equal keys compare equal. */
export function makeToken({ type, title, issuer, account, secret, algorithm, digits, period, counter }) {
  const kind = String(type || 'totp').toLowerCase();
  if (!['totp', 'hotp', 'steam'].includes(kind)) throw new Error(`Unsupported OTP type "${type}".`);
  const alg = String(algorithm || 'SHA1').toUpperCase().replace(/^HMAC-?/, '').replace(/-/g, '');
  if (!ALGORITHMS.includes(alg)) throw new Error(`Unsupported OTP algorithm "${algorithm}".`);
  const bytes = base32Decode(secret);
  if (!bytes.length) throw new Error('The secret is empty.');
  const token = {
    type: kind,
    title: String(title || issuer || account || '').trim(),
    issuer: String(issuer || '').trim(),
    account: String(account || '').trim(),
    secret: base32Encode(bytes),
    algorithm: alg,
    digits: kind === 'steam' ? 5 : optionalNumber(digits, 6),
  };
  if (!Number.isInteger(token.digits) || token.digits < 4 || token.digits > 10) throw new Error(`Invalid digit count "${digits}".`);
  if (kind === 'hotp') {
    token.counter = optionalNumber(counter, 0);
    if (!Number.isSafeInteger(token.counter) || token.counter < 0) throw new Error(`Invalid counter "${counter}".`);
  } else {
    token.period = optionalNumber(period, 30);
    if (!Number.isInteger(token.period) || token.period < 1) throw new Error(`Invalid period "${period}".`);
  }
  return token;
}

function decodeComponent(str) {
  try {
    return decodeURIComponent(str);
  } catch {
    return str;
  }
}

/**
 * "Issuer:Account" -> [issuer, account]; without a colon the whole label is the account.
 * A known issuer is matched as a whole, since it may contain a colon itself.
 */
function splitLabel(label, issuer = '') {
  if (issuer && label.startsWith(`${issuer}:`)) return [issuer, label.slice(issuer.length + 1)];
  const i = label.indexOf(':');
  return i < 0 ? ['', label] : [label.slice(0, i), label.slice(i + 1)];
}

/** Parses an otpauth://totp|hotp|steam/Label?secret=… link (Key URI Format; encoder=steam as KeePassXC writes it). */
export function parseOtpauthUri(uri) {
  const m = /^otpauth:\/\/([a-z]+)\/([^?#]*)(?:\?([^#]*))?/i.exec(String(uri ?? '').trim());
  if (!m) throw new Error('Not an otpauth:// link.');
  const params = new URLSearchParams(m[3] || '');
  if (!params.get('secret')) throw new Error('The otpauth:// link has no secret.');
  const issuer = params.get('issuer') || '';
  const [prefix, account] = splitLabel(decodeComponent(m[2]), issuer);
  const steam = (params.get('encoder') || '').toLowerCase() === 'steam';
  return makeToken({
    type: steam ? 'steam' : m[1],
    issuer: issuer || prefix,
    account,
    secret: params.get('secret'),
    algorithm: params.get('algorithm'),
    digits: params.get('digits'),
    period: params.get('period'),
    counter: params.get('counter'),
  });
}

/**
 * Finds every otpauth:// link in a text (pasted, or a .txt export). Links run to the end of the line or to the
 * next link, so labels with spaces survive. Throws on the first invalid link.
 */
export function parseLinks(text) {
  const tokens = [];
  for (const line of String(text ?? '').split(/\r?\n/)) {
    for (const piece of line.split(/(?=otpauth:\/\/)/i)) {
      const link = piece.trim();
      if (/^otpauth:\/\//i.test(link)) tokens.push(parseOtpauthUri(link));
    }
  }
  if (!tokens.length) throw new Error('No otpauth:// link found.');
  return tokens;
}

// ------------------------------------------------------------ 2FAS backups

/** True for a parsed 2FAS backup file. */
export function isTwoFasBackup(json) {
  return Boolean(json) && typeof json === 'object' && Array.isArray(json.services) && 'schemaVersion' in json;
}

/** True for Ente Auth's encrypted export, which is not supported (its plain text export is). */
export function isEnteEncryptedExport(json) {
  return Boolean(json) && typeof json === 'object' && 'encryptedData' in json && 'kdfParams' in json;
}

/** True if the backup's services are encrypted with a backup password. */
export function isEncryptedTwoFas(json) {
  return typeof json.servicesEncrypted === 'string' && json.servicesEncrypted !== '';
}

/** "base64(ciphertext+tag):base64(salt):base64(iv)", AES-256-GCM with a PBKDF2-SHA256 (10000 rounds) key. */
async function decryptTwoFas(field, password) {
  const parts = field.split(':');
  let data;
  let salt;
  let iv;
  try {
    if (parts.length !== 3) throw new Error();
    [data, salt, iv] = parts.map(base64ToBytes);
  } catch {
    throw new Error('The 2FAS backup is damaged.');
  }
  const { subtle } = globalThis.crypto;
  const base = await subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 10000 },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );
  try {
    return new TextDecoder().decode(await subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, data));
  } catch {
    throw new Error('Wrong password for this 2FAS backup.');
  }
}

function twoFasService(service) {
  const otp = service.otp || {};
  let { issuer = '', account = '' } = otp;
  if (!issuer && !account && otp.label) [issuer, account] = splitLabel(otp.label);
  return makeToken({
    type: otp.tokenType,
    title: service.name,
    issuer: issuer || service.name,
    account,
    secret: service.secret,
    algorithm: otp.algorithm,
    digits: otp.digits,
    period: otp.period,
    counter: otp.counter,
  });
}

/** Tokens of a parsed 2FAS backup; `password` is needed if isEncryptedTwoFas(json). */
export async function readTwoFasBackup(json, password = '') {
  let services = json.services;
  if (isEncryptedTwoFas(json)) {
    if (!password) throw new Error('This 2FAS backup is encrypted. Enter its password.');
    services = JSON.parse(await decryptTwoFas(json.servicesEncrypted, password));
    if (!Array.isArray(services)) throw new Error('The 2FAS backup is damaged.');
  }
  return services.map(twoFasService);
}

// ------------------------------------------------------------ KeePass fields

/** The token as an otpauth:// link (also what the restore QR code shows). */
export function toOtpauthUri(token) {
  const enc = encodeURIComponent;
  const account = token.account || token.title || token.issuer;
  const label = token.issuer && token.account ? `${enc(token.issuer)}:${enc(account)}` : enc(account);
  const params = [`secret=${token.secret}`];
  if (token.issuer) params.push(`issuer=${enc(token.issuer)}`);
  params.push(`algorithm=${token.algorithm}`, `digits=${token.digits}`);
  params.push(token.type === 'hotp' ? `counter=${token.counter}` : `period=${token.period}`);
  if (token.type === 'steam') params.push('encoder=steam');
  return `otpauth://${token.type === 'hotp' ? 'hotp' : 'totp'}/${label}?${params.join('&')}`;
}

/**
 * Custom fields for an entry holding the token, in vault.createEntry's `custom` format: `otp` (KeePassXC,
 * KeePassDX, Strongbox) plus KeePass 2's TimeOtp-/HmacOtp- fields when KeePass 2 can generate the code.
 */
export function otpFields(token) {
  const secret = (value) => ({ value, protected: true });
  const plain = (value) => ({ value: String(value), protected: false });
  const fields = { otp: secret(toOtpauthUri(token)) };
  if (token.type === 'totp' && KEEPASS_ALGORITHMS[token.algorithm] && token.digits <= 8) {
    fields['TimeOtp-Secret-Base32'] = secret(token.secret);
    if (token.digits !== 6) fields['TimeOtp-Length'] = plain(token.digits);
    if (token.period !== 30) fields['TimeOtp-Period'] = plain(token.period);
    if (token.algorithm !== 'SHA1') fields['TimeOtp-Algorithm'] = plain(KEEPASS_ALGORITHMS[token.algorithm]);
  } else if (token.type === 'hotp' && token.algorithm === 'SHA1' && token.digits === 6) {
    fields['HmacOtp-Secret-Base32'] = secret(token.secret);
    fields['HmacOtp-Counter'] = plain(token.counter);
  }
  return fields;
}

/** KeePass 2 keeps the secret in one of four encodings: <prefix>Secret (UTF-8), -Hex, -Base32 or -Base64. */
function keepassSecret(fields, prefix) {
  const get = (suffix) => (fields.get(`${prefix}Secret${suffix}`) || '').trim();
  if (get('')) return base32Encode(new TextEncoder().encode(get('')));
  if (get('-Hex')) return base32Encode(hexToBytes(get('-Hex').replace(/\s+/g, '')));
  if (get('-Base32')) return get('-Base32');
  if (get('-Base64')) return base32Encode(base64ToBytes(get('-Base64')));
  return '';
}

/**
 * The token stored in an entry ({title, username, custom: [{name, value}]} as vault.getEntry returns it),
 * from its otp link or its KeePass 2 fields; null if it has none or it is invalid.
 */
export function tokenFromEntry(entry) {
  const fields = new Map(entry.custom.map((f) => [f.name, f.value]));
  const link = (fields.get('otp') || '').trim();
  if (link) {
    try {
      return parseOtpauthUri(link);
    } catch {
      // not a link (or a broken one): try the KeePass 2 fields
    }
  }
  const names = { title: entry.title, issuer: entry.title, account: entry.username };
  try {
    const totp = keepassSecret(fields, 'TimeOtp-');
    if (totp) {
      return makeToken({
        ...names,
        type: 'totp',
        secret: totp,
        digits: fields.get('TimeOtp-Length'),
        period: fields.get('TimeOtp-Period'),
        algorithm: fields.get('TimeOtp-Algorithm'),
      });
    }
    const hotp = keepassSecret(fields, 'HmacOtp-');
    if (hotp) return makeToken({ ...names, type: 'hotp', secret: hotp, counter: fields.get('HmacOtp-Counter') });
  } catch {
    // invalid secret or settings
  }
  return null;
}
