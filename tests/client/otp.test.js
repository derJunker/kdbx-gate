import test from 'node:test';
import assert from 'node:assert/strict';
import { encodeQR } from 'qr';
import { decodeQR } from 'qr/decode.js';
import {
  base32Encode, base32Decode, parseOtpauthUri, parseLinks, isTwoFasBackup, isEncryptedTwoFas, isEnteEncryptedExport,
  readTwoFasBackup, toOtpauthUri, otpFields, tokenFromEntry,
} from '../../src/otp.js';
import { bytesToBase64 } from '../../src/bytes.js';
import { Vault } from '../../src/vault.js';
import { makeDb, PASSWORD, kdbxweb } from './helpers.mjs';

// ------------------------------------------------------------ fixtures

/** Encrypts like 2FAS (BackupCipherImpl): base64(ct+tag):base64(salt):base64(iv), PBKDF2-SHA256 10000, AES-256-GCM. */
async function twoFasEncrypt(plaintext, password, salt) {
  const { subtle } = globalThis.crypto;
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const base = await subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 10000 },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
  return [ct, salt, iv].map((b) => bytesToBase64(new Uint8Array(b))).join(':');
}

// Shape of a current Android export (schema 4), fake secrets; plus a schema 1 service (label only, no settings).
const TWOFAS_SERVICES = [
  {
    name: 'GitHub', secret: 'JBSWY3DPEHPK3PXP', updatedAt: 1760900000000,
    otp: { link: 'otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub', label: 'alice', account: 'alice', issuer: 'GitHub', digits: 6, period: 30, algorithm: 'SHA1', tokenType: 'TOTP', source: 'Link' },
    order: { position: 0 }, groupId: '5f0c6e2e-8d1b-4c1e-9a77-0123456789ab',
  },
  {
    name: 'My VPN', secret: 'krsxg5ctmvrxezlu', updatedAt: 1760900001000,
    otp: { account: 'bob', digits: 8, algorithm: 'SHA256', counter: 42, tokenType: 'HOTP', source: 'Manual' },
    order: { position: 1 },
  },
  {
    name: 'Steam', secret: 'GEZDGNBVGY3TQOJQ', updatedAt: 1760900002000,
    otp: { account: 'carol', issuer: 'Steam', digits: 5, period: 30, algorithm: 'SHA1', tokenType: 'STEAM', source: 'Link' },
    order: { position: 2 },
  },
  { name: 'Deno', secret: '4SJHB4GSD43FZBAI7C2HLRJGPQ', type: 'Unknown', otp: { label: 'Deno:Mason' }, order: { position: 3 } },
];
const TWOFAS_TOKENS = [
  { type: 'totp', title: 'GitHub', issuer: 'GitHub', account: 'alice', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 },
  { type: 'hotp', title: 'My VPN', issuer: 'My VPN', account: 'bob', secret: 'KRSXG5CTMVRXEZLU', algorithm: 'SHA256', digits: 8, counter: 42 },
  { type: 'steam', title: 'Steam', issuer: 'Steam', account: 'carol', secret: 'GEZDGNBVGY3TQOJQ', algorithm: 'SHA1', digits: 5, period: 30 },
  { type: 'totp', title: 'Deno', issuer: 'Deno', account: 'Mason', secret: '4SJHB4GSD43FZBAI7C2HLRJGPQ', algorithm: 'SHA1', digits: 6, period: 30 },
];
const twoFasFile = (extra) => ({
  services: TWOFAS_SERVICES,
  groups: [{ id: '5f0c6e2e-8d1b-4c1e-9a77-0123456789ab', name: 'Work', isExpanded: true }],
  updatedAt: 1760900005000, schemaVersion: 4, appVersionCode: 5000041, appVersionName: '6.1.0', appOrigin: 'android',
  ...extra,
});

// ------------------------------------------------------------ base32

test('base32 matches the RFC 4648 vectors and decodes leniently', () => {
  const vectors = { '': '', f: 'MY', fo: 'MZXQ', foo: 'MZXW6', foob: 'MZXW6YQ', fooba: 'MZXW6YTB', foobar: 'MZXW6YTBOI' };
  for (const [plain, encoded] of Object.entries(vectors)) {
    assert.equal(base32Encode(new TextEncoder().encode(plain)), encoded);
    assert.equal(new TextDecoder().decode(base32Decode(encoded)), plain);
  }
  assert.equal(new TextDecoder().decode(base32Decode('mzxw 6ytb-oi======')), 'foobar');
  assert.throws(() => base32Decode('MZXW1'), /not valid base32/);
});

// ------------------------------------------------------------ otpauth:// links

test('otpauth:// links: labels, issuer, settings, steam', () => {
  assert.deepEqual(
    parseOtpauthUri('otpauth://totp/Air%20Canada:Benjamin?secret=kuvj jom7 53ih tnds&issuer=Air+Canada&algorithm=sha256&digits=8&period=60'),
    { type: 'totp', title: 'Air Canada', issuer: 'Air Canada', account: 'Benjamin', secret: 'KUVJJOM753IHTNDS', algorithm: 'SHA256', digits: 8, period: 60 },
  );
  // the issuer parameter wins over the label prefix
  const google = parseOtpauthUri('otpauth://totp/Google:alice@gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=Google%20Inc');
  assert.deepEqual([google.issuer, google.account, google.title], ['Google Inc', 'alice@gmail.com', 'Google Inc']);
  const bare = parseOtpauthUri('otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP');
  assert.deepEqual([bare.issuer, bare.account, bare.title, bare.digits, bare.period], ['', 'alice', 'alice', 6, 30]);
  const hotp = parseOtpauthUri('otpauth://hotp/X:y?secret=JBSWY3DPEHPK3PXP');
  assert.deepEqual([hotp.type, hotp.counter, hotp.period], ['hotp', 0, undefined]);
  for (const uri of [
    'otpauth://steam/Steam:carol?secret=GEZDGNBVGY3TQOJQ&issuer=Steam', // 2FAS (Android)
    'otpauth://totp/Steam:carol?secret=GEZDGNBVGY3TQOJQ&issuer=Steam&encoder=steam', // KeePassXC
  ]) {
    const t = parseOtpauthUri(uri);
    assert.deepEqual([t.type, t.digits, t.period], ['steam', 5, 30]);
  }

  assert.throws(() => parseOtpauthUri('otpauth://totp/x?issuer=y'), /no secret/);
  assert.throws(() => parseOtpauthUri('otpauth://totp/x?secret=0189'), /not valid base32/);
  assert.throws(() => parseOtpauthUri('otpauth://xotp/x?secret=JBSWY3DP'), /Unsupported OTP type/);
  assert.throws(() => parseOtpauthUri('otpauth://totp/x?secret=JBSWY3DP&digits=12'), /Invalid digit count/);
  assert.throws(() => parseOtpauthUri('otpauth://totp/x?secret=JBSWY3DP&period=0'), /Invalid period/);
  assert.throws(() => parseOtpauthUri('otpauth://totp/x?secret=JBSWY3DP&algorithm=SHA3'), /Unsupported OTP algorithm/);
  assert.throws(() => parseOtpauthUri('https://example.com'), /Not an otpauth/);
});

test('parseLinks finds every link in pasted text or an export file', () => {
  const text = [
    'Exported by 2FAS',
    'otpauth://totp/Air Canada:Ben?secret=JBSWY3DPEHPK3PXP&issuer=Air Canada', // a reader decoded the spaces
    '  otpauth://totp/A:a?secret=MZXW6YTBOI otpauth://hotp/B:b?secret=MZXW6&counter=3\r',
    '',
  ].join('\n');
  assert.deepEqual(parseLinks(text).map((t) => `${t.issuer}/${t.account}`), ['Air Canada/Ben', 'A/a', 'B/b']);
  assert.throws(() => parseLinks('nothing here'), /No otpauth/);
  assert.throws(() => parseLinks('otpauth://totp/A:a?secret=MZXW6YTBOI\notpauth://totp/B?secret=1'), /not valid base32/);
});

test('toOtpauthUri round-trips through parseOtpauthUri', () => {
  const tokens = [
    ...TWOFAS_TOKENS,
    { type: 'totp', title: 'A&B: Co', issuer: 'A&B: Co', account: 'a b+c@x?y=z', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA512', digits: 7, period: 45 },
    { type: 'totp', title: 'solo', issuer: '', account: 'solo', secret: 'MZXW6YTBOI', algorithm: 'SHA1', digits: 6, period: 30 },
  ];
  for (const token of tokens) assert.deepEqual(parseOtpauthUri(toOtpauthUri(token)), token);
});

// ------------------------------------------------------------ 2FAS

test('2FAS: plain backup', async () => {
  const file = JSON.parse(JSON.stringify(twoFasFile()));
  assert.equal(isTwoFasBackup(file), true);
  assert.equal(isEncryptedTwoFas(file), false);
  assert.equal(isTwoFasBackup({ services: [] }), false);
  assert.equal(isTwoFasBackup(null), false);
  assert.equal(isEnteEncryptedExport(file), false);
  assert.equal(isEnteEncryptedExport({ version: 1, kdfParams: {}, encryptedData: 'x', encryptionNonce: 'y' }), true);
  assert.deepEqual(await readTwoFasBackup(file), TWOFAS_TOKENS);
});

test('2FAS: password-encrypted backup', async () => {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(256)); // Android: 256 bytes, iOS: 32
  const file = twoFasFile({
    services: [],
    servicesEncrypted: await twoFasEncrypt(JSON.stringify(TWOFAS_SERVICES), 'backup pässword', salt),
    reference: await twoFasEncrypt('x'.repeat(256), 'backup pässword', salt),
  });
  // iOS escapes "/" in its JSON
  const parsed = JSON.parse(JSON.stringify(file).replace(/\//g, '\\/'));
  assert.equal(isTwoFasBackup(parsed), true);
  assert.equal(isEncryptedTwoFas(parsed), true);
  assert.deepEqual(await readTwoFasBackup(parsed, 'backup pässword'), TWOFAS_TOKENS);
  await assert.rejects(readTwoFasBackup(parsed, 'wrong'), /Wrong password/);
  await assert.rejects(readTwoFasBackup(parsed), /encrypted/);
  const parts = parsed.servicesEncrypted.split(':');
  await assert.rejects(readTwoFasBackup({ ...parsed, servicesEncrypted: parts.slice(0, 2).join(':') }, 'x'), /damaged/);
  await assert.rejects(readTwoFasBackup({ ...parsed, servicesEncrypted: `${parts[0]}:${parts[1]}:no-base64` }, 'x'), /damaged/);
});

// ------------------------------------------------------------ KeePass fields

const totp = (extra = {}) => ({ type: 'totp', title: 'T', issuer: 'T', account: 'a', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30, ...extra });
const hotp = (extra = {}) => ({ type: 'hotp', title: 'H', issuer: 'H', account: 'b', secret: 'MZXW6YTBOI', algorithm: 'SHA1', digits: 6, counter: 5, ...extra });
const protectedValue = (value) => ({ value, protected: true });
const plainValue = (value) => ({ value, protected: false });

test('otpFields: otp link plus KeePass 2 fields where KeePass 2 can generate the code', () => {
  assert.deepEqual(otpFields(totp()), {
    otp: protectedValue(toOtpauthUri(totp())),
    'TimeOtp-Secret-Base32': protectedValue('JBSWY3DPEHPK3PXP'),
  });
  const custom = totp({ algorithm: 'SHA256', digits: 8, period: 60 });
  assert.deepEqual(otpFields(custom), {
    otp: protectedValue(toOtpauthUri(custom)),
    'TimeOtp-Secret-Base32': protectedValue('JBSWY3DPEHPK3PXP'),
    'TimeOtp-Length': plainValue('8'),
    'TimeOtp-Period': plainValue('60'),
    'TimeOtp-Algorithm': plainValue('HMAC-SHA-256'),
  });
  assert.equal(otpFields(totp({ algorithm: 'SHA512' }))['TimeOtp-Algorithm'].value, 'HMAC-SHA-512');
  assert.deepEqual(otpFields(hotp()), {
    otp: protectedValue(toOtpauthUri(hotp())),
    'HmacOtp-Secret-Base32': protectedValue('MZXW6YTBOI'),
    'HmacOtp-Counter': plainValue('5'),
  });
  // KeePass 2 cannot generate these: only the link is stored
  for (const token of [totp({ algorithm: 'SHA384' }), totp({ digits: 10 }), TWOFAS_TOKENS[2], hotp({ digits: 8 }), hotp({ algorithm: 'SHA256' })]) {
    assert.deepEqual(Object.keys(otpFields(token)), ['otp'], JSON.stringify(token));
  }
});

test('tokenFromEntry reads the otp link or the KeePass 2 fields', () => {
  const entry = (custom) => ({ title: 'Site', username: 'me', custom: Object.entries(custom).map(([name, value]) => ({ name, value })) });
  const site = (extra) => totp({ title: 'Site', issuer: 'Site', account: 'me', ...extra });
  const rfc = '12345678901234567890'; // RFC 6238 test key
  const rfcB32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

  assert.deepEqual(tokenFromEntry(entry({ otp: toOtpauthUri(TWOFAS_TOKENS[1]) })), TWOFAS_TOKENS[1]);
  assert.deepEqual(
    tokenFromEntry(entry({ 'TimeOtp-Secret-Base32': 'jbsw y3dp ehpk 3pxp', 'TimeOtp-Length': '8', 'TimeOtp-Period': '60', 'TimeOtp-Algorithm': 'HMAC-SHA-512' })),
    site({ digits: 8, period: 60, algorithm: 'SHA512' }),
  );
  for (const custom of [
    { 'TimeOtp-Secret': rfc },
    { 'TimeOtp-Secret-Hex': '3132333435363738393031323334353637383930' },
    { 'TimeOtp-Secret-Base64': 'MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=' },
    { otp: 'not a link', 'TimeOtp-Secret-Base32': rfcB32 }, // a broken link falls back to the KeePass 2 fields
  ]) {
    assert.deepEqual(tokenFromEntry(entry(custom)), site({ secret: rfcB32 }), JSON.stringify(custom));
  }
  assert.deepEqual(
    tokenFromEntry(entry({ 'HmacOtp-Secret-Base32': 'MZXW6YTBOI', 'HmacOtp-Counter': '12' })),
    hotp({ title: 'Site', issuer: 'Site', account: 'me', counter: 12 }),
  );
  assert.equal(tokenFromEntry(entry({})), null);
  assert.equal(tokenFromEntry(entry({ PIN: '1234' })), null);
  assert.equal(tokenFromEntry(entry({ 'TimeOtp-Secret-Hex': 'xyz' })), null);
  assert.equal(tokenFromEntry(entry({ 'TimeOtp-Secret-Base32': rfcB32, 'TimeOtp-Period': 'abc' })), null);
});

test('imported entries are saved with protected fields and read back as the same tokens', async () => {
  const vault = await Vault.open(await makeDb(), PASSWORD);
  const groupId = vault.createGroup(vault.rootGroupId(), '2FA');
  const tokens = [...TWOFAS_TOKENS, ...parseLinks('otpauth://hotp/ACME:bob?secret=GEZDGNBV&issuer=ACME&counter=7\notpauth://totp/x?secret=MZXW6YTBOI&digits=8')];
  const ids = tokens.map((t) => vault.createEntry(groupId, { title: t.title, username: t.account, custom: otpFields(t) }));
  assert.deepEqual(ids.map((id) => tokenFromEntry(vault.getEntry(id))), tokens);

  const db = await kdbxweb.Kdbx.load(await vault.save(), new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(PASSWORD)));
  const saved = db.getGroup(groupId).entries;
  assert.equal(saved.length, tokens.length);
  const github = saved.find((e) => e.fields.get('Title') === 'GitHub');
  assert.equal(github.fields.get('UserName'), 'alice');
  assert.ok(github.fields.get('otp') instanceof kdbxweb.ProtectedValue);
  assert.ok(github.fields.get('TimeOtp-Secret-Base32') instanceof kdbxweb.ProtectedValue);
  assert.equal(github.fields.get('TimeOtp-Secret-Base32').getText(), 'JBSWY3DPEHPK3PXP');
  assert.equal(github.fields.get('otp').getText(), toOtpauthUri(TWOFAS_TOKENS[0]));
});

// ------------------------------------------------------------ QR library (as src/qr.js uses it)

test('qr: a restore QR code decodes back to the same token', () => {
  const token = {
    type: 'totp', title: 'service.example.com', issuer: 'service.example.com', account: 'someone.with.a.long.name@example.com',
    secret: base32Encode(Uint8Array.from({ length: 64 }, (_, i) => (i * 151 + 11) & 255)), algorithm: 'SHA512', digits: 8, period: 60,
  };
  const uri = toOtpauthUri(token);
  const grid = encodeQR(uri, 'raw', { ecc: 'medium', border: 4 });
  const scale = 4;
  const side = grid.length * scale;
  const data = new Uint8ClampedArray(side * side * 4);
  for (let y = 0; y < side; y++) {
    for (let x = 0; x < side; x++) {
      const v = grid[Math.floor(y / scale)][Math.floor(x / scale)] ? 0 : 255;
      data.set([v, v, v, 255], (y * side + x) * 4);
    }
  }
  const text = decodeQR({ width: side, height: side, data });
  assert.equal(text, uri);
  assert.deepEqual(parseLinks(text), [token]);
});
