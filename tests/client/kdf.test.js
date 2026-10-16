import test from 'node:test';
import assert from 'node:assert/strict';
import {
  deriveAuthToken,
  buildVerifier,
  parseVerifier,
  checkParams,
  checkTokenAgainstVerifier,
  randomSalt,
  DEFAULT_PARAMS,
} from '../../src/kdf.js';
import { base64ToBytes, isBase64 } from '../../src/bytes.js';

// Known-answer vectors computed once with PHP's libsodium (the server side of the scheme):
//   php -r 'echo bin2hex(sodium_crypto_pwhash(32, "correct horse ☃ Größe",
//       base64_decode("AAECAwQFBgcICQoLDA0ODw=="), 1, 1024*1024, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13)), "\n";'
//   php -r '$t = sodium_crypto_pwhash(...same args...); echo hash("sha256", $t), "\n";'
const SMALL = {
  password: 'correct horse ☃ Größe',
  params: { m: 1024, t: 1, p: 1, salt: 'AAECAwQFBgcICQoLDA0ODw==' },
  token: 'b6465b3b521f2109f007597f29b9708580344c52fcfaa231ddc4d1701fcb3d9b',
  sha256: '6c1c4cd5a61d4ee959a914823d3d3f3eb00c6ecfd46bb26f5d5a413ebf768a8d',
};
//   php -r 'echo bin2hex(sodium_crypto_pwhash(32, "hunter2",
//       base64_decode("c2FsdHNhbHRzYWx0c2FsdA=="), 3, 65536*1024, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13)), "\n";'
const DEFAULTS = {
  password: 'hunter2',
  params: { kdf: 'argon2id', m: 65536, t: 3, p: 1, salt: 'c2FsdHNhbHRzYWx0c2FsdA==' },
  token: 'dd17138a1554f3e9034b679b2121901de9463580c7970d2d29c2c6822d271ae0',
  sha256: '0f03c15094c89a1bb37fac8eb37eb20692bed761e1c22caea1432a546a1e4604',
};

test('deriveAuthToken matches libsodium (UTF-8 password, small params)', async () => {
  assert.equal(await deriveAuthToken(SMALL.password, SMALL.params), SMALL.token);
});

test('deriveAuthToken matches libsodium with the SPEC default params', async () => {
  assert.deepEqual({ ...DEFAULT_PARAMS }, { m: 65536, t: 3, p: 1 });
  const token = await deriveAuthToken(DEFAULTS.password, DEFAULTS.params);
  assert.equal(token, DEFAULTS.token);
  assert.match(token, /^[0-9a-f]{64}$/);
});

test('buildVerifier produces the SPEC format with SHA-256(token) as PHP computes it', async () => {
  const v = await buildVerifier(SMALL.token, SMALL.params);
  assert.equal(v, `v1$argon2id$m=1024,t=1,p=1$AAECAwQFBgcICQoLDA0ODw==$${SMALL.sha256}`);
  const v2 = await buildVerifier(DEFAULTS.token, DEFAULTS.params);
  assert.equal(v2, `v1$argon2id$m=65536,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA==$${DEFAULTS.sha256}`);
});

test('parseVerifier round trip and token check', async () => {
  const v = await buildVerifier(SMALL.token, SMALL.params);
  const parsed = parseVerifier(v);
  assert.deepEqual(parsed, { version: 'v1', kdf: 'argon2id', m: 1024, t: 1, p: 1, salt: SMALL.params.salt, hash: SMALL.sha256 });
  assert.equal(await checkTokenAgainstVerifier(SMALL.token, v), true);
  assert.equal(await checkTokenAgainstVerifier('0'.repeat(64), v), false);
  assert.equal(await checkTokenAgainstVerifier('not-hex', v), false);
});

test('parseVerifier rejects malformed verifiers', () => {
  const salt = 'AAECAwQFBgcICQoLDA0ODw==';
  const hash = SMALL.sha256;
  const bad = [
    '',
    'v1$argon2id$m=1024,t=1,p=1$' + salt,
    `v2$argon2id$m=1024,t=1,p=1$${salt}$${hash}`,
    `v1$argon2i$m=1024,t=1,p=1$${salt}$${hash}`,
    `v1$argon2id$m=1024,t=1$${salt}$${hash}`,
    `v1$argon2id$t=1,m=1024,p=1$${salt}$${hash}`,
    `v1$argon2id$m=0,t=1,p=1$${salt}$${hash}`,
    `v1$argon2id$m=1024,t=0,p=1$${salt}$${hash}`,
    `v1$argon2id$m=01024,t=1,p=1$${salt}$${hash}`,
    `v1$argon2id$m=4,t=1,p=1$${salt}$${hash}`,
    `v1$argon2id$m=1024,t=1,p=1$AAECAwQFBgcICQoLDA0ODw$${hash}`, // unpadded
    `v1$argon2id$m=1024,t=1,p=1$AAEC$${hash}`, // 3-byte salt
    `v1$argon2id$m=1024,t=1,p=1$${salt}$${hash.toUpperCase()}`,
    `v1$argon2id$m=1024,t=1,p=1$${salt}$${hash.slice(1)}`,
    `v1$argon2id$m=1024,t=1,p=1$${salt}$${hash}0`,
    `v1$argon2id$m=1024,t=1,p=1$${salt}$${hash}\n`,
    ` v1$argon2id$m=1024,t=1,p=1$${salt}$${hash}`,
  ];
  for (const v of bad) assert.throws(() => parseVerifier(v), undefined, JSON.stringify(v));
  assert.throws(() => parseVerifier(null));
  assert.throws(() => parseVerifier(42));
});

test('checkParams validates server params', () => {
  assert.deepEqual(checkParams({ kdf: 'argon2id', m: 65536, t: 3, p: 1, salt: 'c2FsdHNhbHRzYWx0c2FsdA==' }), {
    kdf: 'argon2id',
    m: 65536,
    t: 3,
    p: 1,
    salt: 'c2FsdHNhbHRzYWx0c2FsdA==',
  });
  assert.throws(() => checkParams({ kdf: 'scrypt', m: 65536, t: 3, p: 1, salt: 'c2FsdHNhbHRzYWx0c2FsdA==' }));
  assert.throws(() => checkParams({ m: 65536.5, t: 3, p: 1, salt: 'c2FsdHNhbHRzYWx0c2FsdA==' }));
  assert.throws(() => checkParams({ m: 16, t: 3, p: 4, salt: 'c2FsdHNhbHRzYWx0c2FsdA==' }));
  assert.throws(() => checkParams({ m: 65536, t: 3, p: 1, salt: 'not base64!' }));
  assert.throws(() => checkParams({ m: 65536, t: 3, p: 1 }));
  assert.throws(() => checkParams(null));
});

test('deriveAuthToken rejects bad input', async () => {
  await assert.rejects(deriveAuthToken(123, SMALL.params));
  await assert.rejects(deriveAuthToken('x', { ...SMALL.params, salt: '' }));
  await assert.rejects(buildVerifier('ABC', SMALL.params));
});

test('randomSalt gives 16 random bytes as padded base64', () => {
  const a = randomSalt();
  const b = randomSalt();
  assert.ok(isBase64(a));
  assert.equal(base64ToBytes(a).length, 16);
  assert.notEqual(a, b);
});
