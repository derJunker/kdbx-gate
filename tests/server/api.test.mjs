// HTTP API basics: params, status, headers, methods, routing, configuration, open.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  assertError, fakeVault, makeVerifier, phpConfig, randomHex, sha256, startServer,
} from './harness.mjs';

describe('api: params, status, routing, headers', () => {
  let s;
  before(async () => { s = await startServer({ config: { delay_seconds: 3 } }); });
  after(() => s.stop());

  test('params returns the public KDF parameters and salt', async () => {
    const r = await s.params();
    assert.equal(r.status, 200);
    assert.deepEqual(r.json, { kdf: 'argon2id', m: 65536, t: 3, p: 1, salt: s.salt });
    assert.deepEqual(Object.keys(r.json), ['kdf', 'm', 't', 'p', 'salt']);
  });

  test('params reflects the parameters stored in the verifier', async () => {
    const salt = randomBytes(16).toString('base64');
    const v = makeVerifier(randomBytes(32), salt, { m: 19456, t: 2, p: 1 });
    s.writeConfig({ verifier: v });
    try {
      const r = await s.params();
      assert.deepEqual(r.json, { kdf: 'argon2id', m: 19456, t: 2, p: 1, salt });
    } finally {
      s.writeConfig();
    }
  });

  test('status shape, without creating any state', async () => {
    s.resetState();
    const r = await s.status();
    assert.equal(r.status, 200);
    assert.deepEqual(r.json, { retryAfter: 0, attemptsLeft: 3 });
    assert.deepEqual(Object.keys(r.json), ['retryAfter', 'attemptsLeft']);
    assert.equal(existsSync(s.lockoutPath), false, 'status must not create lockout.json');
  });

  test('unknown or missing action => 400 bad_request', async () => {
    for (const query of ['a=nope', '', 'a=PARAMS', 'a[]=params', 'a=', 'x=params', 'a=open%00']) {
      const r = await s.request(null, { query });
      assertError(r, 400, 'bad_request');
    }
    const r = await s.request(null, { query: 'a=nope', method: 'POST', token: s.tokenHex });
    assertError(r, 400, 'bad_request');
  });

  test('wrong HTTP method => 405 with Allow, and no attempt is spent', async () => {
    s.resetState();
    const cases = [
      ['params', 'POST', 'GET'], ['params', 'PUT', 'GET'], ['status', 'POST', 'GET'],
      ['status', 'DELETE', 'GET'], ['open', 'GET', 'POST'], ['open', 'PUT', 'POST'],
      ['save', 'GET', 'POST'], ['save', 'PUT', 'POST'], ['open', 'OPTIONS', 'POST'],
    ];
    for (const [action, method, allow] of cases) {
      const r = await s.request(action, {
        method, token: randomHex(), headers: { Origin: 'https://evil.example' },
      });
      assertError(r, 405, 'method_not_allowed');
      assert.equal(r.headers.get('allow'), allow);
    }
    assert.equal(existsSync(s.lockoutPath), false);
    assert.deepEqual((await s.status()).json, { retryAfter: 0, attemptsLeft: 3 });
  });

  test('no CORS headers, even for cross-origin requests', async () => {
    const r = await s.request('params', { headers: { Origin: 'https://evil.example' } });
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('access-control-allow-origin'), null);
  });

  test('open returns the exact vault bytes with X-Vault-Rev', async () => {
    const vault = s.writeVault(fakeVault(200000));
    const r = await s.open();
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('content-type'), 'application/octet-stream');
    assert.equal(r.headers.get('content-length'), String(vault.length));
    assert.equal(r.headers.get('x-vault-rev'), sha256(vault));
    assert.ok(r.body.equals(vault));
  });

  test('open ignores the request body', async () => {
    const r = await s.request('open', { method: 'POST', token: s.tokenHex, body: Buffer.from('ignored') });
    assert.equal(r.status, 200);
    assert.ok(r.body.equals(s.vault));
  });

  test('open with a valid token but no vault file => 404 no_vault', async () => {
    const vault = s.readVault();
    rmSync(s.vaultPath);
    try {
      assertError(await s.open(), 404, 'no_vault');
      assertError(await s.open(randomHex()), 401, 'bad_token');
    } finally {
      s.writeVault(vault);
      s.resetState();
    }
  });

  test('stray output from config.php does not leak into responses', async () => {
    s.writeRawConfig(`\n  <?php echo "LEAK"; trigger_error("WARN", E_USER_WARNING);\nreturn ['verifier' => '${s.verifier}', 'delay_seconds' => 3];\n`);
    try {
      const r = await s.params();
      assert.equal(r.status, 200);
      assert.equal(r.body.toString(), JSON.stringify({ kdf: 'argon2id', m: 65536, t: 3, p: 1, salt: s.salt }));
    } finally {
      s.writeConfig();
    }
  });
});

describe('api: not configured => 503 for every action', () => {
  let s;
  before(async () => { s = await startServer({ writeConfig: false }); });
  after(() => s.stop());

  async function expectNotConfigured(label) {
    const results = [
      await s.params(),
      await s.status(),
      await s.open(),
      await s.save(s.vault, { baseRev: sha256(s.vault) }),
    ];
    for (const r of results) {
      assert.equal(r.status, 503, `${label}: got ${r.status} ${r.body}`);
      assert.deepEqual(r.json, { error: 'not_configured' }, label);
    }
    assert.equal(existsSync(s.lockoutPath), false, `${label}: no state may be created`);
    assert.ok(s.readVault().equals(s.vault), `${label}: vault untouched`);
  }

  test('no config file', async () => {
    rmSync(s.configPath, { force: true });
    await expectNotConfigured('missing config');
  });

  test('the shipped config.sample.php (placeholder verifier) is rejected', async () => {
    s.writeRawConfig(readFileSync(join(s.www, 'data', 'config.sample.php')));
    await expectNotConfigured('sample config');
  });

  test('invalid configs', async () => {
    const good = s.verifier;
    const hex = good.split('$').pop();
    const salt = s.salt;
    const bad = {
      'garbage verifier': phpConfig({ verifier: 'garbage' }),
      'empty verifier': phpConfig({ verifier: '' }),
      'no verifier key': phpConfig({ delay_seconds: 5 }),
      'numeric verifier': '<?php return ["verifier" => 12345];',
      'not an array': '<?php return "hello";',
      'returns nothing': '<?php $x = 1;',
      'syntax error': '<?php return [ "verifier" => ;',
      'throws': '<?php throw new Exception("/secret/path");',
      'wrong version': phpConfig({ verifier: good.replace(/^v1/, 'v2') }),
      'wrong kdf': phpConfig({ verifier: good.replace('argon2id', 'argon2i') }),
      'uppercase prefix': phpConfig({ verifier: good.replace('v1$argon2id', 'V1$ARGON2ID') }),
      'short hex': phpConfig({ verifier: good.slice(0, -1) }),
      'long hex': phpConfig({ verifier: `${good}0` }),
      'non-hex': phpConfig({ verifier: `${good.slice(0, -1)}g` }),
      'trailing newline': phpConfig({ verifier: `${good}\n` }),
      'trailing space': phpConfig({ verifier: `${good} ` }),
      'salt not base64': phpConfig({ verifier: `v1$argon2id$m=65536,t=3,p=1$!!!!$${hex}` }),
      'salt unpadded': phpConfig({ verifier: `v1$argon2id$m=65536,t=3,p=1$${salt.replace(/=+$/, '')}$${hex}` }),
      'salt too short': phpConfig({ verifier: `v1$argon2id$m=65536,t=3,p=1$${randomBytes(4).toString('base64')}$${hex}` }),
      'missing salt': phpConfig({ verifier: `v1$argon2id$m=65536,t=3,p=1$$${hex}` }),
      'm zero': phpConfig({ verifier: good.replace('m=65536', 'm=0') }),
      'm < 8p': phpConfig({ verifier: good.replace('m=65536', 'm=8').replace('p=1', 'p=2') }),
      't zero': phpConfig({ verifier: good.replace('t=3', 't=0') }),
      'leading zero': phpConfig({ verifier: good.replace('t=3', 't=03') }),
      'param order': phpConfig({ verifier: good.replace('m=65536,t=3', 't=3,m=65536') }),
      'bad delay_seconds': phpConfig({ verifier: good, delay_seconds: 'abc' }),
      'zero delay_seconds': phpConfig({ verifier: good, delay_seconds: 0 }),
      'negative free_attempts': phpConfig({ verifier: good, free_attempts: -1 }),
      'bad max_vault_bytes': phpConfig({ verifier: good, max_vault_bytes: 1.5 }),
      'bad keep_backups': phpConfig({ verifier: good, keep_backups: '3x' }),
      'bad vault_file': phpConfig({ verifier: good, vault_file: 123 }),
      'empty state_dir': phpConfig({ verifier: good, state_dir: '' }),
    };
    for (const [label, text] of Object.entries(bad)) {
      s.writeRawConfig(text);
      await expectNotConfigured(label);
    }
  });

  test('a valid config works again (sanity check of the fixture)', async () => {
    s.writeConfig();
    assert.equal((await s.params()).status, 200);
    const r = await s.open();
    assert.equal(r.status, 200);
    assert.ok(r.body.equals(s.vault));
  });
});

describe('api: default config location (data/config.php, no KDBX_GATE_CONFIG)', () => {
  let s;
  before(async () => { s = await startServer({ useEnv: false, writeConfig: false }); });
  after(() => s.stop());

  test('503 until data/config.php exists, then works with data/ defaults', async () => {
    assert.equal(s.configPath, join(s.www, 'data', 'config.php'));
    assertError(await s.params(), 503, 'not_configured');
    s.writeConfig();
    const p = await s.params();
    assert.equal(p.status, 200);
    assert.equal(p.json.salt, s.salt);
    const r = await s.open();
    assert.equal(r.status, 200);
    assert.ok(r.body.equals(s.vault));
    assert.equal(r.headers.get('x-vault-rev'), sha256(s.vault));
    assertError(await s.open(randomHex()), 401, 'bad_token');
    assert.equal(s.readState().fails, 1, 'state lives next to config.php by default');
  });
});
