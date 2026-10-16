// Last login: every successful open records {at, ua} in lastlogin.json and reports the
// previous record in the X-Vault-Last-Login(-UA) headers.
import { after, before, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import {
  IS_ROOT, assertError, fakeVault, nowSec, randomHex, startServer,
} from './harness.mjs';

const skipNoRoot = IS_ROOT ? 'file permissions are not enforced for root' : false;
const UA_A = 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0';
const UA_B = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1';

describe('last login', () => {
  let s;
  const readLast = () => JSON.parse(readFileSync(s.lastLoginPath, 'utf8'));
  const openAs = (ua, token = s.tokenHex) =>
    s.request('open', { method: 'POST', token, headers: { 'User-Agent': ua } });

  before(async () => { s = await startServer({ config: { delay_seconds: 3 } }); });
  after(() => s.stop());
  beforeEach(() => {
    if (existsSync(s.lastLoginPath)) chmodSync(s.lastLoginPath, 0o644);
    rmSync(s.lastLoginPath, { force: true });
    s.resetState();
  });

  test('first open: no headers, the open is recorded with time and User-Agent only', async () => {
    const t0 = nowSec();
    const r = await openAs(UA_A);
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('x-vault-last-login'), null);
    assert.equal(r.headers.get('x-vault-last-login-ua'), null);
    const rec = readLast();
    assert.deepEqual(Object.keys(rec), ['at', 'ua']);
    assert.equal(rec.ua, UA_A);
    assert.ok(rec.at >= t0 && rec.at <= nowSec());
  });

  test('next open reports the previous one and records itself', async () => {
    await openAs(UA_A);
    const first = readLast();
    const r = await openAs(UA_B);
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('x-vault-last-login'), String(first.at));
    assert.equal(r.headers.get('x-vault-last-login-ua'), UA_A);
    assert.equal(readLast().ua, UA_B);
  });

  test('failed, locked, status and save requests leave the record alone', async () => {
    await openAs(UA_A);
    const before = readFileSync(s.lastLoginPath, 'utf8');
    assertError(await openAs(UA_B, randomHex()), 401, 'bad_token');
    assert.equal((await s.status()).status, 200);
    assert.equal((await s.save(fakeVault(100))).status, 200);
    await s.fail(3);
    assertError(await openAs(UA_B), 429, 'locked');
    assert.equal(readFileSync(s.lastLoginPath, 'utf8'), before);
  });

  test('status does not create lastlogin.json', async () => {
    await s.status();
    assert.equal(existsSync(s.lastLoginPath), false);
  });

  test('User-Agent is reduced to printable ASCII and 256 chars; empty UA sends no UA header', async () => {
    await openAs(`\tA${'x'.repeat(300)}`);
    assert.equal(readLast().ua, `A${'x'.repeat(255)}`);
    await openAs('');
    assert.equal(readLast().ua, '');
    const r = await openAs(UA_A);
    assert.ok(r.headers.get('x-vault-last-login'));
    assert.equal(r.headers.get('x-vault-last-login-ua'), null);
  });

  test('corrupt record => reported as none and replaced', async () => {
    for (const bad of ['', 'nope', '{"at":"1","ua":"x"}', '{"at":0,"ua":"x"}', '{"at":5,"ua":"\\r\\nX: y"}', '[]']) {
      writeFileSync(s.lastLoginPath, bad);
      const r = await openAs(UA_A);
      assert.equal(r.status, 200);
      assert.equal(r.headers.get('x-vault-last-login'), null, bad);
      assert.equal(readLast().ua, UA_A);
    }
  });

  test('record cannot be written => 500 state_error, vault not served', { skip: skipNoRoot }, async () => {
    writeFileSync(s.lastLoginPath, JSON.stringify({ at: 1, ua: 'x' }));
    chmodSync(s.lastLoginPath, 0o444);
    try {
      const r = await openAs(UA_A);
      assertError(r, 500, 'state_error');
      assert.equal(r.headers.get('x-vault-rev'), null);
      assert.ok(!r.body.includes(s.vault.subarray(0, 8)));
    } finally {
      chmodSync(s.lastLoginPath, 0o644);
    }
    assert.deepEqual(readLast(), { at: 1, ua: 'x' });
    // A wrong token still gets the normal 401 (the record is only touched after the gate).
    assertError(await openAs(UA_A, randomHex()), 401, 'bad_token');
  });
});
