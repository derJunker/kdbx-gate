// POST api.php?a=save
import { after, before, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { KDBX_SIG, assertError, fakeVault, randomHex, sha256, startServer } from './harness.mjs';

const MAX = 65536;
const KEEP = 2;
const BACKUP_RE = /^vault-\d{8}-\d{6}(-\d+)?\.kdbx$/;

function streamOf(buf, chunkSize = 1000) {
  let pos = 0;
  return new ReadableStream({
    pull(controller) {
      if (pos >= buf.length) {
        controller.close();
        return;
      }
      controller.enqueue(new Uint8Array(buf.subarray(pos, pos + chunkSize)));
      pos += chunkSize;
    },
  });
}

describe('save', () => {
  let s;
  before(async () => {
    s = await startServer({ config: { delay_seconds: 3, keep_backups: KEEP, max_vault_bytes: MAX } });
  });
  after(() => s.stop());
  beforeEach(() => {
    s.resetState();
    rmSync(s.backupsDir, { recursive: true, force: true });
    s.writeVault(fakeVault(4096));
  });

  function assertUnchanged(original) {
    assert.ok(s.readVault().equals(original), 'vault must be unchanged');
    assert.deepEqual(s.tempFiles(), [], 'no temp files may be left behind');
  }

  test('success: new rev, content replaced, old version backed up, open serves the new file', async () => {
    const old = s.vault;
    const next = fakeVault(5000);
    const r = await s.save(next, { baseRev: sha256(old) });
    assert.equal(r.status, 200, JSON.stringify(r.json));
    assert.deepEqual(r.json, { rev: sha256(next) });
    assert.ok(s.readVault().equals(next));
    const backups = s.backups();
    assert.equal(backups.length, 1);
    assert.match(backups[0], BACKUP_RE);
    assert.ok(readFileSync(join(s.backupsDir, backups[0])).equals(old));
    assert.deepEqual(s.tempFiles(), []);

    const o = await s.open();
    assert.ok(o.body.equals(next));
    assert.equal(o.headers.get('x-vault-rev'), r.json.rev);
  });

  test('backups are pruned to the newest keep_backups', async () => {
    const versions = [s.vault];
    for (let i = 0; i < 4; i++) {
      const next = fakeVault(1000 + i);
      const r = await s.save(next, { baseRev: sha256(versions.at(-1)) });
      assert.equal(r.status, 200);
      versions.push(next);
    }
    const backups = s.backups();
    assert.equal(backups.length, KEEP);
    for (const b of backups) assert.match(b, BACKUP_RE);
    const kept = new Set(backups.map((b) => sha256(readFileSync(join(s.backupsDir, b)))));
    // the newest backups are the versions replaced by the last two saves
    assert.deepEqual(kept, new Set([sha256(versions[2]), sha256(versions[3])]));
    assert.ok(s.readVault().equals(versions[4]));
  });

  test('pruning leaves unrelated files in backups/ alone', async () => {
    const r1 = await s.save(fakeVault(100));
    assert.equal(r1.status, 200);
    writeFileSync(join(s.backupsDir, 'keep-me.txt'), 'x');
    for (let i = 0; i < 3; i++) assert.equal((await s.save(fakeVault(100))).status, 200);
    const files = s.backups();
    assert.ok(files.includes('keep-me.txt'));
    assert.equal(files.filter((f) => BACKUP_RE.test(f)).length, KEEP);
  });

  test('conflict: base rev differs => 409 with the current rev, nothing written', async () => {
    const old = s.vault;
    const r = await s.save(fakeVault(100), { baseRev: randomHex() });
    assertError(r, 409, 'conflict');
    assert.deepEqual(r.json, { error: 'conflict', rev: sha256(old) });
    assertUnchanged(old);
    assert.deepEqual(s.backups(), []);
  });

  test('missing or malformed X-Vault-Base-Rev => 400 bad_request', async () => {
    const old = s.vault;
    const r1 = await s.request('save', { method: 'POST', token: s.tokenHex, body: fakeVault(100) });
    assertError(r1, 400, 'bad_request');
    const r2 = await s.save(fakeVault(100), { baseRev: 'abc' });
    assertError(r2, 400, 'bad_request');
    assertUnchanged(old);
  });

  test('invalid_kdbx: body without the KDBX signature => 400', async () => {
    const old = s.vault;
    const wrongSig = Buffer.from(KDBX_SIG);
    wrongSig[7] ^= 1;
    for (const body of [
      Buffer.from('hello world, definitely not a kdbx file'),
      Buffer.alloc(0),
      KDBX_SIG.subarray(0, 7),
      Buffer.concat([wrongSig, Buffer.alloc(100)]),
      Buffer.concat([Buffer.from([0]), KDBX_SIG]),
    ]) {
      assertError(await s.save(body, { baseRev: sha256(old) }), 400, 'invalid_kdbx');
    }
    assertUnchanged(old);
  });

  test('a body of exactly max_vault_bytes is accepted', async () => {
    const next = fakeVault(MAX - KDBX_SIG.length);
    assert.equal(next.length, MAX);
    const r = await s.save(next);
    assert.equal(r.status, 200);
    assert.ok(s.readVault().equals(next));
  });

  test('too_large: Content-Length above max_vault_bytes => 413', async () => {
    const old = s.vault;
    const r = await s.save(fakeVault(MAX - KDBX_SIG.length + 1));
    assertError(r, 413, 'too_large');
    assertUnchanged(old);
  });

  test('too_large without Content-Length (chunked): the bounded read stops at max + 1', async () => {
    const old = s.vault;
    const r = await s.save(streamOf(fakeVault(MAX * 2)), { baseRev: sha256(old) });
    assertError(r, 413, 'too_large');
    assertUnchanged(old);
  });

  test('chunked upload within the limit is saved', async () => {
    const next = fakeVault(30000);
    const r = await s.save(streamOf(next, 4096));
    assert.equal(r.status, 200);
    assert.deepEqual(r.json, { rev: sha256(next) });
    assert.ok(s.readVault().equals(next));
  });

  test('save goes through the gate: wrong token => 401, locked => 429 (also for the right token)', async () => {
    const old = s.vault;
    const r1 = await s.save(fakeVault(100), { token: randomHex() });
    assert.deepEqual(r1.json, { error: 'bad_token', attemptsLeft: 2, retryAfter: 0 });
    const r2 = await s.save(fakeVault(100), { token: null });
    assert.deepEqual(r2.json, { error: 'bad_token', attemptsLeft: 1, retryAfter: 0 });
    const r3 = await s.save(fakeVault(100), { token: randomHex() });
    assert.deepEqual(r3.json, { error: 'bad_token', attemptsLeft: 0, retryAfter: 3 });
    const r4 = await s.save(fakeVault(100));
    assertError(r4, 429, 'locked');
    assert.equal(r4.headers.get('retry-after'), String(r4.json.retryAfter));
    // even an oversized or invalid body only ever sees the gate
    assertError(await s.save(fakeVault(MAX * 2)), 429, 'locked');
    assertError(await s.save(Buffer.from('nope')), 429, 'locked');
    assertUnchanged(old);
    assert.deepEqual(s.backups(), []);
  });

  test('a wrong token is rejected before size and format checks', async () => {
    assertError(await s.save(fakeVault(MAX * 2), { token: randomHex() }), 401, 'bad_token');
    assertError(await s.save(Buffer.from('nope'), { token: randomHex() }), 401, 'bad_token');
  });

  test('save with a valid token but no vault file => 404 no_vault', async () => {
    const old = s.vault;
    rmSync(s.vaultPath);
    try {
      assertError(await s.save(fakeVault(100), { baseRev: sha256(old) }), 404, 'no_vault');
      assert.deepEqual(s.tempFiles(), []);
    } finally {
      s.writeVault(old);
    }
  });

  test('keep_backups = 0 disables backups', async () => {
    s.writeConfig({ keep_backups: 0 });
    try {
      assert.equal((await s.save(fakeVault(100))).status, 200);
      assert.deepEqual(s.backups(), []);
    } finally {
      s.writeConfig();
    }
  });
});
