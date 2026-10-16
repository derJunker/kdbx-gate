// Parallel requests against a multi-worker php -S (PHP_CLI_SERVER_WORKERS=8):
// the flock-protected gate and the vault lock must serialize correctly.
import { after, before, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { assertError, fakeVault, nowSec, randomHex, sha256, startServer } from './harness.mjs';

/** Distinct worker PIDs that logged a request since the last clearLog(). */
function workerPids(s) {
  return new Set([...s.getLog().matchAll(/^\[(\d+)\]/gm)].map((m) => m[1]));
}

describe('concurrency', () => {
  let s;
  // Default config (only the verifier): free_attempts 3, delay 60 s, so the
  // lockout cannot expire in the middle of a burst.
  before(async () => { s = await startServer({ vaultSize: 1024 * 1024 }); });
  after(() => s.stop());
  beforeEach(() => { s.resetState(); s.clearLog(); });

  test('20 parallel wrong tokens: exactly 3 get 401, the other 17 get 429', async () => {
    const results = await Promise.all(Array.from({ length: 20 }, () => s.open(randomHex())));
    const unauthorized = results.filter((r) => r.status === 401);
    const locked = results.filter((r) => r.status === 429);
    assert.equal(unauthorized.length, 3, `statuses: ${results.map((r) => r.status)}`);
    assert.equal(locked.length, 17);
    assert.deepEqual(unauthorized.map((r) => r.json.attemptsLeft).sort(), [0, 1, 2]);
    for (const r of unauthorized) {
      assert.equal(r.json.retryAfter, r.json.attemptsLeft > 0 ? 0 : 60);
    }
    for (const r of locked) {
      assertError(r, 429, 'locked');
      assert.ok(r.json.retryAfter >= 58 && r.json.retryAfter <= 60);
    }
    const st = s.readState();
    assert.equal(st.fails, 3);
    assert.ok(Math.abs(st.last - nowSec()) <= 3);
    assert.ok(workerPids(s).size > 1, 'requests must really be handled by several workers');
  });

  test('parallel correct + wrong mixes keep lockout.json consistent', async () => {
    for (let round = 0; round < 3; round++) {
      s.resetState();
      const results = await Promise.all(Array.from({ length: 30 }, (_, i) => (
        i % 3 === 0 ? s.open() : s.open(randomHex())
      )));
      const raw = s.readStateRaw();
      const st = JSON.parse(raw); // never corrupt
      assert.deepEqual(Object.keys(st).sort(), ['fails', 'last']);
      assert.ok(Number.isInteger(st.fails) && st.fails >= 0 && st.fails <= 3, raw);
      assert.ok(Number.isInteger(st.last));
      const count = { 200: 0, 401: 0, 429: 0 };
      for (const r of results) {
        assert.ok(r.status in count, `unexpected status ${r.status}`);
        count[r.status]++;
        if (r.status === 200) {
          assert.ok(r.body.equals(s.vault));
          assert.equal(r.headers.get('x-vault-rev'), sha256(s.vault));
        } else if (r.status === 401) {
          assert.ok([0, 1, 2].includes(r.json.attemptsLeft));
        } else {
          assert.ok(r.json.retryAfter >= 1 && r.json.retryAfter <= 60);
        }
      }
      assert.ok(count[401] >= st.fails);
      assert.ok(count[200] + count[401] >= 1);
      if (count[429] > 0) assert.equal(st.fails, 3, 'a 429 implies the counter reached the limit');
      const status = await s.status();
      assert.equal(status.json.attemptsLeft, 3 - st.fails);
    }
  });

  test('parallel saves with the same base rev: exactly one wins, the rest get 409', async () => {
    const base = sha256(s.vault);
    const bodies = Array.from({ length: 8 }, () => fakeVault(200000));
    const results = await Promise.all(bodies.map((b) => s.save(b, { baseRev: base })));
    const ok = results.map((r, i) => [r, i]).filter(([r]) => r.status === 200);
    assert.equal(ok.length, 1, `statuses: ${results.map((r) => r.status)}`);
    const [winner, wi] = ok[0];
    assert.equal(winner.json.rev, sha256(bodies[wi]));
    for (const r of results) {
      if (r === winner) continue;
      assert.deepEqual(r.json, { error: 'conflict', rev: winner.json.rev });
    }
    assert.ok(s.readVault().equals(bodies[wi]));
    assert.equal(s.backups().length, 1);
    assert.deepEqual(s.tempFiles(), []);
    s.vault = bodies[wi];
  });

  test('opens running in parallel with a save always get bytes matching X-Vault-Rev', async () => {
    const old = s.vault;
    const next = fakeVault(1024 * 1024);
    const requests = Array.from({ length: 12 }, () => s.open());
    requests.splice(4, 0, s.save(next, { baseRev: sha256(old) }));
    const results = await Promise.all(requests);
    const save = results[4];
    assert.equal(save.status, 200);
    for (const r of results) {
      if (r === save) continue;
      assert.equal(r.status, 200);
      assert.equal(sha256(r.body), r.headers.get('x-vault-rev'));
      assert.ok(r.body.equals(old) || r.body.equals(next));
    }
    s.vault = next;
  });
});
