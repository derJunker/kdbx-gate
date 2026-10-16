// Fail closed: when the lockout state cannot be read, locked or written, the
// vault is never served.
import { after, before, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { IS_ROOT, assertError, fakeVault, randomHex, sha256, startServer } from './harness.mjs';

const skipNoRoot = IS_ROOT ? 'file permissions are not enforced for root' : false;

describe('fail closed', () => {
  let s;
  before(async () => { s = await startServer({ config: { delay_seconds: 3 } }); });
  after(() => s.stop());
  beforeEach(() => {
    chmodSync(s.stateDir, 0o755);
    if (existsSync(s.lockoutPath)) chmodSync(s.lockoutPath, 0o644);
    s.resetState();
  });

  function assertNoVault(r) {
    assertError(r, 500, 'state_error');
    assert.ok(!r.body.includes(s.vault.subarray(0, 8)), 'vault bytes must not be served');
    assert.equal(r.headers.get('x-vault-rev'), null);
  }

  test('state dir not writable (lockout.json cannot be created) => 500, vault not served', { skip: skipNoRoot }, async () => {
    const old = s.vault;
    chmodSync(s.stateDir, 0o555);
    try {
      assertNoVault(await s.open());
      assertNoVault(await s.open(randomHex()));
      assertNoVault(await s.save(fakeVault(100), { baseRev: sha256(old) }));
    } finally {
      chmodSync(s.stateDir, 0o755);
    }
    assert.ok(s.readVault().equals(old));
    assert.equal(existsSync(s.lockoutPath), false);
  });

  test('lockout.json read-only => 500 for right and wrong tokens, state unchanged', { skip: skipNoRoot }, async () => {
    s.writeState({ fails: 1, last: 1 });
    chmodSync(s.lockoutPath, 0o444);
    try {
      assertNoVault(await s.open());
      assertNoVault(await s.open(randomHex()));
    } finally {
      chmodSync(s.lockoutPath, 0o644);
    }
    assert.deepEqual(s.readState(), { fails: 1, last: 1 });
  });

  test('lockout.json unreadable => 500 for status and open', { skip: skipNoRoot }, async () => {
    s.writeState({ fails: 0, last: 0 });
    chmodSync(s.lockoutPath, 0o000);
    try {
      assertError(await s.status(), 500, 'state_error');
      assertNoVault(await s.open());
    } finally {
      chmodSync(s.lockoutPath, 0o644);
    }
  });

  test('state_dir missing => 500 state_error', async () => {
    s.writeConfig({ state_dir: join(s.root, 'does-not-exist') });
    try {
      assertNoVault(await s.open());
      assertError(await s.status(), 500, 'state_error');
    } finally {
      s.writeConfig();
    }
  });

  test('state_dir is a file => 500 state_error', async () => {
    const file = join(s.root, 'not-a-dir');
    writeFileSync(file, 'x');
    s.writeConfig({ state_dir: file });
    try {
      assertNoVault(await s.open());
      assertError(await s.status(), 500, 'state_error');
    } finally {
      s.writeConfig();
    }
  });

  test('backups/ cannot be created => save fails (500 backup_failed), vault unchanged', async () => {
    const old = s.vault;
    rmSync(s.backupsDir, { recursive: true, force: true });
    writeFileSync(s.backupsDir, 'in the way'); // a file where the directory should be
    try {
      const r = await s.save(fakeVault(100), { baseRev: sha256(old) });
      assertError(r, 500, 'backup_failed');
      assert.ok(s.readVault().equals(old));
      assert.deepEqual(s.tempFiles(), []);
    } finally {
      rmSync(s.backupsDir, { force: true });
    }
  });

  test('vault directory not writable => save fails (500), vault unchanged', { skip: skipNoRoot }, async () => {
    // Keep state in a separate, writable directory so only the vault dir is read-only.
    const stateDir = join(s.root, 'state2');
    mkdirSync(stateDir, { recursive: true });
    s.writeConfig({ state_dir: stateDir });
    const old = s.vault;
    chmodSync(s.stateDir, 0o555);
    try {
      const r = await s.save(fakeVault(100), { baseRev: sha256(old) });
      assertError(r, 500, 'write_failed');
    } finally {
      chmodSync(s.stateDir, 0o755);
      s.writeConfig();
    }
    assert.ok(s.readVault().equals(old));
  });
});
