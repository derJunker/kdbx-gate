// Test harness for server/api.php: starts `php -S` on a private copy of server/
// with its own config, vault and state directory. Built-ins only (no npm deps).
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import {
  chmodSync, cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync,
  readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = fileURLToPath(new URL('../../', import.meta.url));
export const SERVER_DIR = join(ROOT, 'server');
export const API_PHP = join(SERVER_DIR, 'api.php');
export const KDBX_SIG = Buffer.from([0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5]);
export const IS_ROOT = typeof process.getuid === 'function' && process.getuid() === 0;

export const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
export const nowSec = () => Math.floor(Date.now() / 1000);
export const fakeVault = (size = 4096) => Buffer.concat([KDBX_SIG, randomBytes(size)]);
export const randomHex = (bytes = 32) => randomBytes(bytes).toString('hex');

export function phpAvailable() {
  const r = spawnSync('php', ['-v'], { encoding: 'utf8' });
  return r.status === 0;
}

function phpValue(v) {
  if (typeof v === 'number' || typeof v === 'boolean') return JSON.stringify(v);
  if (v === null) return 'null';
  return `'${String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}

/** Render a flat object as a PHP config file that returns an array. */
export function phpConfig(obj) {
  const lines = Object.entries(obj).map(([k, v]) => `    ${phpValue(k)} => ${phpValue(v)},`);
  return `<?php\nreturn [\n${lines.join('\n')}\n];\n`;
}

export function makeVerifier(token, salt, { m = 65536, t = 3, p = 1 } = {}) {
  return `v1$argon2id$m=${m},t=${t},p=${p}$${salt}$${sha256(token)}`;
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

/** Make everything below `dir` writable again so it can be removed. */
function restorePerms(dir) {
  try {
    chmodSync(dir, 0o700);
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      const st = lstatSync(p);
      if (st.isDirectory()) restorePerms(p);
      else if (!st.isSymbolicLink()) chmodSync(p, 0o600);
    }
  } catch {
    // best effort
  }
}

const running = new Set();
process.on('exit', () => {
  for (const child of running) {
    try { process.kill(-child.pid, 'SIGKILL'); } catch { /* already gone */ }
  }
});

async function spawnPhp(www, env) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const port = await freePort();
    const args = [
      '-d', 'display_errors=1', // api.php must switch this off itself
      '-d', 'display_startup_errors=1',
      '-d', 'error_reporting=-1',
      '-d', 'html_errors=0',
      '-d', 'expose_php=1', // api.php must remove X-Powered-By
      '-d', 'opcache.enable_cli=0', // tests rewrite config.php between requests
      '-d', 'post_max_size=8M',
      '-S', `127.0.0.1:${port}`, '-t', www,
    ];
    // detached => own process group, so the workers die together with the master
    const child = spawn('php', args, { env, stdio: ['ignore', 'pipe', 'pipe'], detached: true });
    let log = '';
    let exited = false;
    child.stdout.on('data', (d) => { log += d; });
    child.stderr.on('data', (d) => { log += d; });
    child.on('exit', () => { exited = true; });
    running.add(child);
    const base = `http://127.0.0.1:${port}`;
    const deadline = Date.now() + 10000;
    while (!exited && Date.now() < deadline) {
      try {
        await fetch(`${base}/api.php?a=__ready__`);
        return { child, base, port, getLog: () => log, clearLog: () => { log = ''; } };
      } catch {
        await sleep(40);
      }
    }
    try { process.kill(-child.pid, 'SIGKILL'); } catch { /* gone */ }
    running.delete(child);
    if (!/address already in use|Failed to listen/i.test(log)) {
      throw new Error(`php -S did not start:\n${log}`);
    }
  }
  throw new Error('php -S: no free port found');
}

/**
 * Start a server.
 * @param {object} opts
 * @param {object} [opts.config]       extra config keys (merged over {verifier})
 * @param {boolean} [opts.writeConfig] write config.php (default true)
 * @param {boolean} [opts.useEnv]      pass KDBX_GATE_CONFIG (default true); if false the
 *                                     config lives at www/data/config.php (the default path)
 * @param {number|false} [opts.vaultSize] size of the fake vault, false = no vault
 */
export async function startServer(opts = {}) {
  const { config = {}, writeConfig = true, useEnv = true, vaultSize = 4096 } = opts;
  const root = mkdtempSync(join(tmpdir(), 'kdbx-gate-test-'));
  const www = join(root, 'www');
  cpSync(SERVER_DIR, www, { recursive: true });
  // A developer's real data must never end up in (or influence) a test run.
  for (const f of ['config.php', 'vault.kdbx', 'lockout.json', 'lastlogin.json', 'vault.lock', 'backups']) {
    rmSync(join(www, 'data', f), { recursive: true, force: true });
  }
  const stateRoot = join(root, 'state');
  mkdirSync(stateRoot);

  const configPath = useEnv ? join(stateRoot, 'config.php') : join(www, 'data', 'config.php');
  const stateDir = dirname(configPath); // default state_dir = directory of config.php
  const vaultPath = join(stateDir, 'vault.kdbx'); // default vault_file
  const token = randomBytes(32);
  const tokenHex = token.toString('hex');
  const salt = randomBytes(16).toString('base64');
  const verifier = makeVerifier(token, salt);

  const s = {
    root, www, stateDir, configPath, vaultPath, tokenHex, salt, verifier,
    lockoutPath: join(stateDir, 'lockout.json'),
    lastLoginPath: join(stateDir, 'lastlogin.json'),
    backupsDir: join(stateDir, 'backups'),
    vault: null,
  };

  s.writeConfig = (extra = {}) => writeFileSync(configPath, phpConfig({ verifier, ...config, ...extra }));
  s.writeRawConfig = (text) => writeFileSync(configPath, text);
  s.writeVault = (buf) => { writeFileSync(vaultPath, buf); s.vault = buf; return buf; };
  s.readVault = () => readFileSync(vaultPath);
  s.readStateRaw = () => (existsSync(s.lockoutPath) ? readFileSync(s.lockoutPath, 'utf8') : null);
  s.readState = () => { const raw = s.readStateRaw(); return raw === null ? null : JSON.parse(raw); };
  s.writeState = (obj) => writeFileSync(s.lockoutPath, typeof obj === 'string' ? obj : JSON.stringify(obj));
  s.resetState = () => rmSync(s.lockoutPath, { force: true });
  s.backups = () => (existsSync(s.backupsDir) ? readdirSync(s.backupsDir).sort() : []);
  s.tempFiles = () => readdirSync(dirname(vaultPath)).filter((n) => n.includes('.tmp-'));

  if (writeConfig) s.writeConfig();
  if (vaultSize !== false) s.writeVault(fakeVault(vaultSize));

  const env = { ...process.env, PHP_CLI_SERVER_WORKERS: '8' };
  delete env.KDBX_GATE_CONFIG;
  if (useEnv) env.KDBX_GATE_CONFIG = configPath;
  const proc = await spawnPhp(www, env);
  s.base = proc.base;
  s.getLog = proc.getLog;
  s.clearLog = proc.clearLog;

  /**
   * Raw request. `action` null => no query string; `query` overrides the query string.
   * Every response is checked for the mandatory headers, and JSON bodies are parsed
   * strictly (a leaked PHP warning would make JSON.parse throw).
   */
  s.request = async (action, { method = 'GET', token, baseRev, body, headers = {}, query } = {}) => {
    const h = new Headers(headers);
    if (token !== undefined && token !== null) h.set('X-Vault-Token', token);
    if (baseRev !== undefined && baseRev !== null) h.set('X-Vault-Base-Rev', baseRev);
    if (body !== undefined && !h.has('content-type')) h.set('Content-Type', 'application/octet-stream');
    const qs = query !== undefined ? query : action === null ? '' : `a=${encodeURIComponent(action)}`;
    const init = { method, headers: h };
    if (body !== undefined) {
      init.body = body;
      if (typeof body.getReader === 'function') init.duplex = 'half';
    }
    const res = await fetch(`${s.base}/api.php${qs ? `?${qs}` : ''}`, init);
    const buf = Buffer.from(await res.arrayBuffer());
    assertCommonHeaders(res);
    const ct = res.headers.get('content-type');
    let json = null;
    if (ct === 'application/json; charset=utf-8') {
      json = JSON.parse(buf.toString('utf8'));
    } else {
      assert.equal(ct, 'application/octet-stream', `unexpected content-type ${ct}: ${buf.toString('utf8', 0, 300)}`);
      assert.equal(res.status, 200);
    }
    return { status: res.status, headers: res.headers, body: buf, json };
  };
  s.params = () => s.request('params');
  s.status = () => s.request('status');
  s.open = (token = tokenHex) => s.request('open', { method: 'POST', token });
  s.save = (body, { token = tokenHex, baseRev = sha256(s.readVault()), headers } = {}) =>
    s.request('save', { method: 'POST', token, baseRev, body, headers });
  /** n wrong-token open requests, sequentially. */
  s.fail = async (n = 1) => {
    const out = [];
    for (let i = 0; i < n; i++) out.push(await s.open(randomHex()));
    return out;
  };

  s.stop = async () => {
    const { child } = proc;
    if (child.exitCode === null && child.signalCode === null) {
      const done = new Promise((resolve) => child.once('exit', resolve));
      try { process.kill(-child.pid, 'SIGTERM'); } catch { /* gone */ }
      const timer = setTimeout(() => { try { process.kill(-child.pid, 'SIGKILL'); } catch { /* gone */ } }, 2000);
      await done;
      clearTimeout(timer);
    }
    running.delete(child);
    restorePerms(root);
    rmSync(root, { recursive: true, force: true });
  };
  return s;
}

export function assertCommonHeaders(res) {
  const h = res.headers;
  assert.equal(h.get('cache-control'), 'no-store');
  assert.equal(h.get('x-content-type-options'), 'nosniff');
  assert.equal(h.get('referrer-policy'), 'no-referrer');
  assert.equal(h.get('x-powered-by'), null, 'X-Powered-By must be removed');
  for (const name of h.keys()) {
    assert.ok(!name.startsWith('access-control-'), `unexpected CORS header ${name}`);
  }
}

/** Assert a JSON error response. */
export function assertError(res, status, error) {
  assert.equal(res.status, status, `expected ${status} ${error}, got ${res.status} ${JSON.stringify(res.json)}`);
  assert.ok(res.json, 'expected a JSON body');
  assert.equal(res.json.error, error);
}
