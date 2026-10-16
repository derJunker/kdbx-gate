// Real Apache check of server/.htaccess and server/data/.htaccess (php -S ignores
// .htaccess). Runs a throwaway, unprivileged httpd if one is installed; skipped
// otherwise. PHP is not wired into this Apache: only static access rules and
// headers are tested here.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SERVER_DIR, sleep } from './harness.mjs';

const HTTPD = ['/usr/sbin/httpd', '/usr/sbin/apache2'].find((p) => existsSync(p));
const MODULES = ['/usr/lib64/httpd/modules', '/usr/lib/apache2/modules'].find((p) => existsSync(p));
const NEEDED = ['mpm_prefork', 'unixd', 'authz_core', 'headers', 'dir', 'mime', 'alias', 'autoindex'];
const missing = !HTTPD || !MODULES || NEEDED.some((m) => !existsSync(join(MODULES, `mod_${m}.so`)));

const CSP = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

describe('apache: .htaccess', { skip: missing ? 'no usable httpd found' : false }, () => {
  let tmp;
  let child;
  let base;
  let startError = null;

  before(async () => {
    tmp = mkdtempSync(join(tmpdir(), 'kdbx-gate-apache-'));
    const www = join(tmp, 'www');
    cpSync(SERVER_DIR, www, { recursive: true });
    const files = {
      'index.html': '<!doctype html><title>t</title>INDEX',
      'data/vault.kdbx': 'VAULT', 'data/config.php': '<?php return [];', 'data/lockout.json': '{}',
      'data/backups/vault-20260101-000000.kdbx': 'OLD', 'data/anything.txt': 'x',
      'stray.kdbx': 'x', 'sub/upper.KDBX': 'x', 'foo.json': '{}', 'vault.lock': '', 'sub/.vault.kdbx.tmp-1': 'x',
      '.hidden': 'x', '.user.ini': 'x', '.git/config': 'x', '.well-known/acme-challenge/tok': 'ACME',
      'app.js': 'console.log(1)', 'emptydir/.keep': '',
    };
    for (const [name, content] of Object.entries(files)) {
      mkdirSync(join(www, name, '..'), { recursive: true });
      writeFileSync(join(www, name), content);
    }
    const port = await freePort();
    base = `http://127.0.0.1:${port}`;
    const conf = join(tmp, 'httpd.conf');
    writeFileSync(conf, [
      `ServerRoot "${tmp}"`,
      `Listen 127.0.0.1:${port}`,
      'ServerName 127.0.0.1',
      `PidFile "${tmp}/httpd.pid"`,
      `ErrorLog "${tmp}/error.log"`,
      'LogLevel warn',
      ...NEEDED.map((m) => `LoadModule ${m}_module "${MODULES}/mod_${m}.so"`),
      existsSync('/etc/mime.types') ? 'TypesConfig /etc/mime.types' : `TypesConfig "${conf}"`,
      'StartServers 1', 'MinSpareServers 1', 'MaxSpareServers 2',
      `DocumentRoot "${www}"`,
      '<Directory />', '  AllowOverride None', '  Require all denied', '</Directory>',
      `<Directory "${www}">`, '  AllowOverride All', '  Options Indexes FollowSymLinks', '  Require all granted', '</Directory>',
      '',
    ].join('\n'));
    child = spawn(HTTPD, ['-f', conf, '-DFOREGROUND'], { stdio: ['ignore', 'pipe', 'pipe'], detached: true });
    let log = '';
    child.stdout.on('data', (d) => { log += d; });
    child.stderr.on('data', (d) => { log += d; });
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline && child.exitCode === null) {
      try {
        await fetch(`${base}/`);
        return;
      } catch {
        await sleep(50);
      }
    }
    startError = `httpd did not start: ${log}`;
  });

  after(() => {
    if (child && child.exitCode === null) {
      try { process.kill(-child.pid, 'SIGKILL'); } catch { /* gone */ }
    }
    if (tmp) rmSync(tmp, { recursive: true, force: true });
  });

  async function get(path, method = 'GET') {
    if (startError) throw new Error(startError);
    const res = await fetch(`${base}${path}`, { method, redirect: 'manual' });
    const body = await res.text();
    return { status: res.status, headers: res.headers, body };
  }

  test('index is served with all security headers', async () => {
    const r = await get('/');
    assert.equal(r.status, 200, r.body);
    assert.match(r.body, /INDEX/);
    assert.equal(r.headers.get('content-security-policy'), CSP);
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
    assert.equal(r.headers.get('permissions-policy'), 'camera=(), microphone=(), geolocation=()');
    assert.equal((await get('/app.js')).status, 200);
  });

  test('data/ is never served (GET and HEAD)', async () => {
    for (const p of ['/data/', '/data/vault.kdbx', '/data/config.php', '/data/lockout.json',
      '/data/backups/vault-20260101-000000.kdbx', '/data/anything.txt', '/data/config.sample.php', '/data/.htaccess']) {
      for (const method of ['GET', 'HEAD']) {
        const r = await get(p, method);
        assert.equal(r.status, 403, `${method} ${p} => ${r.status}`);
        if (method === 'GET') assert.doesNotMatch(r.body, /VAULT|OLD/);
      }
    }
  });

  test('*.kdbx, *.json, *.lock and dotfiles are denied anywhere', async () => {
    for (const p of ['/stray.kdbx', '/sub/upper.KDBX', '/foo.json', '/vault.lock', '/sub/.vault.kdbx.tmp-1',
      '/.hidden', '/.user.ini', '/.htaccess', '/.git/config']) {
      const r = await get(p);
      assert.ok([403, 404].includes(r.status), `${p} => ${r.status}`);
    }
  });

  test('error responses carry the security headers too', async () => {
    const r = await get('/stray.kdbx');
    assert.equal(r.headers.get('content-security-policy'), CSP);
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
  });

  test('no directory listing; .well-known stays reachable', async () => {
    assert.equal((await get('/emptydir/')).status, 403);
    const acme = await get('/.well-known/acme-challenge/tok');
    assert.equal(acme.status, 200);
    assert.equal(acme.body, 'ACME');
  });
});
