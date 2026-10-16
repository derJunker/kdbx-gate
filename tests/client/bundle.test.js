import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { DOMParser, XMLSerializer } from '@xmldom/xmldom';
import { main as buildDist, bundleOptions, serverFilter } from '../../scripts/build.mjs';
import { makeDb, PASSWORD, kdbxweb } from './helpers.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const dist = path.join(root, 'dist');
const EVAL_LIKE = /\beval\s*\(|new\s+Function\b|\bFunction\s*\(/;

async function exists(p) {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}

test('npm run build output: bundles exist, no eval-like code, CSP-clean HTML', async () => {
  await buildDist();
  for (const f of ['app.js', 'setup.js', 'index.html', 'setup.html', 'style.css']) {
    assert.ok(await exists(path.join(dist, f)), `dist/${f} missing`);
  }
  for (const f of ['app.js', 'setup.js']) {
    const code = await readFile(path.join(dist, f), 'utf8');
    assert.ok(code.length > 50000, `${f} suspiciously small`);
    assert.doesNotMatch(code, EVAL_LIKE, `${f} contains eval-like code`);
    assert.doesNotMatch(code, /\brequire\(["'](crypto|@xmldom\/xmldom)["']\)/, `${f} still requires node modules`);
  }
  // setup.js must not touch the network
  const setup = await readFile(path.join(dist, 'setup.js'), 'utf8');
  assert.doesNotMatch(setup, /\bfetch\(|XMLHttpRequest|sendBeacon|WebSocket/);

  for (const f of ['index.html', 'setup.html']) {
    const html = await readFile(path.join(dist, f), 'utf8');
    assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/i, `${f}: inline <script>`);
    assert.doesNotMatch(html, /<style/i, `${f}: <style> element`);
    assert.doesNotMatch(html, /\sstyle\s*=/i, `${f}: style attribute`);
    assert.doesNotMatch(html, /\son[a-z]+\s*=/i, `${f}: inline event handler`);
    assert.match(html, /name="viewport"/);
  }
  // server files are copied (when present) without secrets or runtime state
  if (await exists(path.join(root, 'server', 'api.php'))) assert.ok(await exists(path.join(dist, 'api.php')));
  if (await exists(path.join(root, 'server', '.htaccess'))) assert.ok(await exists(path.join(dist, '.htaccess')));
  const walk = async (dir) => (await readdir(dir, { withFileTypes: true })).flatMap((d) => [path.join(dir, d.name)]);
  const dataFiles = (await exists(path.join(dist, 'data'))) ? (await walk(path.join(dist, 'data'))).map((p) => path.basename(p)) : [];
  for (const forbidden of ['config.php', 'vault.kdbx', 'lockout.json', 'backups', 'vault.lock']) {
    assert.ok(!dataFiles.includes(forbidden), `dist/data/${forbidden} must not be shipped`);
  }
});

test('serverFilter excludes secrets and runtime files', () => {
  const s = path.join(root, 'server');
  const ok = (rel) => serverFilter(path.join(s, rel), s);
  assert.equal(ok(''), true);
  assert.equal(ok('api.php'), true);
  assert.equal(ok('.htaccess'), true);
  assert.equal(ok('data'), true);
  assert.equal(ok('data/.htaccess'), true);
  assert.equal(ok('data/config.sample.php'), true);
  assert.equal(ok('data/config.php'), false);
  assert.equal(ok('data/vault.kdbx'), false);
  assert.equal(ok('data/other.kdbx'), false);
  assert.equal(ok('data/lockout.json'), false);
  assert.equal(ok('data/vault.lock'), false);
  assert.equal(ok('data/backups'), false);
  assert.equal(ok('data/backups/vault-20260101-000000.kdbx'), false);
});

test('src: vault data is never written with innerHTML-like sinks', async () => {
  const dir = path.join(root, 'src');
  for (const f of await readdir(dir)) {
    if (!f.endsWith('.js')) continue;
    const code = await readFile(path.join(dir, f), 'utf8');
    assert.doesNotMatch(code, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function/, f);
  }
});

test('browser bundle (with node shims) opens AES-KDF and Argon2id vaults and derives tokens', async () => {
  const result = await build({
    ...bundleOptions,
    minify: false,
    write: false,
    globalName: 'KG',
    stdin: {
      contents: [
        "export { Vault, isInvalidKeyError } from './src/vault.js';",
        "export { deriveAuthToken } from './src/kdf.js';",
      ].join('\n'),
      resolveDir: root,
      sourcefile: 'bundle-test-entry.js',
    },
  });
  const code = result.outputFiles[0].text;
  assert.doesNotMatch(code, EVAL_LIKE);

  // Browsers have native DOMParser/XMLSerializer; xmldom stands in for them here.
  globalThis.DOMParser = DOMParser;
  globalThis.XMLSerializer = XMLSerializer;
  try {
    const KG = vm.runInThisContext(`(function () {\n${code}\nreturn KG;\n})()`, { filename: 'bundle.js' });

    const token = await KG.deriveAuthToken('correct horse ☃ Größe', { m: 1024, t: 1, p: 1, salt: 'AAECAwQFBgcICQoLDA0ODw==' });
    assert.equal(token, 'b6465b3b521f2109f007597f29b9708580344c52fcfaa231ddc4d1701fcb3d9b');

    for (const kdf of ['aes', 'argon2id']) {
      const bytes = await makeDb({ kdf });
      const vault = await KG.Vault.open(bytes, PASSWORD);
      assert.deepEqual(vault.listEntries().map((e) => e.title), ['GitHub', 'Mail', 'Visa']);
      const id = vault.listEntries()[0].id;
      vault.updateEntry(id, { password: 'from-bundle' });
      const saved = await vault.save();
      // the file written by the browser bundle opens with the stock (Node) kdbxweb
      const db = await kdbxweb.Kdbx.load(saved, new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(PASSWORD)));
      const entry = [...db.getDefaultGroup().allEntries()].find((e) => e.uuid.id === id);
      assert.equal(entry.fields.get('Password').getText(), 'from-bundle');
      await assert.rejects(KG.Vault.open(bytes, 'wrong'), (err) => KG.isInvalidKeyError(err));
    }
  } finally {
    delete globalThis.DOMParser;
    delete globalThis.XMLSerializer;
  }
});
