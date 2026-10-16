// Builds dist/: esbuild bundles (IIFE) + static files + a copy of server/ (minus runtime/secret files).
import { build } from 'esbuild';
import { cp, mkdir, readFile, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dist = path.join(root, 'dist');
const srcDir = path.join(root, 'src');
const serverDir = path.join(root, 'server');

// kdbxweb's UMD bundle eagerly require()s "crypto" and "@xmldom/xmldom", but only uses them when
// globalThis.crypto.subtle / DOMParser are missing (Node). In the browser both become empty modules.
export const browserShims = {
  name: 'kdbxweb-browser-shims',
  setup(b) {
    b.onResolve({ filter: /^(crypto|@xmldom\/xmldom)$/ }, (args) => ({ path: args.path, namespace: 'empty-shim' }));
    b.onLoad({ filter: /.*/, namespace: 'empty-shim' }, () => ({ contents: 'module.exports = {};', loader: 'js' }));
    // webpack's global-object helper has a dead `new Function('return this')()` fallback (only used if
    // globalThis is missing). Replace it so the bundle contains no eval-like code under a strict CSP.
    b.onLoad({ filter: /[\\/]kdbxweb[\\/]dist[\\/]kdbxweb\.js$/ }, async (args) => {
      const code = await readFile(args.path, 'utf8');
      const needle = "new Function('return this')()";
      if (!code.includes(needle)) throw new Error('kdbxweb bundle changed: global shim not found');
      return { contents: code.replace(needle, 'globalThis'), loader: 'js' };
    });
  },
};

// Never ship secrets / runtime state from server/ (data/config.php, the vault, lockout, backups).
export function serverFilter(src, base = serverDir) {
  const rel = path.relative(base, src).split(path.sep).join('/');
  if (rel === '') return true;
  const name = path.posix.basename(rel);
  if (rel === 'data/config.php') return false;
  if (name === 'backups' || rel.includes('/backups/') || rel.startsWith('backups/')) return false;
  if (name === 'lockout.json' || name.endsWith('.kdbx') || name.endsWith('.lock')) return false;
  return true;
}

async function exists(p) {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}

/** esbuild options shared by the build and the bundle tests. */
export const bundleOptions = {
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: ['es2020'],
  minify: true,
  charset: 'utf8',
  legalComments: 'eof',
  sourcemap: false,
  plugins: [browserShims],
  logLevel: 'warning',
};

export async function main() {
  await rm(dist, { recursive: true, force: true });
  await mkdir(dist, { recursive: true });

  await build({
    entryPoints: { app: path.join(srcDir, 'app.js'), setup: path.join(srcDir, 'setup.js') },
    outdir: dist,
    ...bundleOptions,
  });

  for (const file of ['index.html', 'setup.html', 'style.css']) {
    await cp(path.join(srcDir, file), path.join(dist, file));
  }

  if (await exists(serverDir)) {
    await cp(serverDir, dist, { recursive: true, filter: (src) => serverFilter(src) });
  }

  const files = ['app.js', 'setup.js', 'index.html', 'setup.html', 'style.css'];
  for (const f of files) {
    const s = await stat(path.join(dist, f));
    console.log(`dist/${f.padEnd(12)} ${(s.size / 1024).toFixed(1).padStart(7)} KiB`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
