// Static checks: PHP syntax, PHP 7.4 compatibility, .htaccess structure.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { API_PHP, SERVER_DIR } from './harness.mjs';

const php = (args, input) => spawnSync('php', args, { encoding: 'utf8', input });

describe('static checks', () => {
  test('php -l server/api.php', () => {
    const r = php(['-l', API_PHP]);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /No syntax errors/);
  });

  test('php -l server/data/config.sample.php, and it returns an array with every key', () => {
    const sample = join(SERVER_DIR, 'data', 'config.sample.php');
    const lint = php(['-l', sample]);
    assert.equal(lint.status, 0, lint.stdout + lint.stderr);
    const r = php(['-r', 'echo json_encode(array_keys(include $argv[1]));', sample]);
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout).sort(), [
      'delay_seconds', 'free_attempts', 'keep_backups', 'max_vault_bytes', 'state_dir', 'vault_file', 'verifier',
    ]);
  });

  test('api.php switches display_errors off before anything else', () => {
    const src = readFileSync(API_PHP, 'utf8');
    assert.match(src, /^<\?php\s*(\/\*[\s\S]*?\*\/\s*)?ini_set\('display_errors', '0'\);/);
  });

  test('api.php uses no PHP 8-only syntax or functions (must run on PHP 7.4)', () => {
    // Tokenize with the local PHP and look for constructs PHP 7.4 cannot parse/run.
    const checker = String.raw`
      $tokens = token_get_all(file_get_contents($argv[1]));
      $bad = array();
      $badTokens = array('T_MATCH', 'T_NULLSAFE_OBJECT_OPERATOR', 'T_ENUM', 'T_READONLY', 'T_ATTRIBUTE');
      $badNames = array('str_starts_with', 'str_ends_with', 'str_contains', 'array_is_list', 'get_debug_type',
                        'fdiv', 'get_resource_id', 'preg_last_error_msg', 'array_find', 'array_any', 'array_all',
                        'mixed', 'never');
      $n = count($tokens);
      for ($i = 0; $i < $n; $i++) {
        $t = $tokens[$i];
        if (!is_array($t)) {
          // first-class callable syntax: foo(...)
          if ($t === '(' && isset($tokens[$i + 1][0], $tokens[$i + 2]) && $tokens[$i + 1][0] === T_ELLIPSIS && $tokens[$i + 2] === ')') {
            $bad[] = 'first-class callable';
          }
          continue;
        }
        $name = token_name($t[0]);
        if (in_array($name, $badTokens, true)) $bad[] = $name . ' on line ' . $t[2];
        if ($t[0] === T_STRING && in_array(strtolower($t[1]), $badNames, true)) $bad[] = $t[1] . ' on line ' . $t[2];
        if ($t[0] === T_CATCH) {
          // catch without a variable is PHP 8.0+
          for ($j = $i + 1; $j < $n && $tokens[$j] !== ')'; $j++) {}
          $hasVar = false;
          for ($k = $i + 1; $k < $j; $k++) if (is_array($tokens[$k]) && $tokens[$k][0] === T_VARIABLE) $hasVar = true;
          if (!$hasVar) $bad[] = 'catch without variable on line ' . $t[2];
        }
      }
      echo json_encode($bad);
    `;
    const r = php(['-r', checker, API_PHP]);
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout), []);
    // fsync() is PHP 8.1+: it may only be used behind function_exists().
    const src = readFileSync(API_PHP, 'utf8');
    const calls = src.match(/@?fsync\(/g) || [];
    const guards = src.match(/function_exists\('fsync'\)/g) || [];
    assert.ok(guards.length >= 1 && calls.length <= guards.length, 'fsync must be guarded');
  });

  function balanced(text, tag) {
    text = text.split('\n').filter((l) => !l.trim().startsWith('#')).join('\n');
    const open = (text.match(new RegExp(`<${tag}[\\s>]`, 'g')) || []).length;
    const close = (text.match(new RegExp(`</${tag}>`, 'g')) || []).length;
    return open === close;
  }

  test('server/.htaccess: required directives, balanced blocks, no forced HTTPS', () => {
    const t = readFileSync(join(SERVER_DIR, '.htaccess'), 'utf8');
    for (const tag of ['IfModule', 'FilesMatch']) assert.ok(balanced(t, tag), `unbalanced <${tag}>`);
    assert.match(t, /^Options -Indexes$/m);
    assert.match(t, /^DirectoryIndex index\.html$/m);
    assert.match(t, /<FilesMatch "\(\?i\)\\\.\(kdbx\|json\|lock\)\$">/);
    assert.match(t, /<FilesMatch "\^\\\.">/);
    assert.ok(t.includes(
      `Content-Security-Policy "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'"`,
    ));
    assert.match(t, /X-Frame-Options "DENY"/);
    assert.match(t, /X-Content-Type-Options "nosniff"/);
    assert.match(t, /Referrer-Policy "no-referrer"/);
    assert.match(t, /Permissions-Policy "camera=\(\), microphone=\(\), geolocation=\(\)"/);
    assert.ok(!/RewriteRule[^\n]*https/i.test(t) && !/Redirect(Match)?\s+(30\d|permanent)/i.test(t), 'no HTTPS redirect');
    // Every module-specific directive must sit inside an <IfModule>.
    let depth = 0;
    for (const line of t.split('\n').map((l) => l.trim())) {
      if (line.startsWith('<IfModule')) depth++;
      else if (line.startsWith('</IfModule>')) depth--;
      else if (/^(Header|Require|Order|Deny|Allow|RedirectMatch|Rewrite\w*|php_\w+)\b/.test(line)) {
        assert.ok(depth > 0, `not guarded by <IfModule>: ${line}`);
      }
    }
  });

  test('server/data/.htaccess denies everything on Apache 2.2 and 2.4', () => {
    const t = readFileSync(join(SERVER_DIR, 'data', '.htaccess'), 'utf8');
    assert.ok(balanced(t, 'IfModule'));
    assert.match(t, /<IfModule mod_authz_core\.c>\s*Require all denied\s*<\/IfModule>/);
    assert.match(t, /<IfModule !mod_authz_core\.c>\s*Order deny,allow\s*Deny from all\s*<\/IfModule>/);
  });
});
