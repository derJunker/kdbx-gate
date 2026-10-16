<?php
/*
 * kdbx-gate: api.php
 *
 * The only server-side code of kdbx-gate. Single file, no Composer, no extensions
 * beyond what every PHP build ships (hash, json, pcre). Deliberately written in
 * PHP 7.4-compatible syntax so it runs on old shared hosting.
 *
 * The binding contract is docs/SPEC.md. Actions (query parameter "a"):
 *   GET  api.php?a=params   public Argon2id parameters and salt
 *   GET  api.php?a=status   lockout status (read-only)
 *   POST api.php?a=open     gate, then stream the .kdbx
 *   POST api.php?a=save     gate, then replace the .kdbx (conflict check + backup)
 *
 * Security notes:
 *   - Every error path fails closed: if the lockout state cannot be read, locked or
 *     written, the vault is never served (500 {"error":"state_error"}).
 *   - PHP warnings are never shown to the client (display_errors is off and all
 *     file system calls check their return values).
 */

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
ini_set('html_errors', '0');
ini_set('zlib.output_compression', '0');
error_reporting(E_ALL);
if (function_exists('header_remove')) {
    header_remove('X-Powered-By');
}
if (function_exists('ignore_user_abort')) {
    // A client disconnect must never interrupt a state or vault update half-way.
    ignore_user_abort(true);
}

define('KG_KDBX_SIGNATURE', "\x03\xD9\xA2\x9A\x67\xFB\x4B\xB5");
define('KG_CHUNK', 65536);

/** Temp files to delete if the request ends early (see kg_shutdown). */
$GLOBALS['kg_cleanup'] = array();
register_shutdown_function('kg_shutdown');

/* ------------------------------------------------------------------------ */
/* Responses                                                                */
/* ------------------------------------------------------------------------ */

function kg_discard_output()
{
    while (ob_get_level() > 0) {
        if (!@ob_end_clean()) {
            break;
        }
    }
}

function kg_common_headers()
{
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
}

/**
 * Send a JSON response and end the request.
 *
 * @param int   $status
 * @param array $body
 * @param array $extraHeaders list of "Name: value" strings
 */
function kg_json($status, $body, $extraHeaders = array())
{
    kg_discard_output();
    if (!headers_sent()) {
        http_response_code($status);
        kg_common_headers();
        header('Content-Type: application/json; charset=utf-8');
        foreach ($extraHeaders as $h) {
            header($h);
        }
    }
    echo json_encode($body, JSON_UNESCAPED_SLASHES);
    exit;
}

function kg_error($status, $code)
{
    kg_json($status, array('error' => $code));
}

function kg_shutdown()
{
    if (isset($GLOBALS['kg_cleanup']) && is_array($GLOBALS['kg_cleanup'])) {
        foreach ($GLOBALS['kg_cleanup'] as $file) {
            if (is_string($file) && $file !== '' && @is_file($file)) {
                @unlink($file);
            }
        }
    }
    $e = error_get_last();
    $fatal = E_ERROR | E_PARSE | E_CORE_ERROR | E_COMPILE_ERROR | E_USER_ERROR | E_RECOVERABLE_ERROR;
    if (is_array($e) && ($e['type'] & $fatal) && !headers_sent()) {
        kg_discard_output();
        http_response_code(500);
        kg_common_headers();
        header('Content-Type: application/json; charset=utf-8');
        echo '{"error":"server_error"}';
    }
}

/* ------------------------------------------------------------------------ */
/* Configuration                                                            */
/* ------------------------------------------------------------------------ */

function kg_config_path()
{
    $env = getenv('KDBX_GATE_CONFIG');
    if (is_string($env) && $env !== '') {
        return $env;
    }
    return __DIR__ . '/data/config.php';
}

/** Include the config file in an isolated scope, swallowing any stray output. */
function kg_include_config($kgFile)
{
    ob_start();
    try {
        $kgResult = include $kgFile;
    } catch (Throwable $e) {
        $kgResult = null;
    }
    ob_end_clean();
    return $kgResult;
}

/**
 * Parse "v1$argon2id$m=..,t=..,p=..$<salt b64>$<sha256 hex>".
 * Returns array(m, t, p, salt, verifier_hex) or null if anything is off.
 */
function kg_parse_verifier($s)
{
    $re = '#^v1\$argon2id\$m=([1-9][0-9]{0,8}),t=([1-9][0-9]{0,8}),p=([1-9][0-9]{0,8})'
        . '\$([A-Za-z0-9+/]+={0,2})\$([0-9a-fA-F]{64})\z#';
    if (!is_string($s) || !preg_match($re, $s, $mm)) {
        return null;
    }
    $m = (int) $mm[1];
    $t = (int) $mm[2];
    $p = (int) $mm[3];
    if ($m < 8 * $p) {
        return null; // Argon2 requires m >= 8 * p
    }
    $salt = base64_decode($mm[4], true);
    if ($salt === false || base64_encode($salt) !== $mm[4]) {
        return null; // not canonical, padded standard base64
    }
    $len = strlen($salt);
    if ($len < 8 || $len > 64) {
        return null;
    }
    return array(
        'm' => $m,
        't' => $t,
        'p' => $p,
        'salt' => $mm[4],
        'verifier_hex' => strtolower($mm[5]),
    );
}

/** Optional integer option; returns null if present but invalid. */
function kg_opt_int($raw, $key, $default, $min)
{
    if (!array_key_exists($key, $raw) || $raw[$key] === null) {
        return $default;
    }
    $v = $raw[$key];
    if (is_string($v) && preg_match('/^[0-9]{1,15}\z/', $v)) {
        $v = (int) $v;
    } elseif (is_float($v) && is_finite($v) && floor($v) === $v && abs($v) < 9.0e15) {
        $v = (int) $v;
    }
    if (!is_int($v) || $v < $min) {
        return null;
    }
    return $v;
}

/** Optional path option; returns null if present but invalid. */
function kg_opt_path($raw, $key, $default)
{
    if (!array_key_exists($key, $raw) || $raw[$key] === null) {
        return $default;
    }
    $v = $raw[$key];
    if (!is_string($v) || $v === '' || strpos($v, "\0") !== false) {
        return null;
    }
    return $v;
}

/**
 * Load and validate the configuration. Returns the normalized config array or
 * null (=> 503 not_configured). Invalid optional keys also yield null: a broken
 * config must never silently weaken the gate.
 */
function kg_load_config()
{
    $path = kg_config_path();
    clearstatcache();
    if (!@is_file($path) || !@is_readable($path)) {
        return null;
    }
    $raw = kg_include_config($path);
    if (!is_array($raw) || !isset($raw['verifier'])) {
        return null;
    }
    $cfg = kg_parse_verifier($raw['verifier']);
    if ($cfg === null) {
        return null;
    }
    // Defaults are relative to the config file, exactly like the __DIR__-based
    // values in config.sample.php.
    $dir = dirname($path);
    $cfg['vault_file'] = kg_opt_path($raw, 'vault_file', $dir . '/vault.kdbx');
    $cfg['state_dir'] = kg_opt_path($raw, 'state_dir', $dir);
    $cfg['free_attempts'] = kg_opt_int($raw, 'free_attempts', 3, 0);
    $cfg['delay_seconds'] = kg_opt_int($raw, 'delay_seconds', 60, 1);
    $cfg['max_vault_bytes'] = kg_opt_int($raw, 'max_vault_bytes', 20 * 1024 * 1024, 8);
    $cfg['keep_backups'] = kg_opt_int($raw, 'keep_backups', 10, 0);
    foreach ($cfg as $value) {
        if ($value === null) {
            return null;
        }
    }
    return $cfg;
}

/* ------------------------------------------------------------------------ */
/* Lockout state                                                            */
/* ------------------------------------------------------------------------ */

/** Returns array(fails, last), a fresh state for an empty file, or null if corrupt. */
function kg_parse_state($raw)
{
    if (trim($raw) === '') {
        return array('fails' => 0, 'last' => 0);
    }
    $d = json_decode($raw, true);
    if (!is_array($d) || !isset($d['fails'], $d['last'])
        || !is_int($d['fails']) || !is_int($d['last'])
        || $d['fails'] < 0 || $d['last'] < 0) {
        return null;
    }
    return array('fails' => $d['fails'], 'last' => $d['last']);
}

/** State to assume when lockout.json is corrupt: locked, starting now (fail closed). */
function kg_locked_state($cfg, $now)
{
    return array('fails' => $cfg['free_attempts'], 'last' => $now);
}

/** Seconds until the next attempt is allowed (0 = allowed now). */
function kg_retry_after($state, $cfg, $now)
{
    if ($state['fails'] < $cfg['free_attempts']) {
        return 0;
    }
    $elapsed = $now - $state['last'];
    if ($elapsed < 0) {
        $elapsed = 0;
    }
    if ($elapsed >= $cfg['delay_seconds']) {
        return 0;
    }
    return $cfg['delay_seconds'] - $elapsed;
}

/**
 * Overwrite the state in place (the handle is locked). The new content is written
 * first and the file truncated afterwards, so it is never observed empty.
 */
function kg_write_state($fh, $state)
{
    $json = json_encode(array('fails' => $state['fails'], 'last' => $state['last']));
    if (!is_string($json) || !@rewind($fh)) {
        return false;
    }
    $len = strlen($json);
    if (@fwrite($fh, $json) !== $len) {
        return false;
    }
    if (!@ftruncate($fh, $len) || !@fflush($fh)) {
        return false;
    }
    return true;
}

function kg_release($fh)
{
    @flock($fh, LOCK_UN);
    @fclose($fh);
}

function kg_state_fail($fh)
{
    if (is_resource($fh)) {
        kg_release($fh);
    }
    kg_error(500, 'state_error');
}

/**
 * The gate (SPEC "Lockout algorithm"). Returns only if the token is valid;
 * otherwise it sends 401/429/500 and ends the request. The whole
 * check -> verify -> update sequence runs under an exclusive flock.
 */
function kg_gate($cfg)
{
    $fh = @fopen($cfg['state_dir'] . '/lockout.json', 'c+');
    if ($fh === false) {
        kg_error(500, 'state_error');
    }
    if (!@flock($fh, LOCK_EX)) {
        @fclose($fh);
        kg_error(500, 'state_error');
    }
    $raw = @stream_get_contents($fh);
    if (!is_string($raw)) {
        kg_state_fail($fh);
    }

    $now = time();
    $dirty = false;
    $state = kg_parse_state($raw);
    if ($state === null) {
        $state = kg_locked_state($cfg, $now);
        $dirty = true;
    } elseif ($state['last'] > $now) {
        // The clock went backwards: do not stay locked longer than one delay.
        $state['last'] = $now;
        $dirty = true;
    }

    $retry = kg_retry_after($state, $cfg, $now);
    if ($retry > 0) {
        // Locked: the token is not looked at and the state is not changed
        // (except to persist a repair of a corrupt/future-dated state).
        if ($dirty && !kg_write_state($fh, $state)) {
            kg_state_fail($fh);
        }
        kg_release($fh);
        kg_json(429, array('error' => 'locked', 'retryAfter' => $retry), array('Retry-After: ' . $retry));
    }

    $token = isset($_SERVER['HTTP_X_VAULT_TOKEN']) ? $_SERVER['HTTP_X_VAULT_TOKEN'] : null;
    $ok = false;
    if (is_string($token) && preg_match('/^[0-9a-f]{64}\z/', $token)) {
        $ok = hash_equals($cfg['verifier_hex'], hash('sha256', hex2bin($token)));
    }

    if ($ok) {
        if ($state['fails'] !== 0 || $dirty) {
            $state['fails'] = 0;
            if (!kg_write_state($fh, $state)) {
                kg_state_fail($fh);
            }
        }
        kg_release($fh);
        return;
    }

    $state['fails'] = $state['fails'] + 1;
    $state['last'] = $now;
    if (!kg_write_state($fh, $state)) {
        kg_state_fail($fh);
    }
    kg_release($fh);
    $left = max(0, $cfg['free_attempts'] - $state['fails']);
    kg_json(401, array(
        'error' => 'bad_token',
        'attemptsLeft' => $left,
        'retryAfter' => $left > 0 ? 0 : $cfg['delay_seconds'],
    ));
}

/* ------------------------------------------------------------------------ */
/* Actions                                                                  */
/* ------------------------------------------------------------------------ */

function kg_action_params($cfg)
{
    kg_json(200, array(
        'kdf' => 'argon2id',
        'm' => $cfg['m'],
        't' => $cfg['t'],
        'p' => $cfg['p'],
        'salt' => $cfg['salt'],
    ));
}

function kg_action_status($cfg)
{
    clearstatcache();
    if (!@is_dir($cfg['state_dir'])) {
        kg_error(500, 'state_error');
    }
    $path = $cfg['state_dir'] . '/lockout.json';
    $now = time();
    $state = array('fails' => 0, 'last' => 0);
    if (@file_exists($path)) {
        // Read-only: never creates or modifies the state file.
        $fh = @fopen($path, 'r');
        if ($fh === false) {
            kg_error(500, 'state_error');
        }
        if (!@flock($fh, LOCK_SH)) {
            @fclose($fh);
            kg_error(500, 'state_error');
        }
        $raw = @stream_get_contents($fh);
        kg_release($fh);
        if (!is_string($raw)) {
            kg_error(500, 'state_error');
        }
        $state = kg_parse_state($raw);
        if ($state === null) {
            $state = kg_locked_state($cfg, $now);
        } elseif ($state['last'] > $now) {
            $state['last'] = $now;
        }
    }
    kg_json(200, array(
        'retryAfter' => kg_retry_after($state, $cfg, $now),
        'attemptsLeft' => max(0, $cfg['free_attempts'] - $state['fails']),
    ));
}

function kg_action_open($cfg)
{
    kg_gate($cfg);

    $path = $cfg['vault_file'];
    clearstatcache();
    if (!@is_file($path)) {
        kg_error(404, 'no_vault');
    }
    // Hash and send from the same handle: a concurrent save replaces the file via
    // rename(), so this handle keeps pointing at one consistent version and the
    // X-Vault-Rev header always matches the bytes sent.
    $fh = @fopen($path, 'rb');
    if ($fh === false) {
        kg_error(500, 'server_error');
    }
    $ctx = hash_init('sha256');
    $size = 0;
    while (true) {
        $chunk = @fread($fh, KG_CHUNK);
        if ($chunk === false) {
            @fclose($fh);
            kg_error(500, 'server_error');
        }
        if ($chunk === '') {
            break;
        }
        hash_update($ctx, $chunk);
        $size += strlen($chunk);
    }
    $rev = hash_final($ctx);
    if (!@rewind($fh)) {
        @fclose($fh);
        kg_error(500, 'server_error');
    }

    kg_discard_output();
    http_response_code(200);
    kg_common_headers();
    header('Content-Type: application/octet-stream');
    header('Content-Length: ' . $size);
    header('X-Vault-Rev: ' . $rev);
    $sent = 0;
    while ($sent < $size) {
        $chunk = @fread($fh, min(KG_CHUNK, $size - $sent));
        if ($chunk === false || $chunk === '') {
            break;
        }
        echo $chunk;
        $sent += strlen($chunk);
    }
    @fclose($fh);
    exit;
}

/** Declared request body length: -1 if absent, -2 if malformed. */
function kg_content_length()
{
    if (!isset($_SERVER['CONTENT_LENGTH']) || $_SERVER['CONTENT_LENGTH'] === '') {
        return -1;
    }
    $v = $_SERVER['CONTENT_LENGTH'];
    if (!is_string($v) || !preg_match('/^[0-9]+\z/', $v)) {
        return -2;
    }
    if (strlen($v) > 15) {
        return PHP_INT_MAX;
    }
    return (int) $v;
}

/** Parse a php.ini size value such as "8M" into bytes (0 = unlimited/unknown). */
function kg_ini_bytes($v)
{
    if (!is_string($v) || !preg_match('/^\s*([0-9]+)\s*([kmgKMG]?)/', $v, $m)) {
        return 0;
    }
    $n = (float) $m[1];
    switch (strtolower($m[2])) {
        case 'g':
            $n *= 1024;
            // fall through
        case 'm':
            $n *= 1024;
            // fall through
        case 'k':
            $n *= 1024;
    }
    return $n;
}

/** Copy the current vault to backups/vault-YYYYmmdd-HHMMSS[-n].kdbx. */
function kg_backup($vault, $dir)
{
    if (!@is_dir($dir) && !@mkdir($dir, 0700, true) && !@is_dir($dir)) {
        return false;
    }
    $stamp = date('Ymd-His');
    // Next free counter for this second: one above the highest existing one, never a
    // gap left by pruning (otherwise the newest backup would sort as the oldest).
    $start = 0;
    $list = @scandir($dir);
    if (is_array($list)) {
        foreach ($list as $f) {
            if (preg_match('/^vault-' . $stamp . '(?:-([0-9]+))?\.kdbx\z/', $f, $m)) {
                $n = isset($m[1]) ? (int) $m[1] : 0;
                if ($n + 1 > $start) {
                    $start = $n + 1;
                }
            }
        }
    }
    for ($n = $start; $n < $start + 1000; $n++) {
        $name = $dir . '/vault-' . $stamp . ($n > 0 ? '-' . $n : '') . '.kdbx';
        if (@file_exists($name)) {
            continue;
        }
        $dst = @fopen($name, 'xb');
        if ($dst === false) {
            if (@file_exists($name)) {
                continue;
            }
            return false;
        }
        $src = @fopen($vault, 'rb');
        $ok = false;
        if ($src !== false) {
            $st = @fstat($src);
            $copied = @stream_copy_to_stream($src, $dst);
            $ok = is_array($st) && $copied !== false && $copied === $st['size'] && @fflush($dst);
            if ($ok && function_exists('fsync')) {
                @fsync($dst);
            }
            @fclose($src);
        }
        @fclose($dst);
        if (!$ok) {
            @unlink($name);
        }
        return $ok;
    }
    return false;
}

/** Delete all but the newest $keep backups (only files matching the backup pattern). */
function kg_prune_backups($dir, $keep)
{
    if (!@is_dir($dir)) {
        return;
    }
    $list = @scandir($dir);
    if (!is_array($list)) {
        return;
    }
    $items = array();
    foreach ($list as $f) {
        if (preg_match('/^vault-([0-9]{8}-[0-9]{6})(?:-([0-9]+))?\.kdbx\z/', $f, $m)) {
            $items[] = array($m[1], isset($m[2]) ? (int) $m[2] : 0, $f);
        }
    }
    // Oldest first: by timestamp, then by collision counter.
    usort($items, function ($a, $b) {
        $c = strcmp($a[0], $b[0]);
        if ($c !== 0) {
            return $c;
        }
        return $a[1] - $b[1];
    });
    $excess = count($items) - $keep;
    for ($i = 0; $i < $excess; $i++) {
        @unlink($dir . '/' . $items[$i][2]);
    }
}

function kg_action_save($cfg)
{
    kg_gate($cfg);

    $base = isset($_SERVER['HTTP_X_VAULT_BASE_REV']) ? $_SERVER['HTTP_X_VAULT_BASE_REV'] : null;
    if (!is_string($base) || !preg_match('/^[0-9a-fA-F]{64}\z/', $base)) {
        kg_error(400, 'bad_request');
    }
    $base = strtolower($base);

    // Size check before reading the body. post_max_size also caps php://input, so a
    // body above it would arrive empty: report that as too_large as well.
    $max = $cfg['max_vault_bytes'];
    $declared = kg_content_length();
    if ($declared === -2) {
        kg_error(400, 'bad_request');
    }
    $postMax = kg_ini_bytes(ini_get('post_max_size'));
    if ($declared > $max || ($postMax > 0 && $declared > $postMax)) {
        kg_error(413, 'too_large');
    }

    $vault = $cfg['vault_file'];
    clearstatcache();
    if (!@is_file($vault)) {
        kg_error(404, 'no_vault');
    }

    // Stream the body (at most max + 1 bytes) into a temp file next to the vault,
    // so the final rename() is atomic and memory use stays flat.
    $tmp = dirname($vault) . '/.' . basename($vault) . '.tmp-' . bin2hex(random_bytes(8));
    $out = @fopen($tmp, 'xb');
    if ($out === false) {
        kg_error(500, 'write_failed');
    }
    $GLOBALS['kg_cleanup'][] = $tmp;
    $in = @fopen('php://input', 'rb');
    if ($in === false) {
        @fclose($out);
        @unlink($tmp);
        kg_error(500, 'server_error');
    }
    $ctx = hash_init('sha256');
    $total = 0;
    $head = '';
    $readError = false;
    while (true) {
        $chunk = @fread($in, KG_CHUNK);
        if ($chunk === false) {
            $readError = true;
            break;
        }
        if ($chunk === '') {
            break;
        }
        $len = strlen($chunk);
        $total += $len;
        if ($total > $max) {
            @fclose($in);
            @fclose($out);
            @unlink($tmp);
            kg_error(413, 'too_large');
        }
        if (strlen($head) < 8) {
            $head .= substr($chunk, 0, 8 - strlen($head));
        }
        if (@fwrite($out, $chunk) !== $len) {
            @fclose($in);
            @fclose($out);
            @unlink($tmp);
            kg_error(500, 'write_failed');
        }
        hash_update($ctx, $chunk);
    }
    @fclose($in);
    $flushed = @fflush($out);
    if ($flushed && function_exists('fsync')) {
        $flushed = @fsync($out);
    }
    @fclose($out);
    if ($readError || ($declared >= 0 && $total !== $declared)) {
        @unlink($tmp);
        kg_error(400, 'bad_request'); // incomplete body
    }
    if (!$flushed) {
        @unlink($tmp);
        kg_error(500, 'write_failed');
    }
    if ($head !== KG_KDBX_SIGNATURE) {
        @unlink($tmp);
        kg_error(400, 'invalid_kdbx');
    }
    $newRev = hash_final($ctx);

    // Critical section: conflict check, backup and replace are serialized by a
    // separate lock so concurrent saves cannot interleave.
    $lock = @fopen($cfg['state_dir'] . '/vault.lock', 'c');
    if ($lock === false) {
        @unlink($tmp);
        kg_error(500, 'state_error');
    }
    if (!@flock($lock, LOCK_EX)) {
        @fclose($lock);
        @unlink($tmp);
        kg_error(500, 'state_error');
    }
    clearstatcache();
    if (!@is_file($vault)) {
        kg_release($lock);
        @unlink($tmp);
        kg_error(404, 'no_vault');
    }
    $current = @hash_file('sha256', $vault);
    if (!is_string($current)) {
        kg_release($lock);
        @unlink($tmp);
        kg_error(500, 'server_error');
    }
    if (!hash_equals($current, $base)) {
        kg_release($lock);
        @unlink($tmp);
        kg_json(409, array('error' => 'conflict', 'rev' => $current));
    }
    $backupDir = $cfg['state_dir'] . '/backups';
    if ($cfg['keep_backups'] > 0 && !kg_backup($vault, $backupDir)) {
        kg_release($lock);
        @unlink($tmp);
        kg_error(500, 'backup_failed');
    }
    $perms = @fileperms($vault);
    if ($perms !== false) {
        @chmod($tmp, $perms & 0777);
    }
    if (!@rename($tmp, $vault)) {
        kg_release($lock);
        @unlink($tmp);
        kg_error(500, 'write_failed');
    }
    kg_prune_backups($backupDir, $cfg['keep_backups']);
    kg_release($lock);
    kg_json(200, array('rev' => $newRev));
}

/* ------------------------------------------------------------------------ */
/* Dispatch                                                                 */
/* ------------------------------------------------------------------------ */

function kg_main()
{
    $methods = array('params' => 'GET', 'status' => 'GET', 'open' => 'POST', 'save' => 'POST');
    $action = (isset($_GET['a']) && is_string($_GET['a'])) ? $_GET['a'] : '';
    if (!isset($methods[$action])) {
        kg_error(400, 'bad_request');
    }
    $method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper((string) $_SERVER['REQUEST_METHOD']) : '';
    if ($method !== $methods[$action]) {
        kg_json(405, array('error' => 'method_not_allowed'), array('Allow: ' . $methods[$action]));
    }
    $cfg = kg_load_config();
    if ($cfg === null) {
        kg_error(503, 'not_configured');
    }
    switch ($action) {
        case 'params':
            kg_action_params($cfg);
            break;
        case 'status':
            kg_action_status($cfg);
            break;
        case 'open':
            kg_action_open($cfg);
            break;
        case 'save':
            kg_action_save($cfg);
            break;
    }
    kg_error(500, 'server_error');
}

try {
    kg_main();
} catch (Throwable $e) {
    kg_error(500, 'server_error');
}
