# kdbx-gate: specification

A minimal web vault for KeePass `.kdbx` files that runs on plain PHP shared hosting
(FTP upload only: no SSH, no database, no cron, no long-running processes).

## Goals

- **One password.** The user types the KeePass master password once. It unlocks the
  server gate and decrypts the vault.
- **The vault is not downloadable without the password.** The `.kdbx` lives in a
  denied directory (`data/`), and only `api.php` hands it out after authentication.
- **Rate limit.** After 3 consecutive failed attempts, only 1 attempt per 60 s is
  allowed. The limit is global (not per IP), and attempts made while locked are
  rejected without checking the password.
- **Decryption happens only in the browser** (kdbxweb). The server never sees the
  master password or the decrypted data.
- A simple, mobile-friendly UI: flat, no gradients, no framework.

## Authentication scheme

```
token    = Argon2id(password_utf8, salt, m, t, p, len = 32)   // computed in the browser (hash-wasm)
verifier = SHA-256(token)                                     // stored on the server, hex
```

- `salt` is 16 random bytes generated during setup and stored with the verifier.
  It is public (served by `?a=params`).
- The token is sent hex-encoded (64 lowercase hex chars) in the HTTP header
  `X-Vault-Token`, and never in a URL.
- Server check: `hash_equals($verifierHex, hash('sha256', hex2bin($tokenHex)))`.
- Why this is safe: the token is the output of a memory-hard KDF, so storing
  SHA-256(token) costs an attacker who obtains the verifier one Argon2id run per
  password guess. Argon2id with a separate salt is independent of the KDBX key
  derivation, which uses SHA-256(password) followed by the KDBX file's own KDF.
- Default parameters: `m = 65536` (KiB, i.e. 64 MiB), `t = 3`, `p = 1`.

### Verifier string (stored in `data/config.php`)

```
v1$argon2id$m=65536,t=3,p=1$<salt base64 (standard, padded)>$<sha256 hex>
```

## Files on the server (contents of `dist/`)

```
index.html        app (login, list, entry view/edit)
setup.html        local helper: choose a .kdbx and type the password; it verifies the
                  file opens, then produces data/config.php (nothing is uploaded)
app.js, setup.js  esbuild bundles (IIFE, so they also work from file://)
style.css
api.php           the only server-side code (single file, no Composer)
.htaccess         security headers, no directory listing
data/.htaccess    deny all
data/config.sample.php
data/config.php   (created by the user from setup.html)
data/vault.kdbx   (uploaded by the user)
data/lockout.json (created at runtime)
data/lastlogin.json (created at runtime; time and User-Agent of the latest successful open)
data/backups/     (created at runtime; old versions from before each save)
```

## `data/config.php`

```php
<?php
return [
    'verifier'        => 'v1$argon2id$m=65536,t=3,p=1$...$...',
    'vault_file'      => __DIR__ . '/vault.kdbx',  // may point outside the webroot
    'state_dir'       => __DIR__,                  // lockout.json + backups/ live here
    'free_attempts'   => 3,                        // failures allowed before the delay starts
    'delay_seconds'   => 60,                       // minimum spacing of attempts while locked
    'max_vault_bytes' => 20 * 1024 * 1024,
    'keep_backups'    => 10,
];
```

Every key except `verifier` is optional and defaults to the values above.
`api.php` loads the config from `__DIR__ . '/data/config.php'`, unless the
environment variable `KDBX_GATE_CONFIG` is set to another path (used by tests).

## HTTP API (`api.php`)

All JSON responses use `Content-Type: application/json; charset=utf-8`. All
responses send `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and
`Referrer-Policy: no-referrer`. No CORS headers are sent.

The action is selected with the `a` query parameter. An unknown action returns 400
`{"error":"bad_request"}`, and a wrong HTTP method returns 405 `{"error":"method_not_allowed"}`.

If there is no config or no valid `verifier`, every action returns
503 `{"error":"not_configured"}`.

### `GET api.php?a=params`
200 `{"kdf":"argon2id","m":65536,"t":3,"p":1,"salt":"<base64>"}`

### `GET api.php?a=status`
200 `{"retryAfter": <int seconds, 0 if an attempt is allowed now>, "attemptsLeft": <int, failures left before the delay starts>}`

This lets the UI show a countdown without spending an attempt. It does not modify
state.

### `POST api.php?a=open`
Header `X-Vault-Token: <64 hex>`. The request body is ignored.
- 200: the raw `.kdbx` bytes, `Content-Type: application/octet-stream`, header
  `X-Vault-Rev: <sha256 hex of the file bytes>`. If an earlier successful open is on
  record, also `X-Vault-Last-Login: <unix ts>` and (if that request sent one)
  `X-Vault-Last-Login-UA: <its User-Agent>`.
- Last login: after the gate accepts and the vault file is opened, `open` replaces
  `state_dir/lastlogin.json` (`{"at": unix_ts, "ua": string}`, under an exclusive
  `flock`) with the current request and reports the previous content in the headers
  above. Nothing else is stored (no IP, no token). The User-Agent is reduced to
  printable ASCII (0x20-0x7E) and 256 characters. An empty or corrupt file counts
  as "no earlier open" and is overwritten. If the file cannot be opened, locked or
  written, the vault is not served (500 `{"error":"state_error"}`). Failed, locked,
  `status` and `save` requests never touch it.
- 401 `{"error":"bad_token","attemptsLeft":n,"retryAfter":s}`: wrong token (or
  missing/malformed token, which counts as a failed attempt). `retryAfter` is 0
  while `attemptsLeft > 0`, otherwise `delay_seconds`.
- 429 `{"error":"locked","retryAfter":s}` plus the `Retry-After: s` header: the
  attempt was rejected because of the lockout. The token was **not** checked and
  the state is unchanged.
- 404 `{"error":"no_vault"}`: authenticated, but the vault file is missing.

### `POST api.php?a=save`
Headers: `X-Vault-Token`, `X-Vault-Base-Rev: <sha256 hex the client loaded>`. The body is
the raw `.kdbx` bytes (`Content-Type: application/octet-stream`).
- Authentication goes through exactly the same gate as `open` (same 401/429 responses).
- 413 `{"error":"too_large"}` if the body is larger than `max_vault_bytes`
  (checked before reading where possible).
- 400 `{"error":"invalid_kdbx"}` if the body does not start with the KDBX signature
  `03 D9 A2 9A 67 FB 4B B5`.
- 409 `{"error":"conflict","rev":"<current sha256>"}` if the current file's hash
  differs from `X-Vault-Base-Rev`.
- 200 `{"rev":"<sha256 of new file>"}` on success.
- Write procedure: take an exclusive lock, copy the current file to
  `backups/vault-YYYYmmdd-HHMMSS[-n].kdbx`, write the new content to a temp
  file in the same directory, `rename()` it over the vault, and prune the backups
  to the newest `keep_backups`.

### Lockout algorithm (the gate)

State lives in `state_dir/lockout.json`: `{"fails": int, "last": unix_ts_of_last_failure}`.
The whole check, verify and update sequence runs while holding an exclusive `flock`, so
parallel requests cannot bypass the counter.

```
now = time()
if fails >= free_attempts and now - last < delay_seconds:
    -> 429, retryAfter = delay_seconds - (now - last)     (state unchanged, token not checked)
if verify(token):
    fails = 0                                             -> proceed
else:
    fails += 1; last = now                                -> 401
```

## Client

- On load, the client checks `location.protocol` and refuses to send the token over
  plain `http:`, except on `localhost` or `127.0.0.1`.
- On load, it sends `HEAD data/vault.kdbx` and `HEAD data/config.php`. If either
  returns 200, it shows a red warning that the data directory is publicly readable.
- Unlock: GET params, derive the token (Argon2id via hash-wasm), POST open, then
  `kdbxweb.Kdbx.load(bytes, new Credentials(ProtectedValue.fromString(pw), keyFile?))`.
  The token and the rev stay in memory. A key file is optional and only used for KDBX
  decryption.
- The unlocked view's top bar shows the previous successful open from
  `X-Vault-Last-Login(-UA)`: "Last login: <local date/time> · <browser> on <system>"
  (full User-Agent as tooltip), or "Last login: none recorded". An unexpected time or
  device there means someone else had the password.
- The server's 401/429 responses are shown as "Wrong password, n attempts left before
  delay" or "Locked, try again in mm:ss" with a live countdown.
- If the gate accepts but the KDBX decryption fails, the client shows: "Server accepted
  the password but the vault could not be decrypted. Re-run setup if you changed the
  master password, or provide the key file."
- Features: group navigation like a folder browser (breadcrumb, subgroups first, then the
  group's entries; starts at the root and remembers the current group while unlocked), a
  sidebar with the nested group tree (expand/collapse, current group highlighted) on wide
  screens (≥ 900 px), live search across all groups excluding the recycle bin (title,
  username, URL, notes, tags; results show the group path), entry view (copy username and
  password, reveal the password, open the URL: shown as a link if it is
  http(s), or a bare host like `github.com`, which gets `https://`), edit fields and move the entry to another
  group, add an entry (defaults to the current group), delete an entry (moves it to the
  recycle bin; deleting inside the bin is permanent), group management (new subgroup,
  rename, delete: moves the group to the recycle bin, permanent inside the bin; the root
  and the recycle bin itself are protected), the recycle bin shown as a group (view
  deleted entries, restore by moving them to another group), a password generator, save
  (with conflict handling), download the encrypted `.kdbx`, lock.
- Copy buttons put the value on the clipboard and leave it there (no auto-clear). The
  app auto-locks after 5 min of inactivity and drops all decrypted state.
- CSP-compatible: no inline scripts or styles and no eval. WebAssembly needs
  `'wasm-unsafe-eval'`.
