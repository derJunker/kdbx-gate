# kdbx-gate

A minimal web vault for KeePass `.kdbx` files that runs on **plain PHP shared hosting**,
deployable over FTP. It needs no database, no SSH, no cron and no Composer.

- **One password.** Your KeePass master password opens the server gate and decrypts
  the vault.
- **The vault is not publicly downloadable.** The `.kdbx` sits in a denied `data/`
  directory, and `api.php` only hands it out after the password check passes.
- **Rate limited.** After 3 wrong attempts, only 1 attempt per minute is allowed. The
  limit is global, and attempts made while locked are rejected without checking the
  password.
- **Decryption happens only in your browser** (via [kdbxweb](https://github.com/keeweb/kdbxweb)).
  The server never sees your master password or the decrypted data.
- The file stays a normal `.kdbx`, so KeePassXC, KeePassDX and other KeePass apps
  keep working with it.

See [`docs/SPEC.md`](docs/SPEC.md) for the design and the HTTP API.

## How the password check works

The browser derives `token = Argon2id(password, salt)` and sends it to `api.php`.
The server stores only `SHA-256(token)` and compares the token against it. The
token's salt is independent of the `.kdbx` file's own KDF, so the token does not
reveal the vault key. Anyone who steals the stored verifier still has to run
Argon2id (64 MiB) for every password guess.

## Build

```sh
npm install
npm run build      # -> dist/
npm test           # client + server tests (needs php in PATH)
npm run dev        # build + php -S on http://127.0.0.1:8080 (put a config + vault in dist/data first)
```

## Deploy (FTP)

1. Run `npm run build` and upload the **contents** of `dist/` to a folder on your
   host, for example `/vault/`. Make sure your FTP client uploads dotfiles
   (`.htaccess`, `data/.htaccess`).
2. Open `setup.html` locally (double-click `dist/setup.html`) or on the server.
   Choose your `.kdbx`, enter the master password (and the key file, if you use one),
   and download the generated `config.php`. Nothing leaves your browser.
3. Upload `config.php` and your vault, renamed to `vault.kdbx`, into `data/`.
4. Open `https://your-site/vault/`. If the page shows a red warning that the data
   directory is readable, your host ignores `.htaccess`, and you must fix that before
   using the vault. Either move `vault.kdbx` outside the webroot and set `vault_file`
   in `config.php`, or ask your host.
5. `data/` must be writable by PHP so it can store `lockout.json`, `backups/` and
   saves. If it isn't, the gate fails closed.

**Important:** if you change the master password in another KeePass app, run setup
again and upload the new `config.php`. Otherwise the gate will reject the new
password.

## Requirements

- PHP ≥ 7.4 (no extensions beyond the defaults: `hash`, `json`)
- Apache with `.htaccess` (`AllowOverride` incl. `AuthConfig`/`Limit`, plus `mod_headers` for the security headers)
- HTTPS
- A browser with WebAssembly (needed for Argon2)

## Under attack?

The lockout is global, so an attacker can keep it locked and lock you out too. That
is intentional, because it means guessing stays slow. If it happens, rename or delete
`api.php` over FTP to take the vault offline.

## License

MIT. Bundles [kdbxweb](https://github.com/keeweb/kdbxweb) (MIT) and
[hash-wasm](https://github.com/Daninet/hash-wasm) (MIT).
