# kdbx-gate: how it works and how to run it

A plain-language guide: what happens where, what you need, how to set it up, and
what to do when something changes. For the exact protocol and API, see [`SPEC.md`](SPEC.md).

## How it works

1. **You type your KeePass master password in the browser.** The browser turns it into
   a *token*, a long code derived with Argon2id. The password can't be recovered from
   the token, and the password itself never leaves the browser.
2. **The server checks the token.** `api.php` compares the token with the fingerprint
   stored in `data/config.php`. If they match, it sends the vault file. The file is
   still encrypted at that point.
3. **Wrong guesses are throttled.** After 3 wrong attempts, only 1 attempt per minute is
   allowed. The limit applies to everyone, not per IP.
4. **The browser decrypts the vault** with your password (via kdbxweb). The server only
   ever holds the encrypted `.kdbx`.
5. **Saving works the same way in reverse.** The browser encrypts the vault and uploads
   it. The server keeps the previous version in `data/backups/` (the newest 10).
6. **Locking never loses changes by accident.** After 10 minutes without use, the vault
   locks itself and saves unsaved changes on the way. The next unlock in that tab lists
   what was saved and lets you **Revert** it. **Lock** asks whether to save or discard.
   Reloading or closing the tab drops the revert offer, but the earlier version is still
   in `data/backups/`.
7. **You see when the vault was last opened.** Each successful unlock stores its time
   and browser (User-Agent, nothing else) in `data/lastlogin.json`. The top bar of the
   unlocked app shows the *previous* one, e.g. "Last login: 16 Oct 2026, 14:03 · Firefox
   on Linux". If you don't recognise it, someone else knows your password: change it.

The file stays a normal KeePass file, so KeePassXC, KeePassDX and other KeePass apps
keep working with it.

## What's used where

| Where | What | Job |
|---|---|---|
| Browser | `index.html`, `app.js`, `style.css` | The app: derives the token, decrypts, shows and edits entries |
| Browser, setup only | `setup.html`, `setup.js` | Creates `config.php` from your password (see below) |
| Server | `api.php` | The only server code: token check, lockout, sending and saving the file |
| Server | `.htaccess`, `data/.htaccess` | Blocks direct downloads from `data/` and sends the security headers |
| Server, `data/` | `config.php`, `vault.kdbx` | The two files you upload |
| Server, `data/` | `lockout.json`, `lastlogin.json`, `backups/` | Created automatically at runtime |
| This repo | `src/`, `server/`, `tests/` | Source and tests. `npm run build` puts the deployable files in `dist/` |

## `config.php`

### What it is

A small PHP file that `api.php` reads on every request. Its main line is the
**verifier**:

```
v1$argon2id$m=65536,t=3,p=1$<salt>$<fingerprint of the token>
```

- **The settings and the salt** tell the browser how to derive the token (`api.php?a=params`
  hands them out). The salt is random and created during setup. It doesn't need to be
  secret.
- **The fingerprint** (SHA-256 of the token) lets the server tell whether a token is
  correct without ever knowing your password.

Everything else in it is optional and has sensible defaults: where the vault lives,
where the lockout and backup files go, the lockout numbers, the maximum vault size, and
how many backups to keep.

### Why it's generated in the browser and not on the server

- **Building it needs your password.** If the server did this, you would have to send
  your password to the server, and the point of the design is that the server never
  sees it.
- **A setup page on the server would be an open door.** Whoever reached it first could
  set their own password. Shared hosting with FTP only offers no safe "first run" step,
  so the server side has no setup at all: it only reads the finished file.
- **It checks your password first.** `setup.html` opens your `.kdbx` with the password
  before it writes the config. A typo can't create a gate that rejects your real password.

"Locally" means in your browser. You can open `dist/setup.html` straight from disk, or
`setup.html` on the server. In both cases nothing is uploaded.

### Is it secret?

Keep it private, but it isn't a key. Someone who got it could only try passwords
offline, at a cost of one Argon2id run (64 MiB) per guess. That's why it sits in the
blocked `data/` folder. It is tied to your **password**, not to the vault file. The
same `config.php` keeps working when the vault's contents or encryption settings change.

## What you need

- PHP 7.4 or newer on Apache, with `.htaccess` support and HTTPS. Ordinary shared
  hosting is enough; no database, SSH or cron.
- An FTP client that also uploads dotfiles (`.htaccess`).
- Node.js, only for building (`npm install`, `npm run build`).

## Setup

1. **Build and upload the app.** Run `npm run build` and upload the *contents* of
   `dist/` to a folder such as `/vault/`. Include both `.htaccess` files.
2. **Create `config.php`.** Open `setup.html`, pick your `.kdbx`, enter the master
   password (and the key file, if you use one), and download `config.php`.
3. **Upload your data.** Put `config.php` and your database, renamed to **`vault.kdbx`**,
   into `/vault/data/`.
4. **Check it.**
   - `https://your-site/vault/` should show no red warning.
   - `curl -sI https://your-site/vault/data/vault.kdbx` should return `403`.

`data/` must be writable by PHP so it can store `lockout.json`, `lastlogin.json`, `backups/` and saves.
If it isn't, the gate refuses everything.

## Backing up 2FA codes

**Import 2FA codes** (below the entry list) turns an authenticator app's export into vault entries:

- **2FAS:** Settings → 2FAS Backup → Export (with or without a backup password), then choose the `.2fas` file.
  Doing this on the phone itself works: open the vault in the phone's browser and pick the saved file.
- **Ente Auth:** Settings → Data → Export → **Plain text**, then choose the `.txt` file. Its encrypted export
  is not supported.
- **Anything else:** paste `otpauth://` links, or choose a text file of them.

Using one app for personal and one for work codes? Create a group for each first (e.g. `2FA/Personal` and
`2FA/Work`) and pick it under **Add to group** for each import. Delete unencrypted export files from the phone
afterwards.

Google Authenticator's export is only QR codes. Move those accounts into 2FAS first (2FAS can scan Google
Authenticator's export QR codes) or Ente Auth, then back up from there.

Files are read in the browser. The codes become entries (in the group `2FA` unless you pick
another one) and reach the server only inside the encrypted vault when you tap **Save**. Each entry has an
`otp` field, which KeePassXC, KeePassDX and Strongbox use to show the codes, plus KeePass 2's `TimeOtp-*`
fields. To move a code back into a phone app, open the entry and tap **Show QR code**.

Keep in mind that 2FA secrets in the same vault as the passwords mean that whoever opens the vault has
both factors.

## When something changes

| Situation | What to do |
|---|---|
| You edited the vault in KeePassXC | Upload it again as `data/vault.kdbx`. The config stays the same. |
| You edited in the web app | The server copy is now newer. Use the app's **Download encrypted .kdbx** button (or FTP) to update your local copy. |
| You edited in both places | Download the server copy, merge it in KeePassXC (**Database → Merge from database**), then upload the result. |
| You changed the master password | Run setup again, then upload the new `config.php` together with the vault. |
| You changed encryption settings or added a key file | Just upload the vault. The key file is never uploaded; you pick it when unlocking. |
| You changed the app's code | Run `npm test` and `npm run build`, then upload `dist/`. This never touches `data/`. |
| You're locked out after typos | Wait a minute per attempt, or delete `data/lockout.json` over FTP. |
| Someone is guessing passwords | Rename or delete `api.php` over FTP. The vault is offline until you restore it. |

Rule of thumb: once the vault is live, treat the server copy as the main one. Download
after editing on the web, and upload after editing locally.

## Pitfalls

- **Don't let an FTP mirror touch `data/`.** A sync that deletes remote files missing
  locally would delete the live vault, the backups and the lockout state. A sync that
  uploads would replace web edits with your old local copy. Exclude `data/`.
- **Never keep real data in `dist/`.** `npm run build` deletes `dist/` first. Test
  locally from a separate folder.
- **For local testing,** `php -S` ignores `.htaccess`, so `data/` is readable there.
  The app shows the red warning; that is expected and only matters on a real host.
