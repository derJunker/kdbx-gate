# kdbxweb 2.1.1 + hash-wasm 4.12: what kdbx-gate uses

Sources: `node_modules/kdbxweb/README.md`, `dist/types/**`, `lib/**/*.ts`; hash-wasm `README.md`, `dist/lib/argon2.d.ts`.

## Import
- kdbxweb ships one webpack UMD bundle (`main: dist/kdbxweb.js`), no ESM/`exports` map:
  `import kdbxweb from 'kdbxweb'` works in Node ESM and esbuild. `Credentials` is an alias of `KdbxCredentials`.
- hash-wasm: `import { argon2id, argon2d } from 'hash-wasm'` (Node gets UMD, esbuild picks `module` = ESM).

## Argon2 (KDBX4 Argon2d/Argon2id files): `CryptoEngine.setArgon2Impl(fn)`
- `fn(password: ArrayBuffer, salt: ArrayBuffer, memory, iterations, length, parallelism, type, version) => Promise<ArrayBuffer|Uint8Array>`
- `memory` is already **KiB** (kdbxweb divides the header's byte value `M` by 1024). hash-wasm `memorySize` is KiB too, so pass through.
- `type`: `0` = argon2d (`CryptoEngine.Argon2TypeArgon2d`), `2` = argon2id (`Argon2TypeArgon2id`). argon2i is not used by KDBX.
- `version`: `0x13` or `0x10`. hash-wasm only implements 0x13, so 0x10 is rejected with a clear error (KeePass writes 0x13).
- hash-wasm wants `Uint8Array`/string (not ArrayBuffer): wrap inputs, use `outputType: 'binary'`.
- Without an impl, Argon2 files fail with `KdbxError` code `NotImplemented`.
- Our gate token uses `argon2id({password: utf8, salt, iterations: t, memorySize: m, parallelism: p, hashLength: 32, outputType: 'hex'})`
  = libsodium `sodium_crypto_pwhash(32, pw, salt, t, m*1024, ARGON2ID13)` (PHP takes **bytes**; libsodium fixes p = 1).

## AES-KDF (the real vault: KDBX 4.0, AES-256 cipher, AES-KDF 600000 rounds)
- Pure WebCrypto, no Argon2 involved. `KeyEncryptorAes` simulates N rounds of AES-ECB by AES-CBC-encrypting
  a zero buffer (max 10000 blocks per call) with the running block as IV; both 16-byte halves run in parallel,
  then SHA-256. 600000 rounds = 60 sequential `subtle.encrypt` calls of 160 KB per half.
- Measured: Node 22 (same WebCrypto path) ~25 ms load / ~45 ms save; headless Firefox, whole unlock
  (Argon2id 64 MiB gate token + fetch + AES-KDF 600k + decrypt) ~0.5 s. Not a bottleneck.
  Payload cipher AES-256-CBC also goes through `crypto.subtle` (needs a secure context: https, localhost, file:).

## Load / create / save
- `await Kdbx.load(arrayBuffer, new Credentials(ProtectedValue.fromString(pw), keyFileBytes|null))`
  — data **must be an `ArrayBuffer`** (`instanceof` check; a Uint8Array/Buffer is rejected with InvalidArg).
- Wrong password / key file: `KdbxError` with `.code === Consts.ErrorCodes.InvalidKey`. Bad file: `BadSignature`, `FileCorrupt`...
- Key file: `Credentials` accepts ArrayBuffer/Uint8Array; handles XML v1/v2, 32-byte raw, 64-hex, else SHA-256 of the file.
- `Kdbx.create(credentials, name)` → KDBX 4.0, AES cipher, Argon2d KDF, creates default group + recycle bin.
  `db.setKdf(Consts.KdfId.Aes|Argon2d|Argon2id)`; tune via `db.header.kdfParameters.set('R'|'M'|'I'|'P', VarDictionary.ValueType.UInt64|UInt32, new Int64(n))`.
- `await db.save()` → ArrayBuffer; regenerates master seed/IV/KDF salt each time (so it re-runs the KDF).

## Tree
- `db.getDefaultGroup()` = root; `group.groups`, `group.entries`, `group.allEntries()` (recursive, no history), `group.allGroups()`.
- `db.getGroup(uuid)`, `entry.uuid.id` (base64 string), `entry.parentGroup`, `group.name`.
- Recycle bin: `db.meta.recycleBinEnabled`, `db.meta.recycleBinUuid` → `db.getGroup(...)`; exclude its subtree from lists.
- `db.remove(obj)`: if recycle bin enabled, creates it if needed and moves obj there; otherwise deletes
  permanently (adds a `deletedObjects` tombstone). `db.move(obj, group)` sets `times.locationChanged`.

## Entries
- `db.createEntry(group)` → Title/UserName/Password/URL/Notes pre-set ('' or ProtectedValue per `meta.memoryProtection`).
- `entry.fields: Map<string, string | ProtectedValue>` (README's `entry.fields.X = ...` is the 1.x API; 2.x is a Map).
  Read: `v instanceof ProtectedValue ? v.getText() : v`. Write Password as `ProtectedValue.fromString(s)`.
- `entry.tags: string[]`, `entry.times.{creationTime,lastModTime}` (Date).
- Edit protocol (README "Entry modification"): `entry.pushHistory()` → change fields → `entry.times.update()`.
  Never edit `entry.history` directly; trim with `entry.removeHistory(0, n)` (respects `meta.historyMaxItems`).

## Merge (used for 409 conflicts)
- `local.merge(remote)`: CRDT-style, newest `lastModTime` wins per entry/group, history merged, deletions via
  `deletedObjects`, moves via `locationChanged`. Default group UUID must match (else `MergeError`).
- Flow: load remote with the same `db.credentials` → `local.merge(remote)` → `save()` → upload with the remote rev
  → on success `db.removeLocalEditState()` (clears history tombstones collected by pushHistory/removeHistory).
- Header (cipher/KDF settings) is not merged: the local header wins.
- If the remote cannot be decrypted with the current credentials (master key changed elsewhere), offer a reload.

## Bundling with esbuild (browser, IIFE)
- The UMD wrapper eagerly evaluates `require("crypto")` and `require("@xmldom/xmldom")` (webpack externals).
  Both are only used when `globalThis.crypto.subtle` / `DOMParser` are missing, so map both to an empty
  module in the browser build (plugin `onResolve`), which also saves ~65 KiB (minified) of xmldom.
- webpack's global shim contains dead code `new Function('return this')()` (only reached if `globalThis`
  is missing). The build patches it to `globalThis` so the bundle has no eval-like code under a strict CSP.
- fflate (gzip) is inlined in kdbxweb's bundle; its worker code is never used (only `gzipSync/gunzipSync`).
- hash-wasm instantiates embedded WASM via `WebAssembly.compile` → CSP needs `script-src 'wasm-unsafe-eval'`.
