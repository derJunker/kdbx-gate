<?php
/*
 * kdbx-gate configuration (sample).
 *
 * Normally you do not edit this by hand: open setup.html locally, choose your
 * .kdbx and type the master password; it generates data/config.php for you.
 * Upload that file together with your vault as data/vault.kdbx.
 *
 * This sample is NOT a working configuration: the placeholder verifier below is
 * rejected and api.php answers 503 {"error":"not_configured"} until a real one is set.
 *
 * Verifier format (see docs/SPEC.md):
 *   v1$argon2id$m=<KiB>,t=<iterations>,p=<parallelism>$<salt, standard base64 with padding>$<SHA-256(token), hex>
 *   token = Argon2id(password, salt, m, t, p, 32 bytes), computed in the browser.
 *
 * Use single quotes around the verifier: it contains "$" characters.
 */
return [
    // Required.
    'verifier'        => 'v1$argon2id$m=65536,t=3,p=1$REPLACE_WITH_SALT$REPLACE_WITH_SHA256_HEX',

    // Everything below is optional; the values shown are the defaults.

    // The KeePass file. May point outside the web root.
    'vault_file'      => __DIR__ . '/vault.kdbx',

    // Directory for lockout.json, lastlogin.json, vault.lock and backups/. Must be writable by PHP.
    'state_dir'       => __DIR__,

    // Failed attempts allowed before the delay starts.
    'free_attempts'   => 3,

    // While locked, at most one attempt per this many seconds (minimum 1).
    'delay_seconds'   => 60,

    // Largest vault accepted by "save" (bytes). PHP's post_max_size must be at
    // least this large, otherwise bigger saves are rejected with 413 too_large.
    'max_vault_bytes' => 20 * 1024 * 1024,

    // Number of previous versions kept in backups/ (0 = no backups).
    'keep_backups'    => 10,
];
