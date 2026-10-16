// kdbxweb Argon2 adapter backed by hash-wasm (needed for KDBX4 files using Argon2d/Argon2id).
// kdbxweb calls: (password, salt, memoryKiB, iterations, length, parallelism, type, version)
//   type: 0 = argon2d, 2 = argon2id;  version: 0x13 (or 0x10, unsupported by hash-wasm).
import kdbxweb from 'kdbxweb';
import { argon2d, argon2id } from 'hash-wasm';

export async function kdbxArgon2(password, salt, memory, iterations, length, parallelism, type, version) {
  if (version !== 0x13) {
    throw new Error(`Argon2 version 0x${Number(version).toString(16)} is not supported (only 1.3)`);
  }
  let fn;
  if (type === kdbxweb.CryptoEngine.Argon2TypeArgon2d) fn = argon2d;
  else if (type === kdbxweb.CryptoEngine.Argon2TypeArgon2id) fn = argon2id;
  else throw new Error(`Unsupported Argon2 type ${type}`);
  const hash = await fn({
    password: new Uint8Array(password),
    salt: new Uint8Array(salt),
    memorySize: memory, // already KiB
    iterations,
    parallelism,
    hashLength: length,
    outputType: 'binary',
  });
  return hash.buffer.slice(hash.byteOffset, hash.byteOffset + hash.byteLength);
}

let installed = false;

/** Registers the adapter with kdbxweb once (idempotent). */
export function installArgon2() {
  if (!installed) {
    kdbxweb.CryptoEngine.setArgon2Impl(kdbxArgon2);
    installed = true;
  }
}
