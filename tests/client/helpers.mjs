// Shared fixtures: small KDBX4 databases created with kdbxweb (cheap KDF params so tests stay fast).
import kdbxweb from 'kdbxweb';
import { installArgon2 } from '../../src/argon2.js';

const { Kdbx, Credentials, ProtectedValue, Consts, VarDictionary, Int64 } = kdbxweb;
export { kdbxweb };

export const PASSWORD = 'pässwörd ☃ 123';

/**
 * Creates a KDBX 4 database with AES cipher and the given KDF:
 *  'aes' (AES-KDF, 1000 rounds), 'argon2d' / 'argon2id' (1 MiB, 2 iterations).
 * Layout: root "Test DB" > GitHub, groups Email > Mail, Banking > Cards > Visa; "Old" is in the recycle bin.
 */
export async function makeDb({ kdf = 'aes', password = PASSWORD, keyFile = null, recycleBin = true } = {}) {
  installArgon2();
  const db = Kdbx.create(new Credentials(ProtectedValue.fromString(password), keyFile), 'Test DB');
  if (kdf === 'aes') {
    db.setKdf(Consts.KdfId.Aes);
    db.header.kdfParameters.set('R', VarDictionary.ValueType.UInt64, new Int64(1000));
  } else {
    db.setKdf(kdf === 'argon2id' ? Consts.KdfId.Argon2id : Consts.KdfId.Argon2d);
    db.header.kdfParameters.set('M', VarDictionary.ValueType.UInt64, new Int64(1024 * 1024));
    db.header.kdfParameters.set('I', VarDictionary.ValueType.UInt64, new Int64(2));
  }
  const root = db.getDefaultGroup();
  const email = db.createGroup(root, 'Email');
  const banking = db.createGroup(root, 'Banking');
  const cards = db.createGroup(banking, 'Cards');

  const add = (group, title, user, pass, url = '', notes = '', tags = []) => {
    const e = db.createEntry(group);
    e.fields.set('Title', title);
    e.fields.set('UserName', user);
    e.fields.set('Password', ProtectedValue.fromString(pass));
    e.fields.set('URL', url);
    e.fields.set('Notes', notes);
    e.tags = tags;
    return e;
  };
  add(root, 'GitHub', 'alice', 'gh-secret', 'https://github.com/login', 'personal account', ['dev', 'work']);
  add(email, 'Mail', 'alice@example.org', 'mail-secret', 'https://mail.example.org', 'webmail');
  const visa = add(cards, 'Visa', '4111', 'visa-secret', '', 'expires 12/29');
  visa.fields.set('PIN', ProtectedValue.fromString('1234'));
  visa.fields.set('Account', 'DE00 1234');
  const old = add(root, 'Old', 'bob', 'old-secret', '', 'zebra');
  db.remove(old); // -> recycle bin
  if (!recycleBin) db.meta.recycleBinEnabled = false;
  // KDBX stores times with 1 s precision and merge compares them, so date the fixture in the past:
  // edits made by a test are then always "newer" than the base state.
  const past = new Date('2020-01-01T00:00:00Z');
  for (const item of root.allGroupsAndEntries()) {
    item.times.creationTime = past;
    item.times.lastModTime = past;
    item.times.lastAccessTime = past;
    item.times.locationChanged = past;
  }
  return db.save();
}

export function credentials(password = PASSWORD, keyFile = null) {
  return new Credentials(ProtectedValue.fromString(password), keyFile);
}

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
