import test from 'node:test';
import assert from 'node:assert/strict';
import { Vault, isInvalidKeyError, safeHttpUrl, parseTags, fieldText } from '../../src/vault.js';
import { kdbxArgon2 } from '../../src/argon2.js';
import { hasKdbxSignature } from '../../src/bytes.js';
import { makeDb, PASSWORD, kdbxweb, sleep } from './helpers.mjs';

const { ProtectedValue, Credentials, Kdbx } = kdbxweb;

for (const kdf of ['aes', 'argon2d', 'argon2id']) {
  test(`KDBX4 + ${kdf}: open, list, search, edit, add, delete, save, reopen`, async () => {
    const bytes = await makeDb({ kdf });
    assert.ok(hasKdbxSignature(bytes));

    // Node Buffers / Uint8Arrays are accepted too (kdbxweb itself wants an ArrayBuffer).
    const vault = await Vault.open(Buffer.from(bytes), PASSWORD);
    assert.equal(vault.name, 'Test DB');
    assert.equal(vault.info.version, '4.0');
    assert.equal(vault.info.cipher, 'AES-256');
    assert.equal(vault.info.kdf.name, { aes: 'AES-KDF', argon2d: 'Argon2d', argon2id: 'Argon2id' }[kdf]);
    assert.equal(vault.dirty, false);

    // list: recycle bin excluded, sorted by title, with group paths
    const list = vault.listEntries();
    assert.deepEqual(list.map((e) => e.title), ['GitHub', 'Mail', 'Visa']);
    assert.deepEqual(list.map((e) => e.groupPath), ['Test DB', 'Email', 'Banking / Cards']);
    assert.deepEqual(vault.listGroups().map((g) => g.path), ['Test DB', 'Email', 'Banking', 'Banking / Cards']);

    // search: title, username, URL, notes, tags; case-insensitive; all terms must match
    const titles = (q) => vault.search(q).map((e) => e.title);
    assert.deepEqual(titles('git'), ['GitHub']);
    assert.deepEqual(titles('ALICE'), ['GitHub', 'Mail']);
    assert.deepEqual(titles('mail.example'), ['Mail']);
    assert.deepEqual(titles('expires'), ['Visa']);
    assert.deepEqual(titles('work'), ['GitHub']);
    assert.deepEqual(titles('alice webmail'), ['Mail']);
    assert.deepEqual(titles('zebra'), []); // only in the recycle bin
    assert.deepEqual(titles('gh-secret'), []); // passwords are not searched
    assert.equal(vault.search('  ').length, 3);

    // entry details incl. protected fields
    const gh = list[0];
    const detail = vault.getEntry(gh.id);
    assert.equal(detail.password, 'gh-secret');
    assert.deepEqual(detail.tags, ['dev', 'work']);
    const visa = vault.getEntry(list[2].id);
    assert.deepEqual(visa.custom, [
      { name: 'Account', value: 'DE00 1234', protected: false },
      { name: 'PIN', value: '1234', protected: true },
    ]);

    // edit: history pushed, password stays protected, modification time updated
    const entry = [...vault.db.getDefaultGroup().allEntries()].find((e) => e.uuid.id === gh.id);
    const before = entry.times.lastModTime.getTime();
    await sleep(5);
    assert.equal(vault.updateEntry(gh.id, { title: 'GitHub', password: 'gh-secret' }), false, 'no-op edit');
    assert.equal(vault.dirty, false);
    assert.equal(vault.updateEntry(gh.id, { password: 'new-secret', tags: 'dev; private', custom: { TOTP: { value: 'otp', protected: true } } }), true);
    assert.equal(vault.dirty, true);
    assert.ok(entry.fields.get('Password') instanceof ProtectedValue);
    assert.ok(entry.fields.get('TOTP') instanceof ProtectedValue);
    assert.equal(entry.history.length, 1);
    assert.equal(fieldText(entry.history[0].fields.get('Password')), 'gh-secret');
    assert.ok(entry.times.lastModTime.getTime() > before);

    // move to another group via edit
    const emailGroup = vault.listGroups().find((g) => g.path === 'Email');
    vault.updateEntry(gh.id, { groupId: emailGroup.id });
    assert.equal(vault.getEntry(gh.id).groupPath, 'Email');

    // add
    const cards = vault.listGroups().find((g) => g.path === 'Banking / Cards');
    const newId = vault.createEntry(cards.id, { title: 'Amex', username: 'carol', password: 'amex-pw', url: 'https://amex.example', tags: 'card' });
    assert.equal(vault.getEntry(newId).groupPath, 'Banking / Cards');

    // delete -> recycle bin
    const mailId = list[1].id;
    assert.equal(vault.deleteEntry(mailId), 'recycled');
    assert.deepEqual(vault.listEntries().map((e) => e.title), ['Amex', 'GitHub', 'Visa']);
    assert.equal(vault.getEntry(mailId).inRecycleBin, true); // a second delete would be permanent (groups.test.js)
    const bin = vault.db.getGroup(vault.db.meta.recycleBinUuid);
    assert.deepEqual(bin.entries.map((e) => fieldText(e.fields.get('Title'))).sort(), ['Mail', 'Old']);
    assert.throws(() => vault.createEntry(bin.uuid.id, { title: 'x' }), /recycle bin/);

    // save + reopen
    const saved = await vault.save();
    vault.markSaved();
    assert.equal(vault.dirty, false);
    const reopened = await Vault.open(saved, PASSWORD);
    assert.deepEqual(reopened.listEntries().map((e) => [e.title, e.groupPath]), [
      ['Amex', 'Banking / Cards'],
      ['GitHub', 'Email'],
      ['Visa', 'Banking / Cards'],
    ]);
    const gh2 = reopened.getEntry(gh.id);
    assert.equal(gh2.password, 'new-secret');
    assert.deepEqual(gh2.tags, ['dev', 'private']);
    assert.deepEqual(gh2.custom, [{ name: 'TOTP', value: 'otp', protected: true }]);
    assert.equal(reopened.getEntry(newId).password, 'amex-pw');

    // wrong password
    await assert.rejects(Vault.open(saved, 'wrong'), (err) => isInvalidKeyError(err));
  });
}

test('key file: required when the database uses one', async () => {
  const keyFile = await Credentials.createRandomKeyFile();
  const bytes = await makeDb({ kdf: 'aes', keyFile });
  await assert.rejects(Vault.open(bytes, PASSWORD), (err) => isInvalidKeyError(err));
  await assert.rejects(Vault.open(bytes, PASSWORD, new Uint8Array(32)), (err) => isInvalidKeyError(err));
  const vault = await Vault.open(bytes, PASSWORD, keyFile.slice().buffer);
  assert.equal(vault.listEntries().length, 3);
});

test('recycle bin disabled: delete removes permanently', async () => {
  const bytes = await makeDb({ recycleBin: false });
  const vault = await Vault.open(bytes, PASSWORD);
  const id = vault.listEntries()[0].id;
  assert.equal(vault.recycleBinEnabled, false);
  // with the bin disabled, the old bin group is a normal group again and its entries are listed
  const before = vault.listEntries().length;
  assert.equal(vault.deleteEntry(id), 'deleted');
  assert.equal(vault.listEntries().length, before - 1);
  assert.equal(vault.db.deletedObjects.some((d) => d.uuid.id === id), true);
});

test('corrupt data is not reported as a wrong password', async () => {
  const bytes = new Uint8Array(await makeDb());
  bytes[0] ^= 0xff;
  await assert.rejects(Vault.open(bytes, PASSWORD), (err) => !isInvalidKeyError(err));
});

test('merge: concurrent edits from two devices are combined', async () => {
  const base = await makeDb({ kdf: 'aes' });
  const a = await Vault.open(base, PASSWORD);
  const b = await Vault.open(base, PASSWORD);
  const ids = Object.fromEntries(a.listEntries().map((e) => [e.title, e.id]));

  // device B edits Visa, adds an entry, deletes Mail, and saves first (server now has B's version)
  await sleep(5);
  b.updateEntry(ids.Visa, { username: '5500' });
  const bNew = b.createEntry(null, { title: 'From B', password: 'b' });
  b.deleteEntry(ids.Mail);
  const remote = await b.save();

  // device A edits GitHub and adds its own entry, then hits a conflict and merges
  await sleep(5);
  a.updateEntry(ids.GitHub, { notes: 'edited on A' });
  const aNew = a.createEntry(null, { title: 'From A', password: 'a' });
  await a.merge(remote);
  assert.equal(a.dirty, true);

  const merged = await Vault.open(await a.save(), PASSWORD);
  const titles = merged.listEntries().map((e) => e.title);
  assert.deepEqual(titles, ['From A', 'From B', 'GitHub', 'Visa']);
  assert.equal(merged.getEntry(ids.GitHub).notes, 'edited on A');
  assert.equal(merged.getEntry(ids.Visa).username, '5500');
  assert.equal(merged.getEntry(aNew).password, 'a');
  assert.equal(merged.getEntry(bNew).password, 'b');
  a.markSaved();
  assert.equal(a.dirty, false);
});

test('merge: the newer edit of the same entry wins, the older one is kept in history', async () => {
  const base = await makeDb();
  const a = await Vault.open(base, PASSWORD);
  const b = await Vault.open(base, PASSWORD);
  const id = a.listEntries()[0].id;
  a.updateEntry(id, { username: 'from-a' });
  // A edited 10 s before B (KDBX times have 1 s resolution, so fake the clock instead of sleeping)
  const entryA = [...a.db.getDefaultGroup().allEntries()].find((e) => e.uuid.id === id);
  entryA.times.lastModTime = new Date(Date.now() - 10000);
  b.updateEntry(id, { username: 'from-b' });
  await a.merge(await b.save());
  assert.equal(a.getEntry(id).username, 'from-b');
  assert.ok(entryA.history.some((h) => fieldText(h.fields.get('UserName')) === 'from-a'));
  // and the reverse direction: B merging A's (older) edit keeps B's value
  const b2 = await Vault.open(await b.save(), PASSWORD);
  await b2.merge(await a.save());
  assert.equal(b2.getEntry(id).username, 'from-b');
});

test('merge: remote encrypted with another password -> InvalidKey', async () => {
  const a = await Vault.open(await makeDb(), PASSWORD);
  const other = await makeDb({ password: 'different' });
  await assert.rejects(a.merge(other), (err) => isInvalidKeyError(err));
});

/** Edits GitHub, adds "New" and group "Work", recycles Mail and group Banking, moves Visa, purges Old. */
function makeChanges(vault) {
  const ids = Object.fromEntries(vault.listEntries().map((e) => [e.title, e.id]));
  const group = (path) => vault.listGroups().find((g) => g.path === path).id;
  vault.updateEntry(ids.GitHub, { notes: 'edited' });
  vault.createEntry(null, { title: 'New' });
  vault.createGroup(null, 'Work');
  vault.deleteEntry(ids.Mail);
  vault.updateEntry(ids.Visa, { groupId: group('Email') });
  vault.deleteGroup(group('Banking')); // Cards goes along without being listed
  const old = vault.getGroupContents(vault.recycleBinId()).entries.find((e) => e.title === 'Old');
  vault.deleteEntry(old.id); // already in the bin: permanent
}

const EXPECTED_CHANGES = [
  ['added', 'entry', 'New'],
  ['added', 'group', 'Work'],
  ['edited', 'entry', 'GitHub'],
  ['moved', 'entry', 'Visa'],
  ['recycled', 'group', 'Banking'],
  ['recycled', 'entry', 'Mail'],
  ['deleted', 'entry', 'Old'],
];
const changeList = (changes) => changes.map((c) => [c.change, c.kind, c.title]);

test('changes: listed against the opened version, reset by markSaved', async () => {
  const vault = await Vault.open(await makeDb(), PASSWORD);
  assert.deepEqual(vault.changes(), []);
  makeChanges(vault);
  assert.deepEqual(changeList(vault.changes()), EXPECTED_CHANGES);
  await vault.save();
  vault.markSaved();
  assert.deepEqual(vault.changes(), []);
});

test('changesSince and openVersion: diff of two saved versions', async () => {
  const base = await makeDb();
  const vault = await Vault.open(base, PASSWORD);
  makeChanges(vault);
  const saved = await vault.openVersion(await vault.save());
  const before = await saved.openVersion(base); // the buffer the vault was opened from is still usable
  assert.deepEqual(changeList(saved.changesSince(before)), EXPECTED_CHANGES);
  assert.deepEqual(before.changesSince(before), []);
  await assert.rejects(saved.openVersion(await makeDb({ password: 'different' })), (err) => isInvalidKeyError(err));
});

test('changes after a merge: only the local edits, not the remote ones', async () => {
  const base = await makeDb();
  const a = await Vault.open(base, PASSWORD);
  const b = await Vault.open(base, PASSWORD);
  const ids = Object.fromEntries(a.listEntries().map((e) => [e.title, e.id]));
  b.updateEntry(ids.Visa, { username: '5500' });
  b.createEntry(null, { title: 'From B' });
  a.updateEntry(ids.GitHub, { notes: 'edited on A' });
  await a.merge(await b.save());
  assert.equal(a.getEntry(ids.Visa).username, '5500');
  assert.deepEqual(changeList(a.changes()), [['edited', 'entry', 'GitHub']]);
});

test('mergeVersion: restores unsaved changes into a fresh copy of the server version', async () => {
  const base = await makeDb();
  const session = await Vault.open(base, PASSWORD);
  makeChanges(session);
  const unsaved = await session.save();

  const server = await Vault.open(base, PASSWORD);
  server.mergeVersion(await server.openVersion(unsaved));
  assert.equal(server.dirty, true);
  assert.deepEqual(changeList(server.changes()), EXPECTED_CHANGES);
  assert.deepEqual(server.listEntries().map((e) => [e.title, e.groupPath]), [
    ['GitHub', 'Test DB'],
    ['New', 'Test DB'],
    ['Visa', 'Email'],
  ]);
});

test('Argon2 adapter: types, KiB units and version check', async () => {
  const pw = new TextEncoder().encode('password').buffer;
  const salt = new TextEncoder().encode('somesaltsomesalt').buffer;
  const d = new Uint8Array(await kdbxArgon2(pw, salt, 64, 1, 32, 1, 0, 0x13));
  const id = new Uint8Array(await kdbxArgon2(pw, salt, 64, 1, 32, 1, 2, 0x13));
  assert.equal(d.length, 32);
  assert.notDeepEqual(d, id);
  await assert.rejects(kdbxArgon2(pw, salt, 64, 1, 32, 1, 2, 0x10), /not supported/);
  await assert.rejects(kdbxArgon2(pw, salt, 64, 1, 32, 1, 1, 0x13), /Unsupported/);
});

test('Argon2 KDBX file opened through kdbxweb matches a direct kdbxweb load', async () => {
  const bytes = await makeDb({ kdf: 'argon2id' });
  const db = await Kdbx.load(bytes, new Credentials(ProtectedValue.fromString(PASSWORD)));
  assert.equal(db.getDefaultGroup().name, 'Test DB');
});

test('safeHttpUrl only allows http(s)', () => {
  assert.equal(safeHttpUrl('https://example.org/a?b=c'), 'https://example.org/a?b=c');
  assert.equal(safeHttpUrl(' http://example.org '), 'http://example.org/');
  for (const bad of [
    'javascript:alert(1)', 'JAVASCRIPT:alert(1)', 'data:text/html,x', '//example.org', 'file:///etc/passwd',
    'mailto:a@example.org', 'user@example.org', 'localhost', 'see notes', 'example', 'example.org/a b',
    '999.1.1.1', 'cmd://calc.exe', '{REF:U@I:46C9B1FFBD4ABC4BBB260C6190BAD20C}', '', null,
  ]) {
    assert.equal(safeHttpUrl(bad), null, String(bad));
  }
});

test('safeHttpUrl links bare hosts as https', () => {
  assert.equal(safeHttpUrl('example.org'), 'https://example.org/');
  assert.equal(safeHttpUrl(' www.Example.org/login?x=1#top '), 'https://www.example.org/login?x=1#top');
  assert.equal(safeHttpUrl('sub.example.co.uk:8443/a'), 'https://sub.example.co.uk:8443/a');
  assert.equal(safeHttpUrl('192.168.178.1'), 'https://192.168.178.1/');
  assert.equal(safeHttpUrl('fritz.box'), 'https://fritz.box/');
});

test('parseTags splits on , and ; and drops duplicates', () => {
  assert.deepEqual(parseTags(' a, b;c ,, a '), ['a', 'b', 'c']);
  assert.deepEqual(parseTags(['x', ' y ', '']), ['x', 'y']);
  assert.deepEqual(parseTags(''), []);
});
