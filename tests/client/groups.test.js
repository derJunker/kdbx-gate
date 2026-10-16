import test from 'node:test';
import assert from 'node:assert/strict';
import { Vault } from '../../src/vault.js';
import { makeDb, PASSWORD } from './helpers.mjs';

// Fixture (helpers.mjs): root "Test DB" (GitHub) > [Recycle Bin (Old), Email (Mail), Banking > Cards (Visa)].
// kdbxweb creates the recycle bin as the root's *first* child; the UI lists it last.

async function openFixture(opts) {
  return Vault.open(await makeDb(opts), PASSWORD);
}

/** {name: [childNames...]}-style compact view of a tree node. */
function shape(node) {
  return node.children.length ? { [node.name]: node.children.map(shape) } : node.name;
}

function groupId(vault, path) {
  const g = vault.listGroups().find((x) => x.path === path);
  assert.ok(g, `group ${path} not found`);
  return g.id;
}

const titles = (list) => list.map((e) => e.title);

test('getGroupTree: nested shape, recycle bin last, flags and direct counts', async () => {
  const vault = await openFixture();
  const tree = vault.getGroupTree();
  assert.deepEqual(shape(tree), { 'Test DB': ['Email', { Banking: ['Cards'] }, 'Recycle Bin'] });

  assert.equal(tree.id, vault.rootGroupId());
  assert.equal(tree.isRoot, true);
  assert.equal(tree.entryCount, 1); // GitHub
  assert.equal(tree.groupCount, 3); // Email, Banking, Recycle Bin

  const [email, banking, bin] = tree.children;
  assert.deepEqual([email.isRecycleBin, banking.isRecycleBin, bin.isRecycleBin], [false, false, true]);
  assert.deepEqual([email.inRecycleBin, bin.inRecycleBin], [false, true]);
  assert.equal(bin.id, vault.recycleBinId());
  assert.equal(email.entryCount, 1);
  assert.deepEqual([banking.entryCount, banking.groupCount], [0, 1]);
  assert.equal(banking.children[0].entryCount, 1);
  assert.equal(bin.entryCount, 1);
});

test('getGroupContents: root, nested group, recycle bin, breadcrumb path', async () => {
  const vault = await openFixture();

  const root = vault.getGroupContents(null);
  assert.deepEqual(root.group, vault.getGroupContents(vault.rootGroupId()).group);
  assert.equal(root.group.name, 'Test DB');
  assert.deepEqual(root.path.map((p) => p.name), ['Test DB']);
  assert.deepEqual(root.groups.map((g) => g.name), ['Email', 'Banking', 'Recycle Bin']);
  assert.deepEqual(titles(root.entries), ['GitHub']);
  assert.equal(root.entries[0].username, 'alice');

  const cardsId = groupId(vault, 'Banking / Cards');
  const cards = vault.getGroupContents(cardsId);
  assert.deepEqual(cards.path.map((p) => p.name), ['Test DB', 'Banking', 'Cards']);
  assert.deepEqual(cards.path.map((p) => p.id), [vault.rootGroupId(), groupId(vault, 'Banking'), cardsId]);
  assert.deepEqual(cards.path, vault.getGroupPath(cardsId));
  assert.deepEqual(cards.groups, []);
  assert.deepEqual(titles(cards.entries), ['Visa']);
  assert.equal(cards.entries[0].groupPath, 'Banking / Cards');
  assert.deepEqual([cards.group.isRoot, cards.group.isRecycleBin, cards.group.inRecycleBin], [false, false, false]);

  const bin = vault.getGroupContents(vault.recycleBinId());
  assert.deepEqual([bin.group.isRecycleBin, bin.group.inRecycleBin], [true, true]);
  assert.deepEqual(bin.path.map((p) => p.name), ['Test DB', 'Recycle Bin']);
  assert.deepEqual(titles(bin.entries), ['Old']);

  // entries are sorted by title within a group
  vault.createEntry(cardsId, { title: 'amex' });
  vault.createEntry(cardsId, { title: 'Bank card' });
  assert.deepEqual(titles(vault.getGroupContents(cardsId).entries), ['amex', 'Bank card', 'Visa']);

  assert.throws(() => vault.getGroupContents('AAAAAAAAAAAAAAAAAAAAAA=='), /not found/);
  assert.throws(() => vault.getGroupPath('nope'), /not found/);
});

test('isInRecycleBin, rootGroupId and listGroups depth for the edit form', async () => {
  const vault = await openFixture();
  assert.equal(vault.isInRecycleBin(vault.recycleBinId()), true);
  assert.equal(vault.isInRecycleBin(vault.rootGroupId()), false);
  assert.equal(vault.isInRecycleBin(null), false);
  assert.equal(vault.isInRecycleBin(groupId(vault, 'Email')), false);
  assert.equal(vault.isInRecycleBin('unknown'), false);

  assert.deepEqual(
    vault.listGroups().map((g) => [g.name, g.depth]),
    [['Test DB', 0], ['Email', 1], ['Banking', 1], ['Cards', 2]],
  );

  // a group deleted into the bin counts as inside it, and so do its subgroups
  const bankingId = groupId(vault, 'Banking');
  const cardsId = groupId(vault, 'Banking / Cards');
  vault.deleteGroup(bankingId);
  assert.equal(vault.isInRecycleBin(bankingId), true);
  assert.equal(vault.isInRecycleBin(cardsId), true);
  assert.equal(vault.getGroupContents(cardsId).group.inRecycleBin, true);
  assert.deepEqual(vault.listGroups().map((g) => g.path), ['Test DB', 'Email']);
});

test('createGroup: nested creation, trimmed names, validation, dirty flag', async () => {
  const vault = await openFixture();
  assert.equal(vault.dirty, false);

  const work = vault.createGroup(null, '  Work  ');
  assert.equal(vault.dirty, true);
  const servers = vault.createGroup(work, 'Servers');
  const prod = vault.createGroup(servers, 'Prod');
  assert.deepEqual(vault.getGroupPath(prod).map((p) => p.name), ['Test DB', 'Work', 'Servers', 'Prod']);
  assert.deepEqual(shape(vault.getGroupTree()), {
    'Test DB': ['Email', { Banking: ['Cards'] }, { Work: [{ Servers: ['Prod'] }] }, 'Recycle Bin'],
  });
  assert.deepEqual(vault.listGroups().find((g) => g.id === prod), { id: prod, name: 'Prod', path: 'Work / Servers / Prod', depth: 3 });

  // entries can be created in the new group
  const id = vault.createEntry(prod, { title: 'db1', username: 'root' });
  assert.equal(vault.getEntry(id).groupPath, 'Work / Servers / Prod');
  assert.deepEqual(titles(vault.getGroupContents(prod).entries), ['db1']);

  for (const bad of ['', '   ', null, undefined]) {
    assert.throws(() => vault.createGroup(null, bad), /group name/i, String(bad));
  }
  assert.throws(() => vault.createGroup(vault.recycleBinId(), 'x'), /recycle bin/);
  assert.throws(() => vault.createGroup('unknown', 'x'), /not found/);
});

test('renameGroup: renames, no-op detection, root and recycle bin protected', async () => {
  const vault = await openFixture();
  const emailId = groupId(vault, 'Email');
  const group = vault.db.getGroup(emailId);
  const before = group.times.lastModTime.getTime();

  assert.equal(vault.renameGroup(emailId, 'Email'), false);
  assert.equal(vault.dirty, false);
  assert.equal(vault.renameGroup(emailId, ' Mail accounts '), true);
  assert.equal(vault.dirty, true);
  assert.equal(group.name, 'Mail accounts');
  assert.ok(group.times.lastModTime.getTime() > before, 'lastModTime updated (wins in merges)');
  assert.equal(vault.getEntry(vault.search('webmail')[0].id).groupPath, 'Mail accounts');

  assert.throws(() => vault.renameGroup(emailId, '  '), /group name/i);
  assert.throws(() => vault.renameGroup(vault.rootGroupId(), 'x'), /root/);
  assert.throws(() => vault.renameGroup(null, 'x'), /root/);
  assert.throws(() => vault.renameGroup(vault.recycleBinId(), 'Trash'), /recycle bin/);
});

test('deleteGroup: to the recycle bin with its contents, then permanently from inside the bin', async () => {
  const vault = await openFixture();
  const bankingId = groupId(vault, 'Banking');
  const cardsId = groupId(vault, 'Banking / Cards');
  const visaId = vault.search('visa')[0].id;

  assert.equal(vault.deleteGroup(bankingId), 'recycled');
  assert.equal(vault.dirty, true);
  assert.deepEqual(shape(vault.getGroupTree()), {
    'Test DB': ['Email', { 'Recycle Bin': [{ Banking: ['Cards'] }] }],
  });
  // search and the flat list exclude everything in the bin
  assert.deepEqual(titles(vault.search('visa')), []);
  assert.deepEqual(titles(vault.listEntries()), ['GitHub', 'Mail']);
  assert.equal(vault.getEntry(visaId).inRecycleBin, true);
  assert.deepEqual(vault.getGroupContents(vault.recycleBinId()).groups.map((g) => g.name), ['Banking']);

  // deleting inside the bin is permanent and leaves tombstones for the group and everything in it
  assert.equal(vault.deleteGroup(bankingId), 'deleted');
  assert.deepEqual(shape(vault.getGroupTree()), { 'Test DB': ['Email', 'Recycle Bin'] });
  const tombstones = vault.db.deletedObjects.map((d) => d.uuid.id);
  for (const id of [bankingId, cardsId, visaId]) assert.ok(tombstones.includes(id), `tombstone for ${id}`);
  assert.throws(() => vault.getEntry(visaId), /not found/);
  assert.throws(() => vault.getGroupContents(bankingId), /not found/);
});

test('deleteGroup: root, recycle bin and a group containing the bin are protected', async () => {
  const vault = await openFixture();
  assert.throws(() => vault.deleteGroup(vault.rootGroupId()), /root/);
  assert.throws(() => vault.deleteGroup(null), /root/);
  assert.throws(() => vault.deleteGroup(vault.recycleBinId()), /recycle bin/);
  assert.throws(() => vault.deleteGroup('unknown'), /not found/);
  assert.equal(vault.dirty, false);

  // a (hand-made) file where the bin sits inside a normal group: moving that group into the bin would be a cycle
  const email = vault.db.getGroup(groupId(vault, 'Email'));
  vault.db.move(vault.db.getGroup(vault.recycleBinId()), email);
  assert.throws(() => vault.deleteGroup(email.uuid.id), /contains the recycle bin/);
});

test('deleteGroup with the recycle bin disabled deletes permanently', async () => {
  const vault = await openFixture({ recycleBin: false });
  const emailId = groupId(vault, 'Email');
  assert.equal(vault.deleteGroup(emailId), 'deleted');
  assert.ok(vault.db.deletedObjects.some((d) => d.uuid.id === emailId));
  assert.deepEqual(titles(vault.listEntries()), ['GitHub', 'Visa']);
});

test('deleteEntry: permanent inside the recycle bin, bin re-created if missing', async () => {
  const vault = await openFixture();
  const binId = vault.recycleBinId();
  const oldId = vault.getGroupContents(binId).entries[0].id;
  assert.equal(vault.getEntry(oldId).inRecycleBin, true);
  assert.equal(vault.deleteEntry(oldId), 'deleted');
  assert.equal(vault.dirty, true);
  assert.deepEqual(vault.getGroupContents(binId).entries, []);
  assert.ok(vault.db.deletedObjects.some((d) => d.uuid.id === oldId));
  assert.throws(() => vault.getEntry(oldId), /not found/);

  // an entry inside a deleted group is in the bin too
  const visaId = vault.search('visa')[0].id;
  vault.deleteGroup(groupId(vault, 'Banking'));
  assert.equal(vault.deleteEntry(visaId), 'deleted');

  // bin enabled but its group is gone: kdbxweb alone would delete permanently; we create a new bin instead
  const other = await openFixture();
  other.db.meta.recycleBinUuid = undefined;
  const ghId = other.search('github')[0].id;
  assert.equal(other.deleteEntry(ghId), 'recycled');
  assert.ok(other.recycleBinId());
  assert.equal(other.getEntry(ghId).inRecycleBin, true);
  assert.ok(!other.db.deletedObjects.some((d) => d.uuid.id === ghId));
});

test('an entry in the recycle bin can be restored by moving it to another group', async () => {
  const vault = await openFixture();
  const oldId = vault.getGroupContents(vault.recycleBinId()).entries[0].id;
  assert.equal(vault.updateEntry(oldId, { groupId: groupId(vault, 'Email') }), true);
  assert.equal(vault.getEntry(oldId).inRecycleBin, false);
  assert.deepEqual(titles(vault.search('zebra')), ['Old']);
});

test('dirty flag: group operations mark the vault dirty, markSaved clears it', async () => {
  const vault = await openFixture();
  const ops = [
    (v) => v.createGroup(null, 'New'),
    (v) => v.renameGroup(groupId(v, 'Email'), 'Inbox'),
    (v) => v.deleteGroup(groupId(v, 'Inbox')),
    (v) => v.deleteEntry(v.getGroupContents(v.recycleBinId()).entries[0].id),
  ];
  for (const op of ops) {
    op(vault);
    assert.equal(vault.dirty, true);
    await vault.save();
    vault.markSaved();
    assert.equal(vault.dirty, false);
  }
  // read-only calls do not mark it dirty
  vault.getGroupTree();
  vault.getGroupContents(null);
  vault.getGroupPath(null);
  vault.isInRecycleBin(null);
  assert.equal(vault.dirty, false);
});

test('save round trip keeps the group structure, renames and deletions', async () => {
  const vault = await openFixture();
  const work = vault.createGroup(null, 'Work');
  const servers = vault.createGroup(work, 'Servers');
  vault.createEntry(servers, { title: 'db1', username: 'root', password: 'pw' });
  vault.renameGroup(groupId(vault, 'Banking'), 'Finance');
  vault.deleteGroup(groupId(vault, 'Email'));
  const expected = {
    'Test DB': [{ Finance: ['Cards'] }, { Work: ['Servers'] }, { 'Recycle Bin': ['Email'] }],
  };
  assert.deepEqual(shape(vault.getGroupTree()), expected);

  const reopened = await Vault.open(await vault.save(), PASSWORD);
  assert.deepEqual(shape(reopened.getGroupTree()), expected);
  assert.equal(reopened.recycleBinId(), vault.recycleBinId());
  const s = reopened.getGroupContents(servers);
  assert.deepEqual(s.path.map((p) => p.name), ['Test DB', 'Work', 'Servers']);
  assert.deepEqual(titles(s.entries), ['db1']);
  assert.equal(reopened.getEntry(s.entries[0].id).password, 'pw');
  assert.deepEqual(titles(reopened.getGroupContents(reopened.recycleBinId()).entries), ['Old']);
  assert.deepEqual(titles(reopened.search('mail')), []); // Mail went to the bin with its group
  assert.deepEqual(titles(reopened.listEntries()), ['db1', 'GitHub', 'Visa']);
});

test('merge: a group renamed on one device and a group created on another are both kept', async () => {
  const base = await makeDb();
  const a = await Vault.open(base, PASSWORD);
  const b = await Vault.open(base, PASSWORD);
  b.createGroup(null, 'From B');
  a.renameGroup(groupId(a, 'Email'), 'Inbox');
  await a.merge(await b.save());
  assert.deepEqual(
    a.getGroupContents(null).groups.map((g) => g.name),
    ['Inbox', 'Banking', 'From B', 'Recycle Bin'],
  );
});

test('group names are returned as plain data (no markup handling needed by callers)', async () => {
  const vault = await openFixture();
  const id = vault.createGroup(null, '<img src=x onerror=alert(1)>');
  const info = vault.getGroupContents(null).groups.find((g) => g.id === id);
  assert.equal(info.name, '<img src=x onerror=alert(1)>');
  // unnamed groups get a placeholder for display
  vault.db.getGroup(id).name = '';
  assert.equal(vault.getGroupContents(id).group.name, '(unnamed)');
});
