// Thin, UI-independent wrapper around kdbxweb (works in browsers and Node >= 20).
import kdbxweb from 'kdbxweb';
import { installArgon2 } from './argon2.js';
import { toArrayBuffer } from './bytes.js';

const { Kdbx, Credentials, ProtectedValue, KdbxError, Consts } = kdbxweb;

export const STANDARD_FIELDS = ['Title', 'UserName', 'Password', 'URL', 'Notes'];
const CHANGE_KEYS = { title: 'Title', username: 'UserName', password: 'Password', url: 'URL', notes: 'Notes' };

export function fieldText(value) {
  if (value instanceof ProtectedValue) return value.getText();
  return typeof value === 'string' ? value : '';
}

/** True if a kdbxweb error means "wrong password / key file". */
export function isInvalidKeyError(err) {
  return err instanceof KdbxError && err.code === Consts.ErrorCodes.InvalidKey;
}

// A bare host such as "github.com/login" or "192.168.178.1:8443" (KeePass URLs often have no scheme).
const BARE_HOST = /^(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}|(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?::[0-9]{1,5})?(?:[/?#]\S*)?$/i;

/**
 * Only http(s) URLs may be opened from the UI. A bare host gets "https://" prepended.
 * Returns the normalised href or null.
 */
export function safeHttpUrl(raw) {
  if (typeof raw !== 'string' || !raw.trim()) return null;
  let s = raw.trim();
  if (BARE_HOST.test(s)) s = `https://${s}`;
  try {
    const u = new URL(s);
    return (u.protocol === 'http:' || u.protocol === 'https:') && u.hostname ? u.href : null;
  } catch {
    return null;
  }
}

/** Splits a tag string on , ; (as KeePass does) and trims. */
export function parseTags(input) {
  const list = Array.isArray(input) ? input : String(input ?? '').split(/[;,]/);
  const out = [];
  for (const tag of list) {
    const t = String(tag).trim();
    if (t && !out.includes(t)) out.push(t);
  }
  return out;
}

/** Trimmed group name; throws if it is empty. */
function cleanGroupName(name) {
  const clean = String(name ?? '').trim();
  if (!clean) throw new Error('Enter a group name.');
  return clean;
}

function compareTitles(a, b) {
  return a.title.localeCompare(b.title, undefined, { sensitivity: 'base' }) || a.id.localeCompare(b.id);
}

/**
 * Every group and entry by uuid: {kind, title, mod, parent, inBin, listed}. The root and the recycle bin
 * itself are kept (as parents) but not listed as changes.
 */
function snapshot(db) {
  const map = new Map();
  const binId = db.meta.recycleBinUuid?.id;
  const time = (item) => item.times.lastModTime?.getTime() ?? 0;
  const walk = (group, parent, inBin) => {
    const id = group.uuid.id;
    const isBin = id === binId;
    map.set(id, { kind: 'group', title: group.name || '(unnamed)', mod: time(group), parent, inBin, listed: Boolean(parent) && !isBin });
    for (const entry of group.entries) {
      const title = fieldText(entry.fields.get('Title')) || '(untitled)';
      map.set(entry.uuid.id, { kind: 'entry', title, mod: time(entry), parent: id, inBin: inBin || isBin, listed: true });
    }
    for (const child of group.groups) walk(child, id, inBin || isBin);
  };
  walk(db.getDefaultGroup(), '', false);
  return map;
}

const CHANGE_ORDER = ['added', 'edited', 'moved', 'recycled', 'deleted'];

/**
 * What turns snapshot `before` into `after`: [{id, kind, title, change}], change one of CHANGE_ORDER.
 * Items that only moved along with their group (into the bin, or deleted with it) are not listed.
 */
function diffSnapshots(before, after) {
  const out = [];
  for (const [id, a] of after) {
    if (!a.listed) continue;
    const b = before.get(id);
    let change = '';
    if (!b) change = a.inBin ? '' : 'added';
    else if (a.parent !== b.parent && a.inBin && !b.inBin) change = 'recycled';
    else if (a.mod !== b.mod) change = 'edited';
    else if (a.parent !== b.parent) change = 'moved';
    if (change) out.push({ id, kind: a.kind, title: a.title, change });
  }
  for (const [id, b] of before) {
    if (b.listed && !after.has(id) && after.has(b.parent)) out.push({ id, kind: b.kind, title: b.title, change: 'deleted' });
  }
  return out.sort(
    (x, y) =>
      CHANGE_ORDER.indexOf(x.change) - CHANGE_ORDER.indexOf(y.change) ||
      x.title.localeCompare(y.title, undefined, { sensitivity: 'base' }),
  );
}

function makeCredentials(password, keyFile) {
  const pv = password instanceof ProtectedValue ? password : ProtectedValue.fromString(String(password ?? ''));
  const kf = keyFile ? new Uint8Array(toArrayBuffer(keyFile)) : null;
  return new Credentials(pv, kf);
}

function describeKdf(header) {
  const params = header.kdfParameters;
  if (!params) return { name: 'AES-KDF (KDBX3)', rounds: Number(header.keyEncryptionRounds ?? 0) };
  const uuid = params.get('$UUID');
  const id = uuid ? kdbxweb.ByteUtils.bytesToBase64(uuid) : '';
  const num = (v) => (v instanceof kdbxweb.Int64 ? v.value : Number(v));
  if (id === Consts.KdfId.Aes) return { name: 'AES-KDF', rounds: num(params.get('R')) };
  const name = id === Consts.KdfId.Argon2id ? 'Argon2id' : id === Consts.KdfId.Argon2d ? 'Argon2d' : 'unknown';
  return {
    name,
    memoryKiB: num(params.get('M')) / 1024,
    iterations: num(params.get('I')),
    parallelism: num(params.get('P')),
  };
}

export class Vault {
  /** @param {kdbxweb.Kdbx} db */
  constructor(db) {
    this.db = db;
    this.dirty = false;
    this._summaries = null;
    this._base = snapshot(db); // the server version: as opened, last saved or last merged
  }

  /** Decrypts KDBX bytes. Throws kdbxweb.KdbxError (code InvalidKey on wrong credentials). */
  static async open(data, password, keyFile = null) {
    installArgon2();
    const db = await Kdbx.load(toArrayBuffer(data), makeCredentials(password, keyFile));
    return new Vault(db);
  }

  /** Wraps an existing kdbxweb database (used by tests). */
  static fromDb(db) {
    installArgon2();
    return new Vault(db);
  }

  /** Decrypts another version of this database (e.g. an earlier save) with the same credentials. */
  async openVersion(data) {
    installArgon2();
    return new Vault(await Kdbx.load(toArrayBuffer(data), this.db.credentials));
  }

  get name() {
    return this.db.meta.name || 'Vault';
  }

  get info() {
    const h = this.db.header;
    const cipher = h.dataCipherUuid ? kdbxweb.ByteUtils.bytesToBase64(h.dataCipherUuid.bytes) : '';
    return {
      version: `${h.versionMajor}.${h.versionMinor}`,
      cipher: cipher === Consts.CipherId.Aes ? 'AES-256' : cipher === Consts.CipherId.ChaCha20 ? 'ChaCha20' : 'unknown',
      kdf: describeKdf(h),
    };
  }

  get recycleBinEnabled() {
    return Boolean(this.db.meta.recycleBinEnabled);
  }

  _recycleBin() {
    const id = this.db.meta.recycleBinUuid;
    return id ? this.db.getGroup(id) : undefined;
  }

  _changed() {
    this.dirty = true;
    this._summaries = null;
  }

  /** Yields [group, pathNames[]] for every group outside the recycle bin (root first). */
  *_groups() {
    const bin = this._recycleBin();
    const root = this.db.getDefaultGroup();
    const walk = function* (group, path) {
      yield [group, path];
      for (const child of group.groups) {
        if (bin && child === bin) continue;
        yield* walk(child, [...path, child.name || '(unnamed)']);
      }
    };
    yield* walk(root, []);
  }

  /**
   * [{id, name, path, depth}] in tree order (parents before children). path is the root's name for the
   * root group, else "A / B"; depth is 0 for the root. Excludes the recycle bin.
   */
  listGroups() {
    const out = [];
    for (const [group, path] of this._groups()) {
      out.push({
        id: group.uuid.id,
        name: group.name || '',
        path: path.length ? path.join(' / ') : group.name || 'Root',
        depth: path.length,
      });
    }
    return out;
  }

  // ------------------------------------------------------------ group navigation

  rootGroupId() {
    return this.db.getDefaultGroup().uuid.id;
  }

  /** Id of the recycle bin group, or null if there is none. */
  recycleBinId() {
    const bin = this._recycleBin();
    return bin ? bin.uuid.id : null;
  }

  /** True if the group is the recycle bin or inside it. Unknown ids return false. */
  isInRecycleBin(groupId) {
    const group = groupId ? this.db.getGroup(groupId) : this.db.getDefaultGroup();
    return Boolean(group) && this._inBin(group);
  }

  _inBin(group, bin = this._recycleBin()) {
    return Boolean(bin) && this._isWithin(group, bin);
  }

  /** True if `group` is `ancestor` or one of its descendants. */
  _isWithin(group, ancestor) {
    for (let g = group; g; g = g.parentGroup) {
      if (g === ancestor) return true;
    }
    return false;
  }

  /** Any group including the recycle bin (null/'' = root). */
  _anyGroup(id) {
    const group = id ? this.db.getGroup(id) : this.db.getDefaultGroup();
    if (!group) throw new Error('Group not found');
    return group;
  }

  _groupName(group) {
    if (group === this.db.getDefaultGroup()) return group.name || 'Root';
    return group.name || '(unnamed)';
  }

  /** Subgroups in display order: file order (as KeePass shows them), the recycle bin last. */
  _childGroups(group, bin = this._recycleBin()) {
    const children = group.groups.filter((g) => g !== bin);
    if (bin && group.groups.includes(bin)) children.push(bin);
    return children;
  }

  _groupInfo(group, bin = this._recycleBin()) {
    return {
      id: group.uuid.id,
      name: this._groupName(group),
      isRoot: group === this.db.getDefaultGroup(),
      isRecycleBin: Boolean(bin) && group === bin,
      inRecycleBin: this._inBin(group, bin),
      entryCount: group.entries.length,
      groupCount: group.groups.length,
    };
  }

  _pathOf(group) {
    const path = [];
    for (let g = group; g; g = g.parentGroup) path.unshift({ id: g.uuid.id, name: this._groupName(g) });
    return path;
  }

  /**
   * The whole group hierarchy including the recycle bin:
   * {id, name, isRoot, isRecycleBin, inRecycleBin, entryCount, groupCount, children: [...]}.
   * Counts are direct children only.
   */
  getGroupTree() {
    const bin = this._recycleBin();
    const walk = (group) => ({ ...this._groupInfo(group, bin), children: this._childGroups(group, bin).map(walk) });
    return walk(this.db.getDefaultGroup());
  }

  /** Breadcrumb [{id, name}] from the root to the group (inclusive). */
  getGroupPath(groupId) {
    return this._pathOf(this._anyGroup(groupId));
  }

  /**
   * What a folder view of one group shows (null = root; the recycle bin is allowed):
   * {group: info, path: [{id, name}], groups: [info], entries: [summary sorted by title]}.
   */
  getGroupContents(groupId) {
    const group = this._anyGroup(groupId);
    const path = this._pathOf(group);
    const names = path.slice(1).map((p) => p.name);
    const entries = group.entries.map((e) => this._summary(e, names, path[0].name)).sort(compareTitles);
    const bin = this._recycleBin();
    return {
      group: this._groupInfo(group, bin),
      path,
      groups: this._childGroups(group, bin).map((g) => this._groupInfo(g, bin)),
      entries,
    };
  }

  // ------------------------------------------------------------ group management

  /** Creates a subgroup (parent null = root; not inside the recycle bin). Returns the new group id. */
  createGroup(parentId, name) {
    const parent = this._group(parentId);
    const group = this.db.createGroup(parent, cleanGroupName(name));
    this._changed();
    return group.uuid.id;
  }

  /** Renames a group (not the root, not the recycle bin or groups in it). Returns true if the name changed. */
  renameGroup(id, name) {
    const group = this._group(id);
    if (group === this.db.getDefaultGroup()) throw new Error('The root group cannot be renamed');
    const clean = cleanGroupName(name);
    if (clean === (group.name || '')) return false;
    group.name = clean;
    group.times.update();
    this._changed();
    return true;
  }

  /**
   * Deletes a group with everything in it: moves it to the recycle bin ('recycled'), or deletes it
   * permanently ('deleted') if it is already inside the bin or the bin is disabled.
   * The root and the recycle bin itself cannot be deleted.
   */
  deleteGroup(id) {
    const group = this._anyGroup(id);
    const bin = this._recycleBin();
    if (group === this.db.getDefaultGroup()) throw new Error('The root group cannot be deleted');
    if (bin && group === bin) throw new Error('The recycle bin cannot be deleted');
    let result;
    if (this._inBin(group)) {
      this.db.move(group, null);
      result = 'deleted';
    } else {
      if (bin && this._isWithin(bin, group)) throw new Error('This group contains the recycle bin and cannot be deleted');
      result = this._remove(group);
    }
    this._changed();
    return result;
  }

  /** Recycles (bin enabled; created if missing) or permanently deletes an entry or group. */
  _remove(object) {
    const recycle = this.recycleBinEnabled;
    // No-op if the bin exists. Without it, kdbxweb's remove() would delete permanently despite the setting.
    if (recycle) this.db.createRecycleBin();
    this.db.remove(object);
    return recycle ? 'recycled' : 'deleted';
  }

  _summary(entry, path, rootName) {
    const f = entry.fields;
    return {
      id: entry.uuid.id,
      title: fieldText(f.get('Title')),
      username: fieldText(f.get('UserName')),
      url: fieldText(f.get('URL')),
      notes: fieldText(f.get('Notes')),
      tags: entry.tags.slice(),
      groupId: entry.parentGroup ? entry.parentGroup.uuid.id : '',
      groupPath: path.length ? path.join(' / ') : rootName,
    };
  }

  /** All entries outside the recycle bin, sorted by title. Cached until the next change. */
  listEntries() {
    if (!this._summaries) {
      const rootName = this.db.getDefaultGroup().name || 'Root';
      const list = [];
      for (const [group, path] of this._groups()) {
        for (const entry of group.entries) list.push(this._summary(entry, path, rootName));
      }
      list.sort(compareTitles);
      this._summaries = list;
    }
    return this._summaries.map((s) => ({ ...s, tags: s.tags.slice() }));
  }

  /** Case-insensitive search over title, username, URL, notes and tags; all terms must match. */
  search(query) {
    const terms = String(query ?? '').toLowerCase().split(/\s+/).filter(Boolean);
    const list = this.listEntries();
    if (!terms.length) return list;
    return list.filter((e) => {
      const hay = [e.title, e.username, e.url, e.notes, e.tags.join(' ')].join('\n').toLowerCase();
      return terms.every((t) => hay.includes(t));
    });
  }

  _entry(id) {
    for (const entry of this.db.getDefaultGroup().allEntries()) {
      if (entry.uuid.id === id) return entry;
    }
    throw new Error('Entry not found');
  }

  /** A group outside the recycle bin (null/'' = root); throws for the bin and groups inside it. */
  _group(id) {
    const group = this._anyGroup(id);
    if (this._inBin(group)) throw new Error('Cannot use the recycle bin');
    return group;
  }

  _path(group) {
    const names = [];
    for (let g = group; g && g.parentGroup; g = g.parentGroup) names.unshift(g.name || '(unnamed)');
    return names.length ? names.join(' / ') : group?.name || 'Root';
  }

  /** Full entry data including the password and custom string fields. */
  getEntry(id) {
    const entry = this._entry(id);
    const f = entry.fields;
    const custom = [];
    for (const [name, value] of f) {
      if (STANDARD_FIELDS.includes(name)) continue;
      custom.push({ name, value: fieldText(value), protected: value instanceof ProtectedValue });
    }
    custom.sort((a, b) => a.name.localeCompare(b.name));
    return {
      id: entry.uuid.id,
      title: fieldText(f.get('Title')),
      username: fieldText(f.get('UserName')),
      password: fieldText(f.get('Password')),
      url: fieldText(f.get('URL')),
      notes: fieldText(f.get('Notes')),
      tags: entry.tags.slice(),
      custom,
      groupId: entry.parentGroup ? entry.parentGroup.uuid.id : '',
      groupPath: this._path(entry.parentGroup),
      inRecycleBin: this._inBin(entry.parentGroup),
      created: entry.times.creationTime || null,
      modified: entry.times.lastModTime || null,
    };
  }

  getField(id, name) {
    return fieldText(this._entry(id).fields.get(name));
  }

  _protectByDefault(name) {
    const mp = this.db.meta.memoryProtection || {};
    switch (name) {
      case 'Password':
        return true;
      case 'Title':
        return Boolean(mp.title);
      case 'UserName':
        return Boolean(mp.userName);
      case 'URL':
        return Boolean(mp.url);
      case 'Notes':
        return Boolean(mp.notes);
      default:
        return false;
    }
  }

  _setField(entry, name, text, forceProtect) {
    const old = entry.fields.get(name);
    const protect = name === 'Password' || forceProtect || old instanceof ProtectedValue || (old === undefined && this._protectByDefault(name));
    entry.fields.set(name, protect ? ProtectedValue.fromString(text) : text);
  }

  /** Normalises a change set into [[fieldName, text, protect?]] containing only real changes. */
  _diff(entry, changes) {
    const out = [];
    for (const [key, name] of Object.entries(CHANGE_KEYS)) {
      if (changes[key] === undefined) continue;
      const text = String(changes[key]);
      if (text !== fieldText(entry.fields.get(name))) out.push([name, text, false]);
    }
    if (changes.custom) {
      for (const [name, val] of Object.entries(changes.custom)) {
        if (STANDARD_FIELDS.includes(name) || !name) continue;
        const text = typeof val === 'object' && val !== null ? String(val.value ?? '') : String(val);
        const protect = typeof val === 'object' && val !== null ? Boolean(val.protected) : false;
        const old = entry.fields.get(name);
        if (old === undefined || text !== fieldText(old)) out.push([name, text, protect]);
      }
    }
    return out;
  }

  /**
   * Applies changes {title, username, password, url, notes, tags, custom: {name: value}, groupId}.
   * Pushes the previous state to history first (kdbxweb edit protocol). Returns true if anything changed.
   */
  updateEntry(id, changes = {}) {
    const entry = this._entry(id);
    const fields = this._diff(entry, changes);
    const newTags = changes.tags !== undefined ? parseTags(changes.tags) : null;
    const tagsChanged = newTags && newTags.join('\u0000') !== entry.tags.join('\u0000');
    const target = changes.groupId && changes.groupId !== entry.parentGroup?.uuid.id ? this._group(changes.groupId) : null;
    if (!fields.length && !tagsChanged && !target) return false;

    if (fields.length || tagsChanged) {
      entry.pushHistory();
      for (const [name, text, protect] of fields) this._setField(entry, name, text, protect);
      if (tagsChanged) entry.tags = newTags;
      entry.times.update();
      const max = this.db.meta.historyMaxItems;
      if (typeof max === 'number' && max >= 0 && entry.history.length > max) {
        entry.removeHistory(0, entry.history.length - max);
      }
    }
    if (target) this.db.move(entry, target);
    this._changed();
    return true;
  }

  /** Creates an entry in the given group (default: root). Returns the new entry id. */
  createEntry(groupId, changes = {}) {
    const group = this._group(groupId);
    const entry = this.db.createEntry(group);
    for (const [name, text, protect] of this._diff(entry, changes)) this._setField(entry, name, text, protect);
    if (changes.tags !== undefined) entry.tags = parseTags(changes.tags);
    entry.times.update();
    this._changed();
    return entry.uuid.id;
  }

  /**
   * Moves the entry to the recycle bin ('recycled'). Deletes it permanently ('deleted') if it is
   * already in the bin or the bin is disabled.
   */
  deleteEntry(id) {
    const entry = this._entry(id);
    let result;
    if (this._inBin(entry.parentGroup)) {
      this.db.move(entry, null); // null target = permanent delete (adds a deletedObjects tombstone)
      result = 'deleted';
    } else {
      result = this._remove(entry);
    }
    this._changed();
    return result;
  }

  /** Encrypts the database. Does not clear the dirty flag (call markSaved after a successful upload). */
  async save() {
    return this.db.save();
  }

  /**
   * Merges a remote version (e.g. after a 409 conflict) into this database, using the same credentials.
   * Throws KdbxError InvalidKey if the remote can no longer be decrypted (master key changed elsewhere).
   */
  async merge(remoteData) {
    installArgon2();
    const remote = await Kdbx.load(toArrayBuffer(remoteData), this.db.credentials);
    const base = snapshot(remote);
    this.db.merge(remote);
    this._base = base;
    this._changed();
  }

  /**
   * Merges another local version (e.g. changes an earlier session could not upload) into this one.
   * The result is unsaved; `other` must not be used afterwards.
   */
  mergeVersion(other) {
    this.db.merge(other.db);
    this._changed();
  }

  /** Entries and groups changed since the version opened, last saved or merged: [{id, kind, title, change}]. */
  changes() {
    return diffSnapshots(this._base, snapshot(this.db));
  }

  /** Entries and groups that differ from `older`, another version of this database. */
  changesSince(older) {
    return diffSnapshots(snapshot(older.db), snapshot(this.db));
  }

  /** Call after the server accepted the saved bytes. */
  markSaved() {
    this.db.removeLocalEditState();
    this.dirty = false;
    this._base = snapshot(this.db);
  }

  close() {
    this.db = null;
    this._summaries = null;
    this._base = null;
    this.dirty = false;
  }
}
