// kdbx-gate browser app (bundled to dist/app.js as an IIFE).
import { createApi, isSecureLocation, isPubliclyReadable } from './api.js';
import { deriveAuthToken } from './kdf.js';
import { Vault, isInvalidKeyError, safeHttpUrl } from './vault.js';
import { generatePassword, estimateBits } from './passgen.js';
import { copyText } from './clipboard.js';
import { lastLoginText } from './lastlogin.js';
import { byId, h, show, mmss, downloadBlob, setStatus, errorMessage } from './dom.js';

const AUTO_LOCK_MS = 5 * 60 * 1000;
const MASK = '••••••••••';
const MAX_TREE_DEPTH = 6; // deeper sidebar levels share the last indentation step (CSS .depth-6)
const INDENT = '   '; // per level in the group <select>
const BIN_NOTE =
  'Deleted items. Deleting them here removes them permanently. ' +
  'To restore an entry, edit it and choose another group.';
const DECRYPT_FAILED =
  'Server accepted the password but the vault could not be decrypted. ' +
  'Re-run setup if you changed the master password, or provide the key file.';

const api = createApi({ baseUrl: 'api.php', location: window.location });

const state = {
  secure: false,
  token: null,
  rev: null,
  vault: null,
  currentId: null, // entry shown in the detail view
  editingId: null, // entry being edited (null = new entry)
  groupId: null, // group shown in the list view (kept while unlocked)
  expanded: new Set(), // sidebar tree: ids of expanded groups
  busy: false,
  retryUntil: 0,
  countdown: null,
  lastActivity: Date.now(),
  statusTimer: null,
};

let el = {};

function cacheElements() {
  const ids = [
    'warnings', 'view-lock', 'lock-form', 'lock-password', 'keyfile-toggle', 'keyfile-row', 'lock-keyfile',
    'unlock-btn', 'lock-status', 'view-app', 'vault-name', 'dirty-badge', 'btn-save', 'btn-lock', 'last-login', 'search',
    'app-status', 'view-list', 'btn-add', 'list-count', 'entry-list', 'btn-download', 'view-entry',
    'group-tree', 'breadcrumb', 'btn-group-new', 'group-tools', 'btn-group-rename', 'btn-group-delete', 'group-note',
    'entry-detail', 'btn-entry-back', 'btn-entry-edit', 'btn-entry-delete', 'view-edit', 'edit-heading',
    'edit-form', 'edit-title', 'edit-username', 'edit-password', 'edit-password-reveal', 'gen-toggle',
    'gen-panel', 'gen-length', 'gen-lower', 'gen-upper', 'gen-digits', 'gen-symbols', 'gen-ambiguous',
    'gen-run', 'gen-info', 'edit-url', 'edit-notes', 'edit-tags', 'edit-group', 'edit-custom', 'edit-cancel',
  ];
  el = {};
  for (const id of ids) el[id.replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = byId(id);
}

// ---------------------------------------------------------------- status helpers

function lockStatus(type, text) {
  setStatus(el.lockStatus, type, text);
}

function appStatus(type, text, autoClearMs = 0) {
  clearTimeout(state.statusTimer);
  setStatus(el.appStatus, type, text);
  if (autoClearMs) state.statusTimer = setTimeout(() => setStatus(el.appStatus, '', ''), autoClearMs);
}

function addWarning(text) {
  el.warnings.append(h('p', { class: 'banner banner-error', text }));
}

function stopCountdown() {
  clearInterval(state.countdown);
  state.countdown = null;
}

/** Live "Locked, try again in mm:ss" countdown on the lock screen. */
function startCountdown(seconds, prefix = '') {
  stopCountdown();
  state.retryUntil = Date.now() + seconds * 1000;
  const tick = () => {
    const left = Math.ceil((state.retryUntil - Date.now()) / 1000);
    if (left <= 0) {
      stopCountdown();
      state.retryUntil = 0;
      el.unlockBtn.disabled = state.busy || !state.secure;
      lockStatus('info', 'You can try again now.');
      return;
    }
    el.unlockBtn.disabled = true;
    lockStatus('error', `${prefix}Locked, try again in ${mmss(left)}.`);
  };
  tick();
  state.countdown = setInterval(tick, 1000);
}

function setBusy(busy) {
  state.busy = busy;
  el.unlockBtn.disabled = busy || !state.secure || state.retryUntil > Date.now();
  const buttons = [
    el.btnSave, el.btnLock, el.btnDownload, el.btnAdd, el.btnEntryEdit, el.btnEntryDelete,
    el.btnGroupNew, el.btnGroupRename, el.btnGroupDelete,
  ];
  for (const b of buttons) {
    b.disabled = busy;
  }
  document.body.classList.toggle('busy', busy);
}

/** Maps gate errors (401/429/404/503/...) to lock-screen messages. */
function showGateError(err) {
  switch (err.code) {
    case 'bad_token':
      if (err.attemptsLeft > 0) {
        const n = err.attemptsLeft;
        lockStatus('error', `Wrong password, ${n} attempt${n === 1 ? '' : 's'} left before delay.`);
      } else if (err.retryAfter > 0) {
        startCountdown(err.retryAfter, 'Wrong password. ');
      } else {
        lockStatus('error', 'Wrong password.');
      }
      break;
    case 'locked':
      startCountdown(err.retryAfter > 0 ? err.retryAfter : 1);
      break;
    case 'no_vault':
      lockStatus('error', 'Password accepted, but there is no vault on the server. Upload your .kdbx file as data/vault.kdbx.');
      break;
    case 'not_configured':
      lockStatus('error', 'The server is not configured yet. Run setup.html and upload data/config.php.');
      break;
    default:
      lockStatus('error', errorMessage(err));
  }
}

// ---------------------------------------------------------------- startup checks

async function checkExposure() {
  const [vaultOpen, configOpen] = await Promise.all([
    isPubliclyReadable('data/vault.kdbx'),
    isPubliclyReadable('data/config.php'),
  ]);
  if (vaultOpen || configOpen) {
    addWarning(
      'Warning: the data/ directory is publicly readable (' +
        [vaultOpen && 'data/vault.kdbx', configOpen && 'data/config.php'].filter(Boolean).join(', ') +
        ' returned HTTP 200). Anyone can download your encrypted vault without the rate limit. ' +
        'Make sure data/.htaccess is uploaded and your host honours it, or move the vault outside the web root.',
    );
  }
}

async function refreshStatus() {
  if (!state.secure) return;
  try {
    const st = await api.getStatus();
    if (st.retryAfter > 0) startCountdown(st.retryAfter);
    else if (st.attemptsLeft === 0) lockStatus('info', 'The next wrong password starts a delay.');
  } catch (err) {
    if (err.code === 'not_configured') {
      lockStatus('error', 'The server is not configured yet. Run setup.html and upload data/config.php.');
    } else if (err.code === 'network') {
      lockStatus('error', 'The server is not reachable.');
    } else {
      lockStatus('error', errorMessage(err));
    }
  }
}

// ---------------------------------------------------------------- unlock / lock

async function onUnlock(event) {
  event.preventDefault();
  if (state.busy) return;
  if (!state.secure) {
    lockStatus('error', 'Refusing to send the password over an insecure connection. Open this page via https.');
    return;
  }
  if (state.retryUntil > Date.now()) return;
  const password = el.lockPassword.value;
  if (!password) {
    lockStatus('error', 'Enter the master password.');
    el.lockPassword.focus();
    return;
  }
  setBusy(true);
  try {
    let keyFile = null;
    const file = !el.keyfileRow.hidden && el.lockKeyfile.files && el.lockKeyfile.files[0];
    if (file) keyFile = await file.arrayBuffer();

    lockStatus('info', 'Checking password…');
    // Fetched every time: params change when setup is re-run, and a stale salt would burn an attempt.
    const params = await api.getParams();
    const token = await deriveAuthToken(password, params);

    let opened;
    try {
      opened = await api.open(token);
    } catch (err) {
      showGateError(err);
      return;
    }

    lockStatus('info', 'Decrypting vault…');
    let vault;
    try {
      vault = await Vault.open(opened.data, password, keyFile);
    } catch (err) {
      lockStatus('error', isInvalidKeyError(err) ? DECRYPT_FAILED : `The vault could not be opened: ${errorMessage(err)}`);
      return;
    }
    state.token = token;
    state.rev = opened.rev;
    state.vault = vault;
    el.lockPassword.value = '';
    el.lockKeyfile.value = '';
    lockStatus('', '');
    enterApp(opened.lastLogin);
  } catch (err) {
    if (err.code) showGateError(err);
    else lockStatus('error', errorMessage(err));
  } finally {
    setBusy(false);
  }
}

function enterApp(lastLogin) {
  state.lastActivity = Date.now();
  el.vaultName.textContent = state.vault.name;
  const last = lastLoginText(lastLogin);
  el.lastLogin.textContent = last.text;
  el.lastLogin.title = last.title;
  el.search.value = '';
  state.groupId = state.vault.rootGroupId();
  state.expanded = new Set([state.groupId]);
  show(el.viewLock, false);
  show(el.viewApp, true);
  updateDirty();
  showList();
}

/** Drops all decrypted state and returns to the lock screen. */
function lock(message = '') {
  if (state.vault) state.vault.close();
  state.vault = null;
  state.token = null;
  state.rev = null;
  state.currentId = null;
  state.editingId = null;
  state.groupId = null;
  state.expanded = new Set();
  el.entryList.replaceChildren();
  el.groupTree.replaceChildren();
  el.breadcrumb.replaceChildren();
  el.groupNote.textContent = '';
  el.entryDetail.replaceChildren();
  el.editCustom.replaceChildren();
  el.editGroup.replaceChildren();
  el.editForm.reset();
  el.search.value = '';
  el.vaultName.textContent = '';
  el.lastLogin.textContent = '';
  el.lastLogin.title = '';
  setStatus(el.appStatus, '', '');
  show(el.viewApp, false);
  show(el.viewLock, true);
  lockStatus(message ? 'info' : '', message);
  if (!message) el.lockPassword.focus();
}

function onLockClick() {
  if (state.vault && state.vault.dirty && !window.confirm('You have unsaved changes. Lock anyway and discard them?')) return;
  lock();
}

function checkIdle() {
  if (!state.vault) return;
  if (Date.now() - state.lastActivity >= AUTO_LOCK_MS) {
    const dirty = state.vault.dirty;
    lock(`Locked after 5 minutes of inactivity.${dirty ? ' Unsaved changes were discarded.' : ''}`);
  }
}

function noteActivity() {
  state.lastActivity = Date.now();
}

// ---------------------------------------------------------------- views

function showView(name) {
  show(el.viewList, name === 'list');
  show(el.viewEntry, name === 'entry');
  show(el.viewEdit, name === 'edit');
  window.scrollTo(0, 0);
}

function updateDirty() {
  const dirty = Boolean(state.vault && state.vault.dirty);
  show(el.dirtyBadge, dirty);
  el.btnSave.classList.toggle('primary', dirty);
}

function showList() {
  state.currentId = null;
  state.editingId = null;
  el.entryDetail.replaceChildren();
  el.editCustom.replaceChildren();
  renderList();
  showView('list');
}

function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many}`;
}

/** "2 groups · 1 entry"; `empty` if both are zero. */
function countText(groups, entries, empty = '') {
  const parts = [];
  if (groups) parts.push(plural(groups, 'group', 'groups'));
  if (entries) parts.push(plural(entries, 'entry', 'entries'));
  return parts.join(' · ') || empty;
}

function entryRow(item, sub) {
  return h(
    'li',
    null,
    h(
      'button',
      { type: 'button', class: 'entry-row', dataset: { id: item.id } },
      h('span', { class: 'entry-title', text: item.title || '(untitled)' }),
      sub ? h('span', { class: 'entry-sub', text: sub }) : null,
    ),
  );
}

function groupRow(group) {
  return h(
    'li',
    null,
    h(
      'button',
      { type: 'button', class: group.isRecycleBin ? 'group-row recycle-bin' : 'group-row', dataset: { group: group.id } },
      h('span', { class: 'folder-icon', 'aria-hidden': 'true' }),
      h(
        'span',
        { class: 'row-text' },
        h('span', { class: 'visually-hidden', text: 'Group: ' }),
        h('span', { class: 'entry-title', text: group.name }),
        h('span', { class: 'entry-sub', text: countText(group.groupCount, group.entryCount, 'Empty') }),
      ),
    ),
  );
}

function emptyRow(text) {
  return h('li', { class: 'empty muted', text });
}

/** Contents of the current group; falls back to the root if it no longer exists (e.g. after a merge). */
function currentContents() {
  try {
    return state.vault.getGroupContents(state.groupId);
  } catch {
    state.groupId = state.vault.rootGroupId();
    return state.vault.getGroupContents(state.groupId);
  }
}

function renderBreadcrumb(path) {
  const items = path.map((p, i) =>
    h(
      'li',
      null,
      i === path.length - 1
        ? h('span', { class: 'crumb current', 'aria-current': 'page', tabindex: '-1', text: p.name })
        : h('button', { type: 'button', class: 'crumb', dataset: { group: p.id }, text: p.name }),
    ),
  );
  el.breadcrumb.replaceChildren(h('ol', null, ...items));
}

/** Folder view of the current group: breadcrumb, group actions, subgroups, then entries. */
function renderGroup() {
  const { group, path, groups, entries } = currentContents();
  renderBreadcrumb(path);
  show(el.breadcrumb, true);
  show(el.btnGroupNew, !group.inRecycleBin);
  show(el.groupTools, !group.isRoot && !group.isRecycleBin);
  show(el.btnGroupRename, !group.inRecycleBin);
  el.btnGroupDelete.textContent = group.inRecycleBin ? 'Delete permanently' : 'Delete group';
  el.groupNote.textContent = group.isRecycleBin ? BIN_NOTE : '';
  show(el.groupNote, group.isRecycleBin);
  const rows = [...groups.map(groupRow), ...entries.map((e) => entryRow(e, e.username))];
  if (!rows.length) rows.push(emptyRow('This group is empty.'));
  el.entryList.replaceChildren(...rows);
  el.listCount.textContent = countText(groups.length, entries.length);
}

/** Flat search results across all groups (recycle bin excluded), with the group path as subtitle. */
function renderSearch(query) {
  const total = state.vault.listEntries().length;
  const items = state.vault.search(query);
  show(el.breadcrumb, false);
  show(el.btnGroupNew, false);
  show(el.groupTools, false);
  show(el.groupNote, false);
  const rows = items.map((item) => entryRow(item, [item.username, item.groupPath].filter(Boolean).join(' · ')));
  if (!rows.length) rows.push(emptyRow('No matching entries.'));
  el.entryList.replaceChildren(...rows);
  el.listCount.textContent = `${items.length} of ${plural(total, 'entry', 'entries')}`;
}

function renderList() {
  if (!state.vault) return;
  const query = el.search.value.trim();
  if (query) renderSearch(query);
  else renderGroup();
  renderTree();
}

// ---------------------------------------------------------------- sidebar group tree (wide screens)

function treeNode(node, depth) {
  const hasChildren = node.children.length > 0;
  const open = hasChildren && state.expanded.has(node.id);
  const active = node.id === state.groupId;
  const classes = ['tree-row', `depth-${Math.min(depth, MAX_TREE_DEPTH)}`];
  if (active) classes.push('active');
  if (node.isRecycleBin) classes.push('recycle-bin');
  const toggle = hasChildren
    ? h(
        'button',
        {
          type: 'button',
          class: 'tree-toggle',
          'aria-expanded': String(open),
          'aria-label': `Subgroups of ${node.name}`,
          dataset: { toggle: node.id },
        },
        h('span', { class: 'chevron', 'aria-hidden': 'true' }),
      )
    : h('span', { class: 'tree-spacer', 'aria-hidden': 'true' });
  const item = h('button', {
    type: 'button',
    class: 'tree-item',
    'aria-current': active ? 'page' : null,
    dataset: { group: node.id },
    text: node.name,
  });
  const children = hasChildren ? h('ul', { hidden: !open }, node.children.map((c) => treeNode(c, depth + 1))) : null;
  return h('li', null, h('div', { class: classes.join(' ') }, toggle, item), children);
}

/** Re-renders the tree; keeps keyboard focus on the same toggle/item if focus was inside it. */
function renderTree() {
  if (!state.vault) return;
  const active = document.activeElement;
  const focused = active instanceof HTMLElement && el.groupTree.contains(active) ? active : null;
  const focusKind = focused ? (focused.dataset.toggle ? 'toggle' : 'group') : '';
  const focusId = focused ? focused.dataset[focusKind] : '';
  el.groupTree.replaceChildren(h('ul', { class: 'tree' }, treeNode(state.vault.getGroupTree(), 0)));
  if (focusId) {
    const target = [...el.groupTree.querySelectorAll('button')].find((b) => b.dataset[focusKind] === focusId);
    if (target) target.focus({ preventScroll: true });
  }
}

function toggleTreeNode(button) {
  const id = button.dataset.toggle;
  const open = button.getAttribute('aria-expanded') !== 'true';
  if (open) state.expanded.add(id);
  else state.expanded.delete(id);
  button.setAttribute('aria-expanded', String(open));
  const children = button.closest('li')?.lastElementChild;
  if (children && children.tagName === 'UL') show(children, open);
}

/** Navigates the list view to a group (from a folder row, the breadcrumb or the sidebar). */
function openGroup(id) {
  if (!state.vault || !id) return false;
  if (!el.viewEdit.hidden) {
    if (!window.confirm('Leave the editor? Changes you have not applied with Done are discarded.')) return false;
    el.editPassword.value = '';
  }
  state.groupId = id;
  try {
    for (const p of state.vault.getGroupPath(id)) state.expanded.add(p.id);
  } catch {
    // unknown group: renderGroup falls back to the root
  }
  el.search.value = '';
  showList();
  return true;
}

/** After navigating from inside the content pane, move focus to the new group's name (screen readers). */
function focusCurrentCrumb() {
  const crumb = el.breadcrumb.querySelector('[aria-current]');
  if (crumb) crumb.focus({ preventScroll: true });
}

function buttonFromEvent(event) {
  return event.target instanceof Element ? event.target.closest('button') : null;
}

function onEntryListClick(event) {
  const btn = buttonFromEvent(event);
  if (!btn) return;
  if (btn.dataset.group) {
    if (openGroup(btn.dataset.group)) focusCurrentCrumb();
  } else if (btn.dataset.id) {
    showEntry(btn.dataset.id);
  }
}

function onBreadcrumbClick(event) {
  const btn = buttonFromEvent(event);
  if (btn && btn.dataset.group && openGroup(btn.dataset.group)) focusCurrentCrumb();
}

function onTreeClick(event) {
  const btn = buttonFromEvent(event);
  if (!btn) return;
  if (btn.dataset.toggle) toggleTreeNode(btn);
  else if (btn.dataset.group) openGroup(btn.dataset.group);
}

// ---------------------------------------------------------------- group management

function onGroupNew() {
  if (!state.vault || state.busy) return;
  const name = window.prompt('Name of the new group:', '');
  if (name === null) return;
  try {
    state.vault.createGroup(state.groupId, name);
    state.expanded.add(state.groupId);
    updateDirty();
    renderList();
    appStatus('info', `Group "${name.trim()}" created. Tap Save to store it on the server.`, 6000);
  } catch (err) {
    appStatus('error', errorMessage(err));
  }
}

function onGroupRename() {
  if (!state.vault || state.busy) return;
  const { group } = currentContents();
  const name = window.prompt('New name for the group:', group.name);
  if (name === null) return;
  try {
    const changed = state.vault.renameGroup(group.id, name);
    updateDirty();
    renderList();
    appStatus('info', changed ? 'Group renamed. Tap Save to store the change.' : 'No changes.', 6000);
  } catch (err) {
    appStatus('error', errorMessage(err));
  }
}

function onGroupDelete() {
  if (!state.vault || state.busy) return;
  const { group, path } = currentContents();
  if (group.isRoot || group.isRecycleBin) return;
  let question;
  if (group.inRecycleBin) {
    question = `Delete the group "${group.name}" and everything in it permanently? This cannot be undone.`;
  } else if (state.vault.recycleBinEnabled) {
    question = `Move the group "${group.name}" and everything in it to the recycle bin?`;
  } else {
    question = `Delete the group "${group.name}" and everything in it permanently? (The recycle bin is disabled in this database.)`;
  }
  if (!window.confirm(question)) return;
  try {
    const result = state.vault.deleteGroup(group.id);
    state.groupId = path[path.length - 2].id; // the parent
    updateDirty();
    showList();
    focusCurrentCrumb();
    appStatus('info', `${result === 'recycled' ? 'Group moved to the recycle bin' : 'Group deleted'}. Tap Save to store the change.`, 6000);
  } catch (err) {
    appStatus('error', errorMessage(err));
  }
}

function copyButton(label, getValue) {
  return h('button', {
    type: 'button',
    class: 'small',
    text: 'Copy',
    'aria-label': `Copy ${label}`,
    onclick: async () => {
      const value = getValue();
      if (!value) return;
      const ok = await copyText(value);
      appStatus(
        ok ? 'ok' : 'error',
        ok ? `${label} copied.` : 'Copy failed.',
        4000,
      );
    },
  });
}

/** A masked value with Show/Hide + Copy; the plaintext is read from the vault only on demand. */
function secretRow(label, getValue) {
  const value = h('span', { class: 'field-value mono', text: MASK });
  const reveal = h('button', {
    type: 'button',
    class: 'small',
    text: 'Show',
    'aria-pressed': 'false',
    onclick: () => {
      const shown = reveal.getAttribute('aria-pressed') === 'true';
      value.textContent = shown ? MASK : getValue() || '';
      reveal.textContent = shown ? 'Show' : 'Hide';
      reveal.setAttribute('aria-pressed', String(!shown));
    },
  });
  return h('div', { class: 'field' }, h('div', { class: 'field-label', text: label }), value, h('div', { class: 'field-actions' }, reveal, copyButton(label, getValue)));
}

function textRow(label, text, { copy = false, multiline = false } = {}) {
  if (!text) return null;
  return h(
    'div',
    { class: 'field' },
    h('div', { class: 'field-label', text: label }),
    h('div', { class: multiline ? 'field-value notes' : 'field-value', text }),
    copy ? h('div', { class: 'field-actions' }, copyButton(label, () => text)) : null,
  );
}

function urlRow(url) {
  if (!url) return null;
  const safe = safeHttpUrl(url);
  const value = safe
    ? h('a', { class: 'field-value', href: safe, target: '_blank', rel: 'noopener noreferrer', text: url })
    : h('div', { class: 'field-value', text: url });
  return h('div', { class: 'field' }, h('div', { class: 'field-label', text: 'URL' }), value, h('div', { class: 'field-actions' }, copyButton('URL', () => url)));
}

function formatDate(d) {
  return d instanceof Date && !Number.isNaN(d.getTime()) ? d.toLocaleString() : '';
}

function showEntry(id) {
  if (!state.vault) return;
  let entry;
  try {
    entry = state.vault.getEntry(id);
  } catch (err) {
    appStatus('error', errorMessage(err));
    showList();
    return;
  }
  state.currentId = id;
  state.editingId = null;
  const vault = state.vault;
  const nodes = [
    h('h2', { class: 'entry-heading', text: entry.title || '(untitled)' }),
    h('p', { class: 'muted', text: entry.groupPath }),
    textRow('Username', entry.username, { copy: true }),
    entry.password ? secretRow('Password', () => (state.vault === vault ? vault.getField(id, 'Password') : '')) : null,
    urlRow(entry.url),
    textRow('Notes', entry.notes, { multiline: true }),
    textRow('Tags', entry.tags.join(', ')),
  ];
  for (const field of entry.custom) {
    if (field.protected) {
      nodes.push(secretRow(field.name, () => (state.vault === vault ? vault.getField(id, field.name) : '')));
    } else {
      nodes.push(textRow(field.name, field.value, { copy: true }));
    }
  }
  const modified = formatDate(entry.modified);
  if (modified) nodes.push(h('p', { class: 'muted small-text', text: `Modified ${modified}` }));
  el.entryDetail.replaceChildren(...nodes.filter(Boolean));
  el.btnEntryDelete.textContent = entry.inRecycleBin ? 'Delete permanently' : 'Delete';
  showView('entry');
}

// ---------------------------------------------------------------- edit / add

function setPasswordVisible(visible) {
  el.editPassword.type = visible ? 'text' : 'password';
  el.editPasswordReveal.textContent = visible ? 'Hide' : 'Show';
  el.editPasswordReveal.setAttribute('aria-pressed', String(visible));
}

/**
 * Group options indented by depth (tree order, recycle bin excluded). `keepLabel` adds a first option
 * with an empty value ("do not move"), used for entries in the recycle bin.
 */
function fillGroupSelect(selectedId, keepLabel = '') {
  const frag = document.createDocumentFragment();
  if (keepLabel) frag.append(h('option', { value: '', text: keepLabel }));
  for (const g of state.vault.listGroups()) {
    const name = g.name || (g.depth ? '(unnamed)' : 'Root');
    const opt = h('option', { value: g.id, text: INDENT.repeat(g.depth) + name });
    if (g.id === selectedId) opt.selected = true;
    frag.append(opt);
  }
  el.editGroup.replaceChildren(frag);
}

/** New entries go to the group being viewed, or to the root when that is the recycle bin. */
function defaultGroupForNewEntry() {
  return state.vault.isInRecycleBin(state.groupId) ? state.vault.rootGroupId() : state.groupId;
}

function showEdit(id) {
  if (!state.vault) return;
  state.editingId = id;
  el.editForm.reset();
  setPasswordVisible(false);
  show(el.genPanel, false);
  el.genToggle.setAttribute('aria-expanded', 'false');
  el.genInfo.textContent = '';
  el.editCustom.replaceChildren();
  if (id) {
    const e = state.vault.getEntry(id);
    el.editHeading.textContent = 'Edit entry';
    el.editTitle.value = e.title;
    el.editUsername.value = e.username;
    el.editPassword.value = e.password;
    el.editUrl.value = e.url;
    el.editNotes.value = e.notes;
    el.editTags.value = e.tags.join(', ');
    fillGroupSelect(e.groupId, e.inRecycleBin ? `(stay in ${e.groupPath})` : '');
    for (const field of e.custom) {
      const input = h('input', {
        type: field.protected ? 'password' : 'text',
        autocomplete: 'off',
        autocapitalize: 'off',
        spellcheck: 'false',
        dataset: { field: field.name, protected: field.protected ? '1' : '' },
      });
      input.value = field.value;
      const inputId = `custom-${el.editCustom.childElementCount}`;
      input.id = inputId;
      el.editCustom.append(h('label', { for: inputId, text: field.name }), input);
    }
  } else {
    el.editHeading.textContent = 'New entry';
    fillGroupSelect(defaultGroupForNewEntry());
  }
  showView('edit');
  el.editTitle.focus();
}

function collectChanges() {
  const changes = {
    title: el.editTitle.value,
    username: el.editUsername.value,
    password: el.editPassword.value,
    url: el.editUrl.value.trim(),
    notes: el.editNotes.value,
    tags: el.editTags.value,
    groupId: el.editGroup.value || undefined,
  };
  const custom = {};
  for (const input of el.editCustom.querySelectorAll('input[data-field]')) {
    custom[input.dataset.field] = { value: input.value, protected: input.dataset.protected === '1' };
  }
  if (Object.keys(custom).length) changes.custom = custom;
  return changes;
}

function onEditSubmit(event) {
  event.preventDefault();
  if (!state.vault || state.busy) return;
  const changes = collectChanges();
  try {
    let id = state.editingId;
    if (id) {
      const changed = state.vault.updateEntry(id, changes);
      appStatus('info', changed ? 'Changes applied. Tap Save to store them on the server.' : 'No changes.', 6000);
    } else {
      id = state.vault.createEntry(changes.groupId, changes);
      appStatus('info', 'Entry added. Tap Save to store it on the server.', 6000);
    }
    el.editPassword.value = '';
    el.editCustom.replaceChildren();
    updateDirty();
    showEntry(id);
  } catch (err) {
    appStatus('error', errorMessage(err));
  }
}

function onEditCancel() {
  const id = state.editingId;
  el.editPassword.value = '';
  el.editCustom.replaceChildren();
  if (id) showEntry(id);
  else showList();
}

function genOptions() {
  return {
    length: Number.parseInt(el.genLength.value, 10),
    lower: el.genLower.checked,
    upper: el.genUpper.checked,
    digits: el.genDigits.checked,
    symbols: el.genSymbols.checked,
    avoidAmbiguous: el.genAmbiguous.checked,
  };
}

function runGenerator() {
  try {
    const opts = genOptions();
    el.editPassword.value = generatePassword(opts);
    setPasswordVisible(true);
    el.genInfo.textContent = `About ${estimateBits(opts)} bits of entropy.`;
  } catch (err) {
    el.genInfo.textContent = errorMessage(err);
  }
}

function onGenToggle() {
  const open = el.genPanel.hidden;
  show(el.genPanel, open);
  el.genToggle.setAttribute('aria-expanded', String(open));
  if (open) runGenerator();
}

function onDelete() {
  const id = state.currentId;
  if (!state.vault || !id) return;
  const entry = state.vault.getEntry(id);
  const name = entry.title || '(untitled)';
  let question;
  if (entry.inRecycleBin) {
    question = `Delete "${name}" permanently? It is already in the recycle bin, so this cannot be undone.`;
  } else if (state.vault.recycleBinEnabled) {
    question = `Move "${name}" to the recycle bin?`;
  } else {
    question = `Delete "${name}" permanently? (The recycle bin is disabled in this database.)`;
  }
  if (!window.confirm(question)) return;
  try {
    const result = state.vault.deleteEntry(id);
    updateDirty();
    appStatus('info', `${result === 'recycled' ? 'Moved to the recycle bin' : 'Deleted'}. Tap Save to store the change.`, 6000);
    showList();
  } catch (err) {
    appStatus('error', errorMessage(err));
  }
}

// ---------------------------------------------------------------- save / download

function describeSaveError(err) {
  switch (err.code) {
    case 'bad_token':
      return 'The server rejected the password (was setup re-run?). Your changes are not saved: download the .kdbx to keep them.';
    case 'locked':
      return `The server is locked after failed attempts. Try saving again in ${mmss(err.retryAfter || 0)}.`;
    case 'too_large':
      return 'The vault is larger than the server allows (max_vault_bytes).';
    case 'no_vault':
      return 'The vault file is missing on the server.';
    default:
      return `Saving failed: ${errorMessage(err)}`;
  }
}

async function saveWithConflictHandling() {
  const vault = state.vault;
  for (let attempt = 0; attempt < 3; attempt++) {
    appStatus('info', 'Encrypting…');
    const data = await vault.save();
    if (state.vault !== vault) return;
    appStatus('info', 'Uploading…');
    try {
      const res = await api.save(state.token, state.rev, data);
      state.rev = res.rev;
      vault.markSaved();
      updateDirty();
      appStatus('ok', 'Saved.', 4000);
      return;
    } catch (err) {
      if (err.code !== 'conflict') throw err;
    }
    const merge = window.confirm(
      'The vault was changed on the server since you opened it (another device?). ' +
        'Merge your changes into the newer version and save?',
    );
    if (!merge) {
      appStatus('error', 'Not saved. Your changes are still here; download the .kdbx or lock and unlock to reload.');
      return;
    }
    appStatus('info', 'Fetching the newer version…');
    const remote = await api.open(state.token);
    if (state.vault !== vault) return;
    try {
      await vault.merge(remote.data);
    } catch (err) {
      if (isInvalidKeyError(err)) {
        appStatus('error', 'The server version cannot be decrypted with your current password or key file (changed elsewhere?). Download your copy, then lock and unlock.');
        return;
      }
      throw err;
    }
    state.rev = remote.rev;
    if (state.currentId) showEntry(state.currentId);
    else if (!el.viewList.hidden) renderList();
    renderTree(); // the sidebar shows in every view, and groups may have changed remotely
  }
  appStatus('error', 'Saving failed repeatedly because of concurrent changes. Try again.');
}

async function onSave() {
  if (!state.vault || state.busy) return;
  if (!state.vault.dirty) {
    appStatus('info', 'No unsaved changes.', 3000);
    return;
  }
  if (!el.viewEdit.hidden) {
    appStatus('info', 'Finish editing first (Done or Cancel).', 4000);
    return;
  }
  setBusy(true);
  try {
    await saveWithConflictHandling();
  } catch (err) {
    appStatus('error', err.code ? describeSaveError(err) : `Saving failed: ${errorMessage(err)}`);
  } finally {
    setBusy(false);
    updateDirty();
  }
}

function safeFileName(name) {
  const base = String(name || 'vault').replace(/[^\w.-]+/g, '_').replace(/^[._]+/, '').slice(0, 60);
  return `${base || 'vault'}.kdbx`;
}

async function onDownload() {
  if (!state.vault || state.busy) return;
  setBusy(true);
  try {
    appStatus('info', 'Encrypting…');
    const data = await state.vault.save();
    downloadBlob(data, safeFileName(state.vault.name));
    appStatus('ok', state.vault.dirty ? 'Downloaded (includes unsaved changes).' : 'Downloaded.', 4000);
  } catch (err) {
    appStatus('error', `Download failed: ${errorMessage(err)}`);
  } finally {
    setBusy(false);
  }
}

// ---------------------------------------------------------------- wiring

function bindEvents() {
  el.lockForm.addEventListener('submit', onUnlock);
  el.keyfileToggle.addEventListener('click', () => {
    const open = el.keyfileRow.hidden;
    show(el.keyfileRow, open);
    el.keyfileToggle.setAttribute('aria-expanded', String(open));
    el.keyfileToggle.textContent = open ? 'Do not use a key file' : 'Use a key file';
    if (!open) el.lockKeyfile.value = '';
  });

  el.btnLock.addEventListener('click', onLockClick);
  el.btnSave.addEventListener('click', onSave);
  el.btnDownload.addEventListener('click', onDownload);
  el.btnAdd.addEventListener('click', () => showEdit(null));
  el.search.addEventListener('input', () => {
    if (el.viewList.hidden) {
      if (!el.viewEdit.hidden) return; // do not discard an edit in progress
      showList();
    } else {
      renderList();
    }
  });
  el.entryList.addEventListener('click', onEntryListClick);
  el.breadcrumb.addEventListener('click', onBreadcrumbClick);
  el.groupTree.addEventListener('click', onTreeClick);
  el.btnGroupNew.addEventListener('click', onGroupNew);
  el.btnGroupRename.addEventListener('click', onGroupRename);
  el.btnGroupDelete.addEventListener('click', onGroupDelete);

  el.btnEntryBack.addEventListener('click', showList);
  el.btnEntryEdit.addEventListener('click', () => state.currentId && showEdit(state.currentId));
  el.btnEntryDelete.addEventListener('click', onDelete);

  el.editForm.addEventListener('submit', onEditSubmit);
  el.editCancel.addEventListener('click', onEditCancel);
  el.editPasswordReveal.addEventListener('click', () => setPasswordVisible(el.editPassword.type === 'password'));
  el.genToggle.addEventListener('click', onGenToggle);
  el.genRun.addEventListener('click', runGenerator);

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && state.vault && !el.viewEntry.hidden) showList();
  });

  for (const type of ['pointerdown', 'keydown', 'input', 'touchstart', 'wheel', 'scroll']) {
    document.addEventListener(type, noteActivity, { capture: true, passive: true });
  }
  setInterval(checkIdle, 10000);
  document.addEventListener('visibilitychange', checkIdle);

  window.addEventListener('beforeunload', (event) => {
    if (state.vault && state.vault.dirty) {
      event.preventDefault();
      event.returnValue = '';
    }
  });
}

function init() {
  cacheElements();
  bindEvents();
  state.secure = isSecureLocation(window.location);
  setBusy(false);
  checkExposure();
  if (!state.secure) {
    lockStatus('error', 'This page is not served over https, so the password will not be sent. Open it via https:// (plain http only works on localhost).');
    return;
  }
  refreshStatus();
  el.lockPassword.focus();
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();
