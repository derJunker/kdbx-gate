import test from 'node:test';
import assert from 'node:assert/strict';
import { createApi, ApiError, isSecureLocation, isPubliclyReadable } from '../../src/api.js';

const TOKEN = 'ab'.repeat(32);
const REV = 'cd'.repeat(32);
const NEW_REV = 'ef'.repeat(32);
const HTTPS = { protocol: 'https:', hostname: 'vault.example.org' };

function jsonResponse(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers },
  });
}

/** Stub fetch that records calls and answers with the given responder. */
function stub(responder) {
  const calls = [];
  const fetch = async (url, init = {}) => {
    calls.push({ url, init, headers: new Headers(init.headers || {}) });
    return typeof responder === 'function' ? responder(url, init) : responder;
  };
  return { fetch, calls };
}

test('getParams: GET api.php?a=params without a token', async () => {
  const s = stub(() => jsonResponse(200, { kdf: 'argon2id', m: 65536, t: 3, p: 1, salt: 'c2FsdHNhbHRzYWx0c2FsdA==' }));
  const api = createApi({ fetch: s.fetch, location: HTTPS });
  assert.deepEqual(await api.getParams(), { kdf: 'argon2id', m: 65536, t: 3, p: 1, salt: 'c2FsdHNhbHRzYWx0c2FsdA==' });
  assert.equal(s.calls[0].url, 'api.php?a=params');
  assert.equal(s.calls[0].init.method, 'GET');
  assert.equal(s.calls[0].init.cache, 'no-store');
  assert.equal(s.calls[0].headers.has('X-Vault-Token'), false);
});

test('getParams: invalid params or non-JSON answer -> bad_response', async () => {
  let api = createApi({ fetch: stub(() => jsonResponse(200, { kdf: 'argon2id', m: 1, t: 3, p: 1, salt: 'x' })).fetch });
  await assert.rejects(api.getParams(), (e) => e instanceof ApiError && e.code === 'bad_response');
  api = createApi({ fetch: stub(() => new Response('<?php echo 1;', { status: 200, headers: { 'Content-Type': 'text/plain' } })).fetch });
  await assert.rejects(api.getParams(), (e) => e.code === 'bad_response');
});

test('getStatus returns retryAfter / attemptsLeft', async () => {
  const s = stub(() => jsonResponse(200, { retryAfter: 42, attemptsLeft: 0 }));
  const api = createApi({ fetch: s.fetch });
  assert.deepEqual(await api.getStatus(), { retryAfter: 42, attemptsLeft: 0 });
  assert.equal(s.calls[0].url, 'api.php?a=status');
});

test('open: POST with X-Vault-Token header, token never in the URL', async () => {
  const bytes = new Uint8Array([3, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 1, 2]);
  const s = stub(() => new Response(bytes, { status: 200, headers: { 'Content-Type': 'application/octet-stream', 'X-Vault-Rev': REV } }));
  const api = createApi({ fetch: s.fetch, location: HTTPS });
  const res = await api.open(TOKEN);
  assert.equal(res.rev, REV);
  assert.deepEqual(new Uint8Array(res.data), bytes);
  const call = s.calls[0];
  assert.equal(call.url, 'api.php?a=open');
  assert.ok(!call.url.includes(TOKEN));
  assert.equal(call.init.method, 'POST');
  assert.equal(call.headers.get('X-Vault-Token'), TOKEN);
  assert.equal(call.init.redirect, 'error');
});

test('open: missing X-Vault-Rev -> bad_response', async () => {
  const api = createApi({ fetch: stub(() => new Response('hello', { status: 200 })).fetch });
  await assert.rejects(api.open(TOKEN), (e) => e.code === 'bad_response');
});

test('error mapping for the gate and the vault', async () => {
  const cases = [
    [jsonResponse(401, { error: 'bad_token', attemptsLeft: 2, retryAfter: 0 }), { code: 'bad_token', attemptsLeft: 2, retryAfter: 0, status: 401 }],
    [jsonResponse(401, { error: 'bad_token', attemptsLeft: 0, retryAfter: 60 }), { code: 'bad_token', attemptsLeft: 0, retryAfter: 60 }],
    [jsonResponse(429, { error: 'locked', retryAfter: 37 }, { 'Retry-After': '37' }), { code: 'locked', retryAfter: 37, status: 429 }],
    [new Response('Too many', { status: 429, headers: { 'Retry-After': '12' } }), { code: 'locked', retryAfter: 12 }],
    [jsonResponse(404, { error: 'no_vault' }), { code: 'no_vault', status: 404 }],
    [new Response('<h1>Not Found</h1>', { status: 404, headers: { 'Content-Type': 'text/html' } }), { code: 'http_error', status: 404 }],
    [jsonResponse(503, { error: 'not_configured' }), { code: 'not_configured', status: 503 }],
    [jsonResponse(405, { error: 'method_not_allowed' }), { code: 'method_not_allowed' }],
    [jsonResponse(400, { error: 'bad_request' }), { code: 'bad_request' }],
    [new Response('oops', { status: 500 }), { code: 'http_error', status: 500 }],
  ];
  for (const [response, expected] of cases) {
    const api = createApi({ fetch: stub(() => response.clone()).fetch, location: HTTPS });
    await assert.rejects(api.open(TOKEN), (e) => {
      assert.ok(e instanceof ApiError);
      for (const [k, v] of Object.entries(expected)) assert.equal(e[k], v, `${k} for ${JSON.stringify(expected)}`);
      return true;
    });
  }
});

test('network failure -> network error', async () => {
  const api = createApi({ fetch: async () => { throw new TypeError('Failed to fetch'); } });
  await assert.rejects(api.getStatus(), (e) => e.code === 'network');
});

test('save: headers, body and new rev', async () => {
  const body = new Uint8Array([3, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5]).buffer;
  const s = stub(() => jsonResponse(200, { rev: NEW_REV }));
  const api = createApi({ fetch: s.fetch, location: HTTPS });
  assert.deepEqual(await api.save(TOKEN, REV, body), { rev: NEW_REV });
  const call = s.calls[0];
  assert.equal(call.url, 'api.php?a=save');
  assert.equal(call.init.method, 'POST');
  assert.equal(call.headers.get('X-Vault-Token'), TOKEN);
  assert.equal(call.headers.get('X-Vault-Base-Rev'), REV);
  assert.equal(call.headers.get('Content-Type'), 'application/octet-stream');
  assert.equal(call.init.body, body);
});

test('save: conflict / too_large / invalid_kdbx / bad_token', async () => {
  const run = (response) => createApi({ fetch: stub(() => response).fetch }).save(TOKEN, REV, new ArrayBuffer(8));
  await assert.rejects(run(jsonResponse(409, { error: 'conflict', rev: NEW_REV })), (e) => e.code === 'conflict' && e.rev === NEW_REV && e.status === 409);
  await assert.rejects(run(jsonResponse(413, { error: 'too_large' })), (e) => e.code === 'too_large');
  await assert.rejects(run(jsonResponse(400, { error: 'invalid_kdbx' })), (e) => e.code === 'invalid_kdbx');
  await assert.rejects(run(jsonResponse(401, { error: 'bad_token', attemptsLeft: 1, retryAfter: 0 })), (e) => e.code === 'bad_token' && e.attemptsLeft === 1);
  await assert.rejects(run(jsonResponse(200, { ok: true })), (e) => e.code === 'bad_response');
});

test('token is never sent over an insecure origin or in a bad format', async () => {
  const s = stub(() => jsonResponse(200, {}));
  for (const location of [
    { protocol: 'http:', hostname: 'vault.example.org' },
    { protocol: 'file:', hostname: '' },
    null,
  ]) {
    const api = createApi({ fetch: s.fetch, location });
    await assert.rejects(api.open(TOKEN), (e) => e.code === 'insecure');
    await assert.rejects(api.save(TOKEN, REV, new ArrayBuffer(8)), (e) => e.code === 'insecure');
  }
  const api = createApi({ fetch: s.fetch, location: HTTPS });
  await assert.rejects(api.open('ABCD'), TypeError);
  await assert.rejects(api.open(TOKEN.toUpperCase()), TypeError);
  await assert.rejects(api.save(TOKEN, 'nope', new ArrayBuffer(8)), TypeError);
  assert.equal(s.calls.length, 0);
});

test('isSecureLocation', () => {
  assert.equal(isSecureLocation({ protocol: 'https:', hostname: 'x.org' }), true);
  assert.equal(isSecureLocation({ protocol: 'http:', hostname: 'localhost' }), true);
  assert.equal(isSecureLocation({ protocol: 'http:', hostname: '127.0.0.1' }), true);
  assert.equal(isSecureLocation({ protocol: 'http:', hostname: 'x.org' }), false);
  assert.equal(isSecureLocation({ protocol: 'http:', hostname: '127.0.0.1.evil.org' }), false);
  assert.equal(isSecureLocation(undefined), false);
});

test('isPubliclyReadable: HEAD, true only for 200', async () => {
  const s = stub((url) => new Response(null, { status: url.endsWith('.kdbx') ? 200 : 403 }));
  assert.equal(await isPubliclyReadable('data/vault.kdbx', s.fetch), true);
  assert.equal(await isPubliclyReadable('data/config.php', s.fetch), false);
  assert.equal(s.calls[0].init.method, 'HEAD');
  assert.equal(await isPubliclyReadable('x', async () => { throw new Error('offline'); }), false);
});
