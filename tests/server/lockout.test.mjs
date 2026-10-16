// The gate: lockout algorithm from SPEC.md ("Lockout algorithm").
import { after, before, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { assertError, nowSec, randomHex, sha256, sleep, startServer } from './harness.mjs';

const DELAY = 3;

describe('gate: lockout', () => {
  let s;
  before(async () => { s = await startServer({ config: { delay_seconds: DELAY } }); });
  after(() => s.stop());
  beforeEach(() => s.resetState());

  /** Assert a 429 and return its retryAfter. */
  function assertLocked(r) {
    assertError(r, 429, 'locked');
    assert.deepEqual(Object.keys(r.json), ['error', 'retryAfter']);
    const ra = r.json.retryAfter;
    assert.ok(Number.isInteger(ra) && ra >= 1 && ra <= DELAY, `retryAfter ${ra}`);
    assert.equal(r.headers.get('retry-after'), String(ra));
    return ra;
  }

  test('wrong token => 401 with attemptsLeft counting down; the 3rd failure starts the delay', async () => {
    const [a, b, c] = await s.fail(3);
    assert.deepEqual(a.json, { error: 'bad_token', attemptsLeft: 2, retryAfter: 0 });
    assert.deepEqual(b.json, { error: 'bad_token', attemptsLeft: 1, retryAfter: 0 });
    assert.deepEqual(c.json, { error: 'bad_token', attemptsLeft: 0, retryAfter: DELAY });
    for (const r of [a, b, c]) assert.equal(r.status, 401);
    const st = s.readState();
    assert.equal(st.fails, 3);
    assert.ok(Math.abs(st.last - nowSec()) <= 2);
  });

  test('missing and malformed tokens count as failed attempts', async () => {
    const upper = s.tokenHex.toUpperCase();
    const tries = [
      await s.request('open', { method: 'POST' }), // no header at all
      await s.open(''),
      await s.open('not-hex'),
    ];
    assert.deepEqual(tries.map((r) => r.json.attemptsLeft), [2, 1, 0]);
    for (const r of tries) assertError(r, 401, 'bad_token');
    assert.equal(s.readState().fails, 3);

    s.resetState();
    const more = [
      await s.open(upper), // the right token, but not lowercase hex
      await s.open(s.tokenHex.slice(0, 63)),
      await s.open(`${s.tokenHex}00`),
    ];
    for (const r of more) assertError(r, 401, 'bad_token');
    assert.equal(s.readState().fails, 3);

    s.resetState();
    // a token in the URL is never accepted
    const r = await s.request(null, { method: 'POST', query: `a=open&token=${s.tokenHex}` });
    assertError(r, 401, 'bad_token');
  });

  test('while locked: 429 + Retry-After, the correct token is rejected unchecked, state unchanged', async () => {
    await s.fail(3);
    const before = s.readStateRaw();
    assertLocked(await s.open(randomHex()));
    assertLocked(await s.open()); // correct token: still 429, no oracle
    assertLocked(await s.request('open', { method: 'POST' }));
    assertLocked(await s.save(s.vault, { baseRev: sha256(s.vault) }));
    assert.equal(s.readStateRaw(), before, 'a rejected attempt must not touch the state');
    const st = await s.status();
    assert.equal(st.json.attemptsLeft, 0);
    assert.ok(st.json.retryAfter >= 1 && st.json.retryAfter <= DELAY);
  });

  test('after the delay exactly one attempt is allowed; a wrong one re-locks immediately', async () => {
    await s.fail(3);
    const ra = assertLocked(await s.open());
    await sleep(ra * 1000 + 150); // Retry-After is never too short

    assert.deepEqual((await s.status()).json, { retryAfter: 0, attemptsLeft: 0 });
    const wrong = await s.open(randomHex());
    assert.deepEqual(wrong.json, { error: 'bad_token', attemptsLeft: 0, retryAfter: DELAY });
    assertLocked(await s.open()); // locked again right away, even for the correct token
    assert.equal(s.readState().fails, 4);
  });

  test('after the delay the correct token opens the vault and resets the counter', async () => {
    s.writeState({ fails: 7, last: nowSec() - DELAY - 1 }); // simulate an expired delay
    const r = await s.open();
    assert.equal(r.status, 200);
    assert.ok(r.body.equals(s.vault));
    assert.equal(s.readState().fails, 0);
    assert.deepEqual((await s.status()).json, { retryAfter: 0, attemptsLeft: 3 });
  });

  test('the correct token resets the counter before the lockout', async () => {
    await s.fail(2);
    assert.deepEqual((await s.status()).json, { retryAfter: 0, attemptsLeft: 1 });
    assert.equal((await s.open()).status, 200);
    assert.equal(s.readState().fails, 0);
    assert.deepEqual((await s.status()).json, { retryAfter: 0, attemptsLeft: 3 });
    const [r] = await s.fail(1);
    assert.equal(r.json.attemptsLeft, 2);
  });

  test('status is read-only and reports the countdown', async () => {
    s.writeState({ fails: 3, last: nowSec() - 1 });
    const raw = s.readStateRaw();
    const r = await s.status();
    assert.equal(r.json.attemptsLeft, 0);
    assert.ok(r.json.retryAfter >= DELAY - 2 && r.json.retryAfter <= DELAY - 1, `retryAfter ${r.json.retryAfter}`);
    assert.equal(s.readStateRaw(), raw);
    s.writeState({ fails: 1, last: nowSec() });
    assert.deepEqual((await s.status()).json, { retryAfter: 0, attemptsLeft: 2 });
  });

  test('a corrupt state file fails closed (treated as locked) and is repaired', async () => {
    s.writeState('{"fails":"0"');
    const st = await s.status();
    assert.deepEqual(st.json, { retryAfter: DELAY, attemptsLeft: 0 });
    assertLocked(await s.open()); // even the correct token
    const repaired = s.readState();
    assert.equal(repaired.fails, 3);
    assert.ok(Math.abs(repaired.last - nowSec()) <= 2);
  });

  test('a state dated in the future does not lock longer than one delay', async () => {
    s.writeState({ fails: 3, last: nowSec() + 3600 });
    assertLocked(await s.open());
    const st = s.readState();
    assert.ok(st.last <= nowSec(), 'last is clamped to now');
    assert.equal(st.fails, 3);
  });
});
