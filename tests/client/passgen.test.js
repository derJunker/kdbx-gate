import test from 'node:test';
import assert from 'node:assert/strict';
import { generatePassword, randomInt, CHARSETS, estimateBits, MIN_LENGTH, MAX_LENGTH } from '../../src/passgen.js';

test('respects length and character classes', () => {
  for (let i = 0; i < 200; i++) {
    const pw = generatePassword({ length: 24 });
    assert.equal(pw.length, 24);
    for (const set of Object.values(CHARSETS)) assert.ok([...pw].some((c) => set.includes(c)), `${pw} lacks a class`);
  }
  const digits = generatePassword({ length: 30, lower: false, upper: false, symbols: false });
  assert.match(digits, /^[0-9]{30}$/);
  const alpha = generatePassword({ length: 40, digits: false, symbols: false });
  assert.match(alpha, /^[A-Za-z]{40}$/);
  assert.match(alpha, /[a-z]/);
  assert.match(alpha, /[A-Z]/);
});

test('every selected class appears even at the minimum length', () => {
  for (let i = 0; i < 200; i++) {
    const pw = generatePassword({ length: MIN_LENGTH });
    assert.match(pw, /[a-z]/);
    assert.match(pw, /[A-Z]/);
    assert.match(pw, /[0-9]/);
    assert.match(pw, /[^A-Za-z0-9]/);
  }
});

test('avoidAmbiguous drops look-alike characters', () => {
  for (let i = 0; i < 100; i++) {
    assert.doesNotMatch(generatePassword({ length: 64, avoidAmbiguous: true }), /[Il1O0o|]/);
  }
});

test('rejects invalid options', () => {
  assert.throws(() => generatePassword({ length: MIN_LENGTH - 1 }), RangeError);
  assert.throws(() => generatePassword({ length: MAX_LENGTH + 1 }), RangeError);
  assert.throws(() => generatePassword({ length: 12.5 }), RangeError);
  assert.throws(() => generatePassword({ lower: false, upper: false, digits: false, symbols: false }), RangeError);
});

test('randomInt uses rejection sampling (values above the last full multiple are discarded)', () => {
  // n = 10: limit = floor(2^32 / 10) * 10 = 4294967290. Values >= limit must be rejected.
  const values = [4294967295, 4294967290, 4294967289];
  const fake = (arr) => {
    arr[0] = values.shift();
    return arr;
  };
  assert.equal(randomInt(10, fake), 4294967289 % 10);
  assert.equal(values.length, 0);
  assert.throws(() => randomInt(0));
});

test('randomInt is roughly uniform', () => {
  const n = 7;
  const draws = 70000;
  const counts = new Array(n).fill(0);
  for (let i = 0; i < draws; i++) counts[randomInt(n)]++;
  const expected = draws / n;
  const chi2 = counts.reduce((sum, c) => sum + (c - expected) ** 2 / expected, 0);
  assert.ok(chi2 < 30, `chi2 ${chi2} too large: ${counts}`); // df = 6, p(chi2 > 30) < 0.0001
});

test('passwords are not repeated and entropy estimate is sane', () => {
  const seen = new Set();
  for (let i = 0; i < 1000; i++) seen.add(generatePassword());
  assert.equal(seen.size, 1000);
  assert.ok(estimateBits({ length: 20 }) > 120);
  assert.equal(estimateBits({ length: 10, lower: false, upper: false, symbols: false }), 33);
});
