// Password generator: crypto.getRandomValues + rejection sampling (no modulo bias).

export const CHARSETS = Object.freeze({
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!#$%&()*+,-./:;<=>?@[]^_{|}~',
});
const AMBIGUOUS = new Set('Il1O0o|');

export const MIN_LENGTH = 4;
export const MAX_LENGTH = 128;
export const DEFAULTS = Object.freeze({
  length: 20,
  lower: true,
  upper: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: false,
});

function defaultRandom(arr) {
  return globalThis.crypto.getRandomValues(arr);
}

/** Uniform integer in [0, n) using rejection sampling on 32-bit values. */
export function randomInt(n, random = defaultRandom) {
  if (!Number.isInteger(n) || n <= 0 || n > 2 ** 32) throw new RangeError('n out of range');
  const limit = Math.floor(2 ** 32 / n) * n; // largest multiple of n that fits
  const buf = new Uint32Array(1);
  for (;;) {
    random(buf);
    if (buf[0] < limit) return buf[0] % n;
  }
}

/** Returns the selected character classes as arrays of characters. */
export function selectedClasses(opts = {}) {
  const o = { ...DEFAULTS, ...opts };
  const classes = [];
  for (const key of Object.keys(CHARSETS)) {
    if (!o[key]) continue;
    const chars = [...CHARSETS[key]].filter((c) => !(o.avoidAmbiguous && AMBIGUOUS.has(c)));
    if (chars.length) classes.push(chars);
  }
  return classes;
}

/**
 * generatePassword({length, lower, upper, digits, symbols, avoidAmbiguous})
 * Every selected class appears at least once (resampled until it does, which keeps the
 * distribution uniform over all such passwords).
 */
export function generatePassword(opts = {}, random = defaultRandom) {
  const o = { ...DEFAULTS, ...opts };
  const length = Number(o.length);
  if (!Number.isInteger(length) || length < MIN_LENGTH || length > MAX_LENGTH) {
    throw new RangeError(`length must be ${MIN_LENGTH}..${MAX_LENGTH}`);
  }
  const classes = selectedClasses(o);
  if (!classes.length) throw new RangeError('select at least one character class');
  const pool = classes.flat();
  for (;;) {
    let out = '';
    for (let i = 0; i < length; i++) out += pool[randomInt(pool.length, random)];
    if (classes.every((cls) => cls.some((c) => out.includes(c)))) return out;
  }
}

/** Rough entropy estimate in bits for the chosen options. */
export function estimateBits(opts = {}) {
  const o = { ...DEFAULTS, ...opts };
  const size = selectedClasses(o).flat().length;
  return size ? Math.floor(Number(o.length) * Math.log2(size)) : 0;
}
