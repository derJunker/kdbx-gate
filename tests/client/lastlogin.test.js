import test from 'node:test';
import assert from 'node:assert/strict';
import { describeUserAgent, lastLoginText } from '../../src/lastlogin.js';

test('describeUserAgent: common browsers and systems', () => {
  const cases = [
    ['Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0', 'Firefox on Linux'],
    ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'Chrome on Windows'],
    ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0', 'Edge on Windows'],
    ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15', 'Safari on macOS'],
    ['Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1', 'Safari on iOS'],
    ['Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/140.0 Mobile/15E148 Safari/605.1.15', 'Firefox on iOS'],
    ['Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36', 'Chrome on Android'],
    ['Mozilla/5.0 (Android 15; Mobile; rv:140.0) Gecko/140.0 Firefox/140.0', 'Firefox on Android'],
    ['Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 OPR/120.0.0.0', 'Opera on Linux'],
  ];
  for (const [ua, expected] of cases) assert.equal(describeUserAgent(ua), expected, ua);
});

test('describeUserAgent: unknown agents are shown as sent, empty stays empty', () => {
  assert.equal(describeUserAgent('curl/8.9.1'), 'curl/8.9.1');
  assert.equal(describeUserAgent(''), '');
  assert.equal(describeUserAgent(undefined), '');
});

test('lastLoginText: date, device and the full UA as title', () => {
  const at = new Date(Date.UTC(2026, 9, 16, 12, 30));
  const ua = 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0';
  const r = lastLoginText({ at, ua }, 'en-GB');
  const when = at.toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' });
  assert.equal(r.text, `Last login: ${when} · Firefox on Linux`);
  assert.equal(r.title, ua);
  assert.equal(lastLoginText({ at, ua: '' }, 'en-GB').text, `Last login: ${when}`);
});

test('lastLoginText: no record', () => {
  for (const v of [null, undefined, {}, { at: new Date(NaN), ua: 'x' }]) {
    assert.equal(lastLoginText(v).text, 'Last login: none recorded');
  }
});
