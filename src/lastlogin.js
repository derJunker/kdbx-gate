// "Last login" line in the top bar: the previous successful open reported by api.php.

const BROWSERS = [
  [/\bEdg(?:e|A|iOS)?\//, 'Edge'],
  [/\b(?:OPR|Opera)\//, 'Opera'],
  [/\b(?:Firefox|FxiOS)\//, 'Firefox'],
  [/\bSamsungBrowser\//, 'Samsung Internet'],
  [/\b(?:Chrome|CriOS|Chromium)\//, 'Chrome'],
  [/\bSafari\//, 'Safari'],
];

const SYSTEMS = [
  [/\bAndroid\b/, 'Android'],
  [/\b(?:iPhone|iPad|iPod)\b/, 'iOS'],
  [/\bWindows\b/, 'Windows'],
  [/\bCrOS\b/, 'ChromeOS'],
  [/\bMac OS X\b|\bMacintosh\b/, 'macOS'],
  [/\bLinux\b/, 'Linux'],
];

const match = (list, ua) => (list.find(([re]) => re.test(ua)) || [])[1];

/** "Firefox on Linux" for a known User-Agent, otherwise the raw string ('' if empty). */
export function describeUserAgent(ua) {
  if (typeof ua !== 'string') return '';
  const browser = match(BROWSERS, ua);
  const system = match(SYSTEMS, ua);
  if (browser && system) return `${browser} on ${system}`;
  return browser || system || ua.trim();
}

/** {text, title} for the top bar; lastLogin is api.open()'s {at: Date, ua} or null. */
export function lastLoginText(lastLogin, locale) {
  if (!lastLogin || !(lastLogin.at instanceof Date) || Number.isNaN(lastLogin.at.getTime())) {
    return { text: 'Last login: none recorded', title: 'No earlier successful login is on record.' };
  }
  const when = lastLogin.at.toLocaleString(locale, { dateStyle: 'medium', timeStyle: 'short' });
  const device = describeUserAgent(lastLogin.ua);
  return {
    text: `Last login: ${when}${device ? ` · ${device}` : ''}`,
    title: lastLogin.ua || 'No User-Agent was sent.',
  };
}
