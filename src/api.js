// fetch wrappers for api.php (see docs/SPEC.md "HTTP API").
// The token is only ever sent in the X-Vault-Token header, never in a URL.
import { checkParams, TOKEN_RE } from './kdf.js';

const REV_RE = /^[0-9a-f]{64}$/;
const UNIX_TS_RE = /^[1-9][0-9]{0,11}$/;

/** Previous successful open from the X-Vault-Last-Login(-UA) headers: {at: Date, ua} or null. */
function lastLoginFrom(headers) {
  const at = (headers.get('X-Vault-Last-Login') || '').trim();
  if (!UNIX_TS_RE.test(at)) return null;
  return { at: new Date(Number(at) * 1000), ua: (headers.get('X-Vault-Last-Login-UA') || '').slice(0, 256) };
}

export class ApiError extends Error {
  /**
   * code: bad_token | locked | conflict | no_vault | not_configured | too_large | invalid_kdbx |
   *       bad_request | method_not_allowed | insecure | network | bad_response | http_error
   */
  constructor(code, message, { status = 0, attemptsLeft, retryAfter, rev } = {}) {
    super(message || code);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    if (attemptsLeft !== undefined) this.attemptsLeft = attemptsLeft;
    if (retryAfter !== undefined) this.retryAfter = retryAfter;
    if (rev !== undefined) this.rev = rev;
  }
}

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/** https:, or plain http: only on localhost / 127.0.0.1. */
export function isSecureLocation(loc) {
  if (!loc) return false;
  if (loc.protocol === 'https:') return true;
  return loc.protocol === 'http:' && LOCAL_HOSTS.has(loc.hostname);
}

function toInt(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : fallback;
}

async function readJson(res) {
  const type = res.headers.get('Content-Type') || '';
  if (!type.toLowerCase().includes('application/json')) return null;
  try {
    return await res.json();
  } catch {
    return null;
  }
}

/** Maps a non-2xx response to an ApiError. */
async function errorFromResponse(res) {
  const body = await readJson(res);
  const status = res.status;
  const code = body && typeof body.error === 'string' ? body.error : null;
  const headerRetry = toInt(res.headers.get('Retry-After'), 0);
  switch (code) {
    case 'bad_token':
      return new ApiError('bad_token', 'Wrong password', {
        status,
        attemptsLeft: toInt(body.attemptsLeft),
        retryAfter: toInt(body.retryAfter),
      });
    case 'locked':
      return new ApiError('locked', 'Locked', { status, retryAfter: toInt(body.retryAfter, headerRetry) });
    case 'conflict':
      return new ApiError('conflict', 'The vault was changed on the server', {
        status,
        rev: typeof body.rev === 'string' ? body.rev : undefined,
      });
    case 'no_vault':
      return new ApiError('no_vault', 'No vault file on the server', { status });
    case 'not_configured':
      return new ApiError('not_configured', 'Server is not configured', { status });
    case 'too_large':
      return new ApiError('too_large', 'Vault is too large for the server limit', { status });
    case 'invalid_kdbx':
      return new ApiError('invalid_kdbx', 'Server rejected the file (not a KDBX file)', { status });
    case 'method_not_allowed':
      return new ApiError('method_not_allowed', 'Method not allowed', { status });
    case 'bad_request':
      return new ApiError('bad_request', 'Bad request', { status });
    default:
      break;
  }
  if (status === 429) return new ApiError('locked', 'Locked', { status, retryAfter: headerRetry });
  return new ApiError('http_error', `Unexpected server response (HTTP ${status})`, { status });
}

/**
 * createApi({ baseUrl, fetch, location })
 *  - baseUrl: URL of api.php (default 'api.php', relative to the page)
 *  - fetch:   fetch implementation (default globalThis.fetch)
 *  - location: if given, open/save refuse to send the token unless isSecureLocation(location)
 */
export function createApi({ baseUrl = 'api.php', fetch: fetchImpl, location } = {}) {
  const doFetch = fetchImpl || ((...args) => globalThis.fetch(...args));

  const url = (action) => `${baseUrl}${baseUrl.includes('?') ? '&' : '?'}a=${action}`;

  async function request(action, init) {
    let res;
    try {
      res = await doFetch(url(action), {
        cache: 'no-store',
        credentials: 'same-origin',
        redirect: 'error',
        ...init,
      });
    } catch (err) {
      throw new ApiError('network', 'Network error (server unreachable or unexpected redirect)', {});
    }
    if (!res.ok) throw await errorFromResponse(res);
    return res;
  }

  function guardToken(token) {
    if (location !== undefined && !isSecureLocation(location)) {
      throw new ApiError('insecure', 'Refusing to send the password over an insecure connection (use https)');
    }
    if (typeof token !== 'string' || !TOKEN_RE.test(token)) {
      throw new TypeError('token must be 64 lowercase hex chars');
    }
  }

  async function json(res) {
    const body = await readJson(res);
    if (!body || typeof body !== 'object') {
      throw new ApiError('bad_response', 'Server returned an unexpected response (is PHP enabled?)', {
        status: res.status,
      });
    }
    return body;
  }

  return {
    /** GET ?a=params -> {kdf, m, t, p, salt} */
    async getParams() {
      const res = await request('params', { method: 'GET' });
      const body = await json(res);
      try {
        return checkParams(body);
      } catch (err) {
        throw new ApiError('bad_response', `Server sent invalid KDF parameters: ${err.message}`, {
          status: res.status,
        });
      }
    },

    /** GET ?a=status -> {retryAfter, attemptsLeft} */
    async getStatus() {
      const res = await request('status', { method: 'GET' });
      const body = await json(res);
      return { retryAfter: toInt(body.retryAfter), attemptsLeft: toInt(body.attemptsLeft) };
    },

    /** POST ?a=open -> {data: ArrayBuffer, rev, lastLogin: {at: Date, ua} | null} */
    async open(token) {
      guardToken(token);
      const res = await request('open', {
        method: 'POST',
        headers: { 'X-Vault-Token': token },
      });
      const rev = (res.headers.get('X-Vault-Rev') || '').toLowerCase();
      if (!REV_RE.test(rev)) {
        throw new ApiError('bad_response', 'Server response is missing the vault revision (is PHP enabled?)', {
          status: res.status,
        });
      }
      const data = await res.arrayBuffer();
      return { data, rev, lastLogin: lastLoginFrom(res.headers) };
    },

    /** POST ?a=save with the encrypted file -> {rev} */
    async save(token, baseRev, data) {
      guardToken(token);
      if (typeof baseRev !== 'string' || !REV_RE.test(baseRev)) {
        throw new TypeError('baseRev must be 64 lowercase hex chars');
      }
      const res = await request('save', {
        method: 'POST',
        headers: {
          'X-Vault-Token': token,
          'X-Vault-Base-Rev': baseRev,
          'Content-Type': 'application/octet-stream',
        },
        body: data,
      });
      const body = await json(res);
      const rev = typeof body.rev === 'string' ? body.rev.toLowerCase() : '';
      if (!REV_RE.test(rev)) {
        throw new ApiError('bad_response', 'Server did not return the new revision', { status: res.status });
      }
      return { rev };
    },
  };
}

/** HEAD request; resolves true if the URL is publicly readable (HTTP 200). Never throws. */
export async function isPubliclyReadable(path, fetchImpl) {
  const doFetch = fetchImpl || ((...args) => globalThis.fetch(...args));
  try {
    const res = await doFetch(path, { method: 'HEAD', cache: 'no-store', redirect: 'manual', credentials: 'omit' });
    return res.status === 200;
  } catch {
    return false;
  }
}
