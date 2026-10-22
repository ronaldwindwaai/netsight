const DEFAULT_API_URL = 'http://127.0.0.1:8000';
const API_PREFIX = '/api/v1/';
const REJECTED = 'Only Netsight API v1 paths are allowed';

// Strict allowlist: fixed prefix, then RFC 3986 path characters (no backslash, space, control
// characters, `#` or `@`), then an optional query of the same character set plus `?`.
const SAFE_API_PATH = /^\/api\/v1\/[A-Za-z0-9._~!$&'()*+,;=:%/-]*(\?[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*)?$/;

// An encoded slash or backslash in the path is decoded by some hops (a proxy, the backend router)
// and not by others, which is how `/api/v1/a%2f..%2fadmin` slips past a segment check. No Netsight
// route needs one in a path (ids are opaque tokens); the query string may still carry `%2F`.
// A `%25` (an encoded percent) is refused too: it is how `%252f` and `%252e` survive one decode.
const ENCODED_SEPARATOR = /%(?:2f|5c|25)/i;

function isDotSegment(segment: string): boolean {
  let decoded: string;
  try {
    decoded = decodeURIComponent(segment);
  } catch {
    return true;
  }
  return decoded === '.' || decoded === '..';
}

/** True only for a path under /api/v1/ with no traversal, no `//`, no encoded dot segments and no encoded slash or backslash. */
export function isSafeApiPath(path: string): boolean {
  if (!SAFE_API_PATH.test(path)) return false;
  const pathname = path.split('?', 1)[0] ?? '';
  if (pathname.includes('//') || ENCODED_SEPARATOR.test(pathname)) return false;
  return !pathname.split('/').some(isDotSegment);
}

/** Validated API base: HTTP(S), no credentials, HTTPS unless loopback. */
export function resolveApiBase(configured: string | undefined): URL {
  const base = new URL(configured ?? DEFAULT_API_URL);
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password) {
    throw new Error('NETSIGHT_API_URL must be an HTTP(S) URL without embedded credentials');
  }
  const isLoopback = ['127.0.0.1', '::1', '[::1]', 'localhost'].includes(base.hostname);
  if (base.protocol !== 'https:' && !isLoopback) {
    throw new Error('NETSIGHT_API_URL must use HTTPS unless it targets loopback');
  }
  return base;
}

/** Builds the upstream URL from the fixed base and an allowlisted path; throws otherwise. */
export function safeApiUrl(path: string, configuredBase: string | undefined): URL {
  if (!isSafeApiPath(path)) throw new Error(REJECTED);
  const base = resolveApiBase(configuredBase);
  const resolved = new URL(path, `${base.toString().replace(/\/$/, '')}/`);
  if (resolved.origin !== base.origin || !resolved.pathname.startsWith(API_PREFIX)) {
    throw new Error(REJECTED);
  }
  return resolved;
}
