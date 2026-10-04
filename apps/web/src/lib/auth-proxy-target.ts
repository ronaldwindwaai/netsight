/**
 * Resolution rules for the same-origin authentication proxy.
 *
 * Kept free of `server-only` so the path/URL allow-list is unit-testable.
 * See `auth-proxy.ts` for the route handler that uses it.
 */

const DEFAULT_API_URL = 'http://127.0.0.1:8000';

/**
 * Authentication paths the browser may reach through the proxy.
 *
 * The list is an allow-list on purpose: an unbounded pass-through would let
 * a crafted path reach arbitrary API routes, and the API is otherwise
 * loopback-only.
 */
export const ALLOWED_AUTH_PATHS = new Set([
  'login/microsoft',
  'login/google',
  'login/clerk',
  'callback',
  'session',
  'csrf',
  'providers',
]);

export function resolveAuthProxyTarget(path: string): URL | null {
  const segments = path.split('/').filter((segment) => segment.length > 0);
  const key = segments.join('/');
  if (!ALLOWED_AUTH_PATHS.has(key)) return null;

  let base: URL;
  try {
    base = new URL(process.env.NETSIGHT_API_URL ?? DEFAULT_API_URL);
  } catch {
    return null;
  }
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password) {
    return null;
  }
  const isLoopback = ['127.0.0.1', '::1', '[::1]', 'localhost'].includes(base.hostname);
  if (base.protocol !== 'https:' && !isLoopback) {
    return null;
  }

  const target = new URL(`/auth/${key}`, base);
  if (target.origin !== base.origin) return null;
  return target;
}