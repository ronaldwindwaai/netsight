/**
 * Resolution rules for the same-origin authentication proxy.
 *
 * Kept free of `server-only` so the path/URL allow-list is unit-testable.
 * See `auth-proxy.ts` for the route handler that uses it.
 */

import { safeNextPath } from './sign-in-redirect.ts';

const DEFAULT_API_URL = 'http://127.0.0.1:8000';

const PROVIDER_LOGIN_PATHS = new Set(['login/microsoft', 'login/google']);

/**
 * The only query parameters a browser may pass to a provider login: a safe return path and the
 * step-up request. Everything else (notably OAuth `state`) is dropped; no other auth path
 * receives a query string at all.
 */
function forwardedLoginParams(search: string): URLSearchParams {
  const incoming = new URLSearchParams(search);
  const forwarded = new URLSearchParams();
  const next = safeNextPath(incoming.get('redirect_to') ?? undefined);
  if (next !== null) forwarded.set('redirect_to', next);
  if (incoming.get('step_up') === 'true') forwarded.set('step_up', 'true');
  return forwarded;
}

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
  'callback',
  'session',
  'csrf',
  'providers',
  // Netsight-managed local credentials (ADR 0010).
  'local/login',
  'local/mfa/verify',
  'local/mfa/enroll',
  'local/mfa/activate',
  'local/password/change',
]);

export function resolveAuthProxyTarget(path: string, search = ''): URL | null {
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

  const target = new URL(`/api/v1/auth/${key}`, base);
  if (target.origin !== base.origin) return null;
  if (PROVIDER_LOGIN_PATHS.has(key)) target.search = forwardedLoginParams(search).toString();
  return target;
}