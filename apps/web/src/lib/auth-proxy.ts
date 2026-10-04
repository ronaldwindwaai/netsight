import 'server-only';

import { resolveAuthProxyTarget } from '@/lib/auth-proxy-target';

const PROXY_TIMEOUT_MS = 10_000;
const CSRF_HEADER = 'x-csrf-token';
const COOKIE_HEADER = 'cookie';

/**
 * Same-origin proxy for browser-driven authentication flows.
 *
 * The Netsight API binds to loopback only and must never be exposed
 * publicly. OIDC redirects and the CSRF-protected logout are browser-driven,
 * so they are proxied through the web tier on the same origin.
 *
 * Implemented as a route handler rather than a `next.config.ts` rewrite
 * because the production deploy ships only `src/` (see the web package
 * `files` allow-list), which would silently drop a build-time rewrite.
 */
export async function proxyAuthRequest(path: string, request: Request): Promise<Response> {
  const target = resolveAuthProxyTarget(path);
  if (target === null) {
    return new Response('Not Found', { status: 404 });
  }

  // Forward only the headers the flow needs; never trust the inbound Host
  // or forward the full header set to the API.
  const headers = new Headers();
  headers.set('Accept', 'application/json');
  const csrfToken = request.headers.get(CSRF_HEADER);
  if (csrfToken !== null) headers.set(CSRF_HEADER, csrfToken);
  const cookie = request.headers.get(COOKIE_HEADER);
  if (cookie !== null) headers.set(COOKIE_HEADER, cookie);
  const correlationId = request.headers.get('x-correlation-id');
  if (correlationId !== null) headers.set('X-Correlation-ID', correlationId);

  let upstream: Response;
  try {
    upstream = await fetch(target, {
      method: request.method,
      headers,
      body: request.method === 'GET' || request.method === 'HEAD' ? undefined : null,
      cache: 'no-store',
      redirect: 'manual',
      signal: AbortSignal.timeout(PROXY_TIMEOUT_MS),
    });
  } catch {
    return new Response(
      JSON.stringify({
        error: {
          code: 'AUTH_PROXY_UNAVAILABLE',
          message: 'The Netsight authentication service is unavailable.',
        },
      }),
      { status: 503, headers: { 'Content-Type': 'application/json' } },
    );
  }

  const responseHeaders = new Headers();
  const contentType = upstream.headers.get('content-type');
  if (contentType !== null) responseHeaders.set('Content-Type', contentType);
  const upstreamCorrelationId = upstream.headers.get('x-correlation-id');
  if (upstreamCorrelationId !== null) {
    responseHeaders.set('X-Correlation-ID', upstreamCorrelationId);
  }
  // Pass the session cookie through so the browser stays on this origin.
  const setCookie = upstream.headers.get('set-cookie');
  if (setCookie !== null) responseHeaders.append('Set-Cookie', setCookie);
  const location = upstream.headers.get('location');
  if (location !== null) responseHeaders.set('Location', location);

  const body =
    upstream.status === 204 || upstream.status === 304 ? null : await upstream.text();
  return new Response(body, { status: upstream.status, headers: responseHeaders });
}