import 'server-only';

import { resolveAuthProxyTarget } from '@/lib/auth-proxy-target';
import {
  buildResponseHeaders,
  buildUpstreamRequest,
  hasNoBody,
} from '@/lib/auth-proxy-request';

const PROXY_TIMEOUT_MS = 10_000;

/**
 * Same-origin proxy for browser-driven authentication flows.
 *
 * The Netsight API binds to loopback only and must never be exposed
 * publicly. OIDC redirects, local credential sign-in and the CSRF-protected
 * logout are browser-driven, so they are proxied through the web tier on the
 * same origin.
 *
 * Implemented as a route handler rather than a `next.config.ts` rewrite
 * because the production deploy ships only `src/` (see the web package
 * `files` allow-list), which would silently drop a build-time rewrite.
 *
 * The request/response translation lives in `auth-proxy-request.ts` so it can
 * be tested directly; this module only adds the server-only boundary, the
 * allow-list decision and the upstream call.
 */
export async function proxyAuthRequest(path: string, request: Request): Promise<Response> {
  const target = resolveAuthProxyTarget(path);
  if (target === null) {
    return new Response('Not Found', { status: 404 });
  }

  const upstreamRequest = await buildUpstreamRequest(request);

  let upstream: Response;
  try {
    upstream = await fetch(target, {
      method: upstreamRequest.method,
      headers: upstreamRequest.headers,
      body: upstreamRequest.body,
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

  const body = hasNoBody(upstream.status) ? null : await upstream.text();
  return new Response(body, {
    status: upstream.status,
    headers: buildResponseHeaders(upstream.headers),
  });
}