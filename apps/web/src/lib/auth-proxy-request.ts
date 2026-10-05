/**
 * Request/response translation for the Netsight auth proxy.
 *
 * Kept free of `server-only` and of bundler path aliases so it can be exercised
 * directly by the test runner. `auth-proxy.ts` wraps this with the server-only
 * guard.
 *
 * This module exists because the proxy used to forward `body: null` for every
 * non-GET request. That was invisible while the only POSTed auth flow carried
 * no body, and broke local credential sign-in, which posts JSON: the API
 * received an empty request and rejected it with 422.
 */

const CSRF_HEADER = 'x-csrf-token';
const COOKIE_HEADER = 'cookie';

/** Headers that may be forwarded from the browser to the API. */
const FORWARDED_REQUEST_HEADERS: readonly string[] = [CSRF_HEADER, COOKIE_HEADER];

export interface UpstreamRequest {
  method: string;
  headers: Headers;
  body: ArrayBuffer | undefined;
}

/**
 * Build the request to send to the API.
 *
 * The payload and its declared content type both survive the hop: the API
 * validates bodies against typed schemas, so a forwarded body without its
 * `Content-Type` would be rejected.
 *
 * The body is read to a buffer rather than passed as a stream, because a route
 * handler may have already consumed the request stream and a consumed stream
 * cannot be replayed upstream. Auth payloads are small and field-bounded.
 */
export async function buildUpstreamRequest(request: Request): Promise<UpstreamRequest> {
  const headers = new Headers();
  headers.set('Accept', 'application/json');

  // Forward only the headers the flow needs. Never trust the inbound Host or
  // relay the full header set to the API.
  for (const name of FORWARDED_REQUEST_HEADERS) {
    const value = request.headers.get(name);
    if (value !== null) headers.set(name, value);
  }

  const correlationId = request.headers.get('x-correlation-id');
  if (correlationId !== null) headers.set('X-Correlation-ID', correlationId);

  const contentType = request.headers.get('content-type');
  if (contentType !== null) headers.set('Content-Type', contentType);

  const forwardsBody = request.method !== 'GET' && request.method !== 'HEAD';

  return {
    method: request.method,
    headers,
    body: forwardsBody ? await request.arrayBuffer() : undefined,
  };
}

/**
 * Select the response headers to hand back to the browser.
 *
 * The `Set-Cookie` is passed through so the session stays on this origin;
 * nothing else from the upstream is trusted or relayed.
 */
export function buildResponseHeaders(upstream: Headers): Headers {
  const headers = new Headers();

  const contentType = upstream.get('content-type');
  if (contentType !== null) headers.set('Content-Type', contentType);

  const correlationId = upstream.get('x-correlation-id');
  if (correlationId !== null) headers.set('X-Correlation-ID', correlationId);

  const setCookie = upstream.get('set-cookie');
  if (setCookie !== null) headers.append('Set-Cookie', setCookie);

  const location = upstream.get('location');
  if (location !== null) headers.set('Location', location);

  const retryAfter = upstream.get('retry-after');
  if (retryAfter !== null) headers.set('Retry-After', retryAfter);

  return headers;
}

/** True when the upstream response carries no body worth forwarding. */
export function hasNoBody(status: number): boolean {
  return status === 204 || status === 304;
}