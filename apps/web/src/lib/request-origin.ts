/**
 * Explicit same-origin check for browser-invoked server actions (S7-3).
 *
 * A server action is a public POST. Next.js rejects a cross-site origin by default, but a
 * privileged action should not rely on that alone — a later config change or a proxy that rewrites
 * Host/X-Forwarded-Host could move the request server-to-server, where the backend's own origin
 * guard sees no Origin and cannot help. These helpers are pure so the decision can be tested
 * without a request.
 */

/** The host (including port) of an Origin or Referer header value, or null if unparseable. */
export function originHost(value: string | null): string | null {
  if (value === null) return null;
  const trimmed = value.trim();
  if (trimmed === '') return null;
  try {
    const url = new URL(trimmed);
    // Origin and Referer are always http(s); anything else (e.g. `javascript:`) has no real host
    // and must never match.
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    if (url.host === '') return null;
    return url.host.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * True only when the request's Origin or Referer host equals the host the request was addressed to.
 * A request with neither header, or one whose host differs, is rejected.
 */
export function sameOrigin(
  expectedHost: string | null,
  origin: string | null,
  referer: string | null,
): boolean {
  if (expectedHost === null || expectedHost.trim() === '') return false;
  const host = expectedHost.trim().toLowerCase();
  return originHost(origin) === host || originHost(referer) === host;
}
