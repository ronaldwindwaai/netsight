/**
 * Explicit same-origin check for browser-invoked server actions and for the export download routes
 * (`isCrossSiteRequest` in `internet-export.ts`, which treats "no proof of same origin" as refusal).
 *
 * A server action is a public POST. Next.js rejects a cross-site origin by default, but a
 * privileged action should not rely on that alone: a later config change, or a request that
 * reaches the server without the browser's headers, would leave the backend's own origin guard
 * (which sees only this server) unable to help. These helpers are pure so the decision is
 * testable without a request.
 *
 * Rules:
 * - `Origin`, when present, decides alone. A present-but-unusable Origin (`null`, malformed) is
 *   a rejection and never falls back to `Referer`.
 * - `Referer` is consulted only when `Origin` is absent.
 * - Scheme and host (with port) must both match the site the request was addressed to.
 * - `X-Forwarded-Host` / `X-Forwarded-Proto` are client-controllable unless a trusted reverse
 *   proxy overwrites them, so they count only when `NETSIGHT_TRUST_PROXY_HEADERS=true` is set
 *   (see docs/02-security/THREAT-MODEL.md). Behind a proxy that rewrites `Host` to an internal
 *   name, turn it on and make the proxy overwrite both headers; otherwise leave it off.
 */

export interface RequestHeaders {
  host: string | null;
  forwardedHost: string | null;
  forwardedProto: string | null;
  origin: string | null;
  referer: string | null;
}

export interface OriginPolicy {
  /** Honour X-Forwarded-Host / X-Forwarded-Proto (only behind a proxy that overwrites them). */
  trustProxy: boolean;
  /** Production sites are served over https; development and loopback may use http. */
  production: boolean;
}

export interface ParsedOrigin {
  scheme: 'http' | 'https';
  host: string;
}

const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

/** The scheme and lowercased host (with port) of an Origin or Referer value, or null. */
export function originOf(value: string | null): ParsedOrigin | null {
  if (value === null) return null;
  const trimmed = value.trim();
  if (trimmed === '') return null;
  try {
    const url = new URL(trimmed);
    // Origin and Referer are always http(s); anything else has no real host and never matches.
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    if (url.host === '') return null;
    return { scheme: url.protocol === 'https:' ? 'https' : 'http', host: url.host.toLowerCase() };
  } catch {
    return null;
  }
}

function firstListValue(value: string | null): string | null {
  if (value === null) return null;
  const first = value.split(',')[0]?.trim() ?? '';
  return first === '' ? null : first;
}

function hostName(host: string): string {
  return host.startsWith('[') ? host.slice(0, host.indexOf(']') + 1) : host.split(':')[0];
}

function expectedOrigin(headers: RequestHeaders, policy: OriginPolicy): ParsedOrigin | null {
  const forwarded = policy.trustProxy ? firstListValue(headers.forwardedHost) : null;
  const host = (forwarded ?? headers.host)?.trim().toLowerCase() ?? '';
  if (host === '') return null;
  const proto = policy.trustProxy ? firstListValue(headers.forwardedProto)?.toLowerCase() : null;
  if (proto === 'http' || proto === 'https') return { scheme: proto, host };
  const plainAllowed = !policy.production || LOOPBACK_HOSTS.includes(hostName(host));
  return { scheme: plainAllowed ? 'http' : 'https', host };
}

/** True only when the request's Origin (else Referer) is this very site, scheme and host. */
export function sameOrigin(headers: RequestHeaders, policy: OriginPolicy): boolean {
  const expected = expectedOrigin(headers, policy);
  if (expected === null) return false;
  const claimed = headers.origin !== null ? originOf(headers.origin) : originOf(headers.referer);
  if (claimed === null) return false;
  return claimed.host === expected.host && claimed.scheme === expected.scheme;
}

/** Proxy headers are trusted only by an explicit, exact opt-in. */
export function readTrustProxy(env: Record<string, string | undefined>): boolean {
  return env.NETSIGHT_TRUST_PROXY_HEADERS === 'true';
}

/** The origin policy for this process: proxy headers only on explicit opt-in, https in production. */
export function originPolicyFromEnv(env: Record<string, string | undefined>): OriginPolicy {
  return { trustProxy: readTrustProxy(env), production: env.NODE_ENV === 'production' };
}
