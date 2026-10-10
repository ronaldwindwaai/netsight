/**
 * Where a sign-in sends the operator afterwards, and how the UI asks for a fresh sign-in
 * (step-up) without ever echoing an attacker-chosen destination.
 *
 * Pure and free of framework imports so the open-redirect rules are unit-testable.
 */

const MAX_NEXT_LENGTH = 512;
// C0/C1 controls, bidi and zero-width formatting characters: none belong in a path we redirect to.
const FORBIDDEN_CHARACTERS = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/;

// The first path segment of every dashboard area (apps/web/src/app/(dashboard)); the API applies the
// same list to `redirect_to`, so neither side can send the browser to /api, /auth or a static path.
const UI_AREAS = [
  'overview',
  'network',
  'devices',
  'traffic',
  'security',
  'diagnostics',
  'incidents',
  'alerts',
];

type RawParam = string | string[] | undefined;

function inUiArea(path: string): boolean {
  const [pathname] = path.split(/[?#]/, 1);
  return UI_AREAS.includes(pathname.split('/')[1] ?? '');
}

/** A same-origin dashboard path (with optional query), or null. Never a URL, never protocol-relative. */
export function safeNextPath(raw: RawParam): string | null {
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_NEXT_LENGTH) return null;
  if (!value.startsWith('/') || value.startsWith('//')) return null;
  if (value.includes('\\') || FORBIDDEN_CHARACTERS.test(value)) return null;
  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    return null;
  }
  if (decoded.startsWith('//') || decoded.includes('\\') || FORBIDDEN_CHARACTERS.test(decoded)) {
    return null;
  }
  return inUiArea(value) && inUiArea(decoded) ? value : null;
}

/** The provider sign-in link, carrying the destination and the step-up request when present. */
export function providerLoginHref(base: string, next: string | null, stepUp: boolean): string {
  const pairs: string[] = [];
  if (next !== null) pairs.push(`redirect_to=${encodeURIComponent(next)}`);
  if (stepUp) pairs.push('step_up=true');
  return pairs.length === 0 ? base : `${base}?${pairs.join('&')}`;
}

/** Link to the sign-in page asking for a fresh second factor, then returning to `currentPath`. */
export function stepUpHref(currentPath: string): string {
  const next = safeNextPath(currentPath);
  return next === null
    ? '/login?step_up=true'
    : `/login?step_up=true&next=${encodeURIComponent(next)}`;
}

/** Link to the sign-in page (after a 401), returning to `currentPath` when it is a safe one. */
export function signInHref(currentPath: string): string {
  const next = safeNextPath(currentPath);
  return next === null ? '/login' : `/login?next=${encodeURIComponent(next)}`;
}
