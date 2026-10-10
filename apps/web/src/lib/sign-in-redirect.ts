/**
 * Where a sign-in sends the operator afterwards, and how the UI asks for a fresh sign-in
 * (step-up) without ever echoing an attacker-chosen destination.
 *
 * Pure and free of framework imports so the open-redirect rules are unit-testable.
 */

const MAX_NEXT_LENGTH = 512;
// C0/C1 controls, bidi and zero-width formatting characters: none belong in a path we redirect to.
const FORBIDDEN_CHARACTERS = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/;

type RawParam = string | string[] | undefined;

/** A same-origin absolute path (with optional query), or null. Never a URL, never protocol-relative. */
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
  return value;
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
