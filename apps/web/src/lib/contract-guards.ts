// Small fail-closed guards shared by the incident / alert-rule parsers.
// Lengths count Unicode code points, matching JSON Schema and pydantic.

export type UnknownRecord = Record<string, unknown>;

export function isPlainRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Exactly these keys: every key present, none extra. */
export function hasExactKeys(value: UnknownRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return (
    actual.length === keys.length &&
    keys.every((key) => Object.prototype.hasOwnProperty.call(value, key))
  );
}

export function codePointLength(value: string): number {
  return Array.from(value).length;
}

export function isText(value: unknown, minimum: number, maximum: number): value is string {
  if (typeof value !== 'string') return false;
  const length = codePointLength(value);
  return length >= minimum && length <= maximum;
}

/** Operator-facing text: bounded and containing at least one non-whitespace character. */
export function isNonBlankText(value: unknown, maximum: number): value is string {
  return isText(value, 1, maximum) && /\S/.test(value);
}

export function isNullableText(
  value: unknown,
  minimum: number,
  maximum: number,
): value is string | null {
  return value === null || isText(value, minimum, maximum);
}

export function isNullableNonBlankText(value: unknown, maximum: number): value is string | null {
  return value === null || isNonBlankText(value, maximum);
}

export function isIntegerInRange(
  value: unknown,
  minimum: number,
  maximum: number,
): value is number {
  return (
    typeof value === 'number' && Number.isInteger(value) && value >= minimum && value <= maximum
  );
}

export function isOneOf<T extends string>(value: unknown, allowed: readonly T[]): value is T {
  return typeof value === 'string' && (allowed as readonly string[]).includes(value);
}

/** Bounded array of valid items, optionally unique; returns a detached copy or null. */
export function parseArray<T>(
  value: unknown,
  minimum: number,
  maximum: number,
  parseItem: (item: unknown) => T | null,
  unique = false,
): T[] | null {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) return null;
  const items: T[] = [];
  for (const raw of value) {
    const item = parseItem(raw);
    if (item === null) return null;
    items.push(item);
  }
  if (unique && new Set(items).size !== items.length) return null;
  return items;
}

export function textItem(
  minimum: number,
  maximum: number,
  nonBlank = false,
): (item: unknown) => string | null {
  return (item) => {
    if (nonBlank ? !isNonBlankText(item, maximum) : !isText(item, minimum, maximum)) return null;
    return item as string;
  };
}
