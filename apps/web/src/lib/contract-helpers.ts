import { hasContractKeys, isRecord, isRfc3339 } from './api-contracts.ts';
import { isIntegerInRange, isText } from './contract-guards.ts';

/** Small fail-closed checks shared by the Step 8 parsers (inventory, IPAM, unknown devices). */
export type Raw = Record<string, unknown>;

/** The value as a record carrying exactly these keys (none missing, none extra), else null. */
export function exactRecord(value: unknown, keys: readonly string[]): Raw | null {
  return isRecord(value) && hasContractKeys(value, keys) ? (value as Raw) : null;
}

export function isTimestamp(value: unknown): value is string {
  return typeof value === 'string' && isRfc3339(value);
}

export function isNullableTimestamp(value: unknown): value is string | null {
  return value === null || isTimestamp(value);
}

export function isNullableText(value: unknown, maximum: number): value is string | null {
  return value === null || isText(value, 1, maximum);
}

export function isCount(value: unknown, maximum = 1_000_000): value is number {
  return isIntegerInRange(value, 0, maximum);
}

export function isBoolean(value: unknown): value is boolean {
  return typeof value === 'boolean';
}

export function isNullableNumberIn(
  value: unknown,
  minimum: number,
  maximum: number,
): value is number | null {
  return (
    value === null ||
    (typeof value === 'number' && Number.isFinite(value) && value >= minimum && value <= maximum)
  );
}

/** True when no two items share the key. */
export function hasUniqueKeys<T>(items: readonly T[], key: (item: T) => string): boolean {
  return new Set(items.map(key)).size === items.length;
}
