import {
  hasContractKeys,
  isRecord,
  isRfc3339,
  type TrafficState,
} from './api-contracts.ts';
import { TRAFFIC_STATES } from './api-contracts-traffic-shared.ts';
import { isIntegerInRange, isOneOf, isText } from './contract-guards.ts';

/** Small fail-closed checks shared by the traffic parsers. Lengths count code points. */

export const RATIO_TOLERANCE = 1e-6;
const COUNTRY = /^[A-Z]{2}$/;

export type Rec = Record<string, unknown>;

// --- primitives ------------------------------------------------------------------------------------

export function count(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0;
}

export function nullableCount(value: unknown): value is number | null {
  return value === null || count(value);
}

export function finite(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

export function share(value: unknown): value is number | null {
  return value === null || (finite(value) && value >= 0 && value <= 1);
}

export function instant(value: unknown): value is string {
  return typeof value === 'string' && isRfc3339(value);
}

export function nullableInstant(value: unknown): value is string | null {
  return value === null || instant(value);
}

export function nullableText(value: unknown, maximum: number): value is string | null {
  return value === null || isText(value, 1, maximum);
}

export function exact(value: unknown, keys: readonly string[]): value is Rec {
  return isRecord(value) && hasContractKeys(value, keys);
}

export function asn(value: unknown): value is number | null {
  return value === null || isIntegerInRange(value, 1, 4294967295);
}

export function country(value: unknown): value is string | null {
  return value === null || (typeof value === 'string' && COUNTRY.test(value));
}

export function isTrafficState(value: unknown): value is TrafficState {
  return isOneOf(value, TRAFFIC_STATES);
}

export function ranks(items: readonly { rank: number }[]): boolean {
  return items.every((item, index) => item.rank === index + 1);
}

