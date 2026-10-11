import { isOneOf } from './contract-guards.ts';
import { exactRecord, isNullableTimestamp, type Raw } from './contract-helpers.ts';

/**
 * The per-source read status, mirroring contracts/json-schema/common.schema.json#/$defs/sourceStatus
 * (shared vectors: contracts/test-vectors/inventory.vectors.json). An ok read carries the time it was
 * made; not-connected (not configured) and unknown (configured but unreadable) carry none.
 */
export const SOURCE_NAMES = ['netbox', 'librenms', 'wazuh'] as const;
export const READ_STATES = ['ok', 'not-connected', 'unknown'] as const;

export type SourceName = (typeof SOURCE_NAMES)[number];
export type ReadState = (typeof READ_STATES)[number];

export interface DataSourceStatus {
  source: SourceName;
  state: ReadState;
  observed_at: string | null;
}

const KEYS = ['source', 'state', 'observed_at'] as const;

export function parseDataSourceStatus(value: unknown): DataSourceStatus | null {
  const record: Raw | null = exactRecord(value, KEYS);
  if (
    record === null ||
    !isOneOf(record.source, SOURCE_NAMES) ||
    !isOneOf(record.state, READ_STATES) ||
    !isNullableTimestamp(record.observed_at) ||
    (record.state === 'ok') !== (record.observed_at !== null)
  ) {
    return null;
  }
  return { source: record.source, state: record.state, observed_at: record.observed_at };
}

/** A bounded list of source statuses, each source once, that includes `required`. */
export function parseSourceStatuses(
  value: unknown,
  required: SourceName,
): DataSourceStatus[] | null {
  if (!Array.isArray(value) || value.length > SOURCE_NAMES.length) return null;
  const sources: DataSourceStatus[] = [];
  for (const raw of value) {
    const parsed = parseDataSourceStatus(raw);
    if (parsed === null) return null;
    sources.push(parsed);
  }
  const names = sources.map((s) => s.source);
  if (new Set(names).size !== names.length || !names.includes(required)) return null;
  return sources;
}
