import { exactRecord, isCount, isNullableText, isNullableTimestamp, isTimestamp } from './contract-helpers.ts';
import { isOneOf, isText } from './contract-guards.ts';

export const CONFIG_NODE_ID = /^config-node-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export interface ConfigurationNode {
  id: string; name: string; group: string | null; model: string | null;
  backup_status: 'success' | 'failed' | 'never' | 'unknown';
  last_attempt_at: string | null; backup_freshness: 'fresh' | 'stale' | 'unknown';
}
export interface ConfigurationVersion { id: string; saved_at: string }
export interface ConfigurationRead<T> {
  source: 'oxidized'; state: 'ok' | 'partial' | 'not-connected' | 'unknown';
  observed_at: string | null; items: T[]; skipped: number; truncated: boolean;
  page: number; page_size: number; total: number | null; has_more: boolean;
}

export function parseConfigurationNode(value: unknown): ConfigurationNode | null {
  const row = exactRecord(value, ['id', 'name', 'group', 'model', 'backup_status', 'last_attempt_at', 'backup_freshness']);
  if (!row || typeof row.id !== 'string' || !CONFIG_NODE_ID.test(row.id) || !isText(row.name, 1, 255)
    || !isNullableText(row.group, 255) || !isNullableText(row.model, 128)
    || !isOneOf(row.backup_status, ['success', 'failed', 'never', 'unknown'] as const)
    || !isNullableTimestamp(row.last_attempt_at)
    || !isOneOf(row.backup_freshness, ['fresh', 'stale', 'unknown'] as const)) return null;
  if (row.backup_freshness !== 'unknown' && (row.last_attempt_at === null || row.backup_status !== 'success')) return null;
  return row as unknown as ConfigurationNode;
}
export function parseConfigurationVersion(value: unknown): ConfigurationVersion | null {
  const row = exactRecord(value, ['id', 'saved_at']);
  return row && typeof row.id === 'string' && /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(row.id)
    && isTimestamp(row.saved_at) ? row as unknown as ConfigurationVersion : null;
}
function parseRead<T extends { id: string }>(value: unknown, parse: (v: unknown) => T | null): ConfigurationRead<T> | null {
  const raw = exactRecord(value, ['source', 'state', 'observed_at', 'items', 'skipped', 'truncated', 'page', 'page_size', 'total', 'has_more']);
  if (!raw || raw.source !== 'oxidized' || !isOneOf(raw.state, ['ok', 'partial', 'not-connected', 'unknown'] as const)
    || !isNullableTimestamp(raw.observed_at) || !Array.isArray(raw.items) || raw.items.length > 2000
    || !isCount(raw.page, 2000) || raw.page < 1 || !isCount(raw.page_size, 2000) || raw.page_size < 1
    || (raw.total !== null && !isCount(raw.total, 2000)) || typeof raw.has_more !== 'boolean'
    || raw.items.length > raw.page_size || !isCount(raw.skipped, 2000) || typeof raw.truncated !== 'boolean') return null;
  const items: T[] = [];
  for (const value of raw.items) { const item = parse(value); if (item === null) return null; items.push(item); }
  if (new Set(items.map(i => i.id)).size !== items.length) return null;
  const readable = raw.state === 'ok' || raw.state === 'partial';
  if (readable !== (raw.observed_at !== null)) return null;
  if (!readable && (items.length || raw.skipped || raw.truncated || raw.total !== null || raw.has_more)) return null;
  if (readable && ((raw.state === 'partial') !== (raw.skipped > 0 || raw.truncated))) return null;
  return { source: 'oxidized', state: raw.state, observed_at: raw.observed_at, items, skipped: raw.skipped, truncated: raw.truncated, page: raw.page, page_size: raw.page_size, total: raw.total, has_more: raw.has_more };
}
export const parseConfigurationNodes = (value: unknown) => parseRead(value, parseConfigurationNode);
export const parseConfigurationVersions = (value: unknown) => parseRead(value, parseConfigurationVersion);
