import { parseSourceStatuses, type DataSourceStatus } from './api-contracts-sources.ts';
import { isOneOf, isText, parseArray } from './contract-guards.ts';
import {
  exactRecord,
  hasUniqueKeys,
  isBoolean,
  isCount,
  isNullableText,
  isTimestamp,
  type Raw,
} from './contract-helpers.ts';

/**
 * Inventory contract, mirroring contracts/json-schema/inventory.schema.json (shared vectors:
 * contracts/test-vectors/inventory.vectors.json).
 *
 * Every parser is fail-closed: anything that does not satisfy the exact contract returns null and
 * the caller must render an explicit error state, never a guess. A field says where its value came
 * from (NetBox, telemetry, both, conflict or nobody); the asset class comes only from the operator's
 * NetBox role/type map. Names, roles and sites are untrusted data and never interpreted.
 */
export const ASSET_CLASSES = [
  'network-device',
  'server',
  'access-point',
  'endpoint',
  'cctv',
  'printer',
  'iot',
  'unknown-asset',
  'unclassified',
] as const;
export const CLASS_BASES = ['role-map', 'type-map', 'unmapped', 'not-in-netbox'] as const;
export const ITEM_SOURCES = ['netbox', 'discovered', 'both'] as const;
export const PROVENANCES = ['netbox', 'discovered', 'both', 'conflict', 'unknown'] as const;
export const RECONCILE_STATUSES = [
  'reconciled',
  'missing-discovered',
  'unknown-discovered',
  'status-mismatch',
  'ambiguous',
  'not-checked',
] as const;
export const BLOCK_STATES = ['not-connected', 'unknown', 'ok'] as const;
export const ALIAS_SOURCES = ['netbox', 'librenms', 'wazuh'] as const;
export const DEVICE_STATUSES = [
  'healthy',
  'warning',
  'degraded',
  'critical',
  'offline',
  'unknown',
  'maintenance',
] as const;

export type AssetClass = (typeof ASSET_CLASSES)[number];
export type ClassBasis = (typeof CLASS_BASES)[number];
export type ItemSource = (typeof ITEM_SOURCES)[number];
export type Provenance = (typeof PROVENANCES)[number];
export type ReconcileStatus = (typeof RECONCILE_STATUSES)[number];
export type BlockState = (typeof BLOCK_STATES)[number];
export type DeviceStatus = (typeof DEVICE_STATUSES)[number];

const MAPPED_CLASSES: readonly AssetClass[] = ASSET_CLASSES.slice(0, 7);
export const MAX_PAGE_SIZE = 100;
const DEVICE_ID = /^device-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export interface InventoryField {
  value: string | null;
  provenance: Provenance;
  netbox: string | null;
  discovered: string | null;
}

export interface InventoryReconcile {
  status: ReconcileStatus;
  detail: string | null;
}

export interface InventoryAlias {
  source: 'netbox' | 'librenms' | 'wazuh';
  native_id: string;
}

export interface InventoryItem {
  id: string;
  asset_class: AssetClass;
  class_basis: ClassBasis;
  source: ItemSource;
  known: boolean;
  name: InventoryField;
  site: InventoryField;
  ip_address: InventoryField;
  mac_address: InventoryField;
  role: string | null;
  device_type: string | null;
  intended_status: string | null;
  observed_status: DeviceStatus | null;
  reconcile: InventoryReconcile;
  sources: InventoryAlias[];
}

export interface InventorySummary {
  total: number;
  known: number;
  unknown: number;
  by_class: Array<{ asset_class: AssetClass; count: number }>;
  by_source: Array<{ source: ItemSource; count: number }>;
}

export interface InventoryList {
  state: BlockState;
  generated_at: string;
  page: number;
  page_size: number;
  total: number;
  sources: DataSourceStatus[];
  summary: InventorySummary | null;
  items: InventoryItem[];
}

export interface InventoryDetail {
  state: BlockState;
  generated_at: string;
  sources: DataSourceStatus[];
  item: InventoryItem | null;
}

export interface InventorySummaryResponse {
  state: BlockState;
  generated_at: string;
  sources: DataSourceStatus[];
  summary: InventorySummary | null;
}

const FIELD_KEYS = ['value', 'provenance', 'netbox', 'discovered'] as const;
const RECONCILE_KEYS = ['status', 'detail'] as const;
const ALIAS_KEYS = ['source', 'native_id'] as const;
const ITEM_KEYS = [
  'id',
  'asset_class',
  'class_basis',
  'source',
  'known',
  'name',
  'site',
  'ip_address',
  'mac_address',
  'role',
  'device_type',
  'intended_status',
  'observed_status',
  'reconcile',
  'sources',
] as const;
const SUMMARY_KEYS = ['total', 'known', 'unknown', 'by_class', 'by_source'] as const;
const LIST_KEYS = [
  'state',
  'generated_at',
  'page',
  'page_size',
  'total',
  'sources',
  'summary',
  'items',
] as const;
const DETAIL_KEYS = ['state', 'generated_at', 'sources', 'item'] as const;
const SUMMARY_RESPONSE_KEYS = ['state', 'generated_at', 'sources', 'summary'] as const;

// --- field / reconcile / alias ---------------------------------------------------------------------

export function parseInventoryField(value: unknown): InventoryField | null {
  const record = exactRecord(value, FIELD_KEYS);
  if (
    record === null ||
    !isNullableText(record.value, 255) ||
    !isNullableText(record.netbox, 255) ||
    !isNullableText(record.discovered, 255) ||
    !isOneOf(record.provenance, PROVENANCES)
  ) {
    return null;
  }
  const { value: shown, netbox, discovered } = record;
  const shapes: Record<Provenance, boolean> = {
    netbox: netbox !== null && discovered === null && shown === netbox,
    discovered: netbox === null && discovered !== null && shown === discovered,
    both: netbox !== null && netbox === discovered && shown === netbox,
    // NetBox is the authority for intended state, so a conflict keeps the NetBox value.
    conflict: netbox !== null && discovered !== null && netbox !== discovered && shown === netbox,
    unknown: netbox === null && discovered === null && shown === null,
  };
  if (!shapes[record.provenance]) return null;
  return { value: shown, provenance: record.provenance, netbox, discovered };
}

export function parseInventoryReconcile(value: unknown): InventoryReconcile | null {
  const record = exactRecord(value, RECONCILE_KEYS);
  if (
    record === null ||
    !isOneOf(record.status, RECONCILE_STATUSES) ||
    !isNullableText(record.detail, 255)
  ) {
    return null;
  }
  return { status: record.status, detail: record.detail };
}

export function parseInventoryAlias(value: unknown): InventoryAlias | null {
  const record = exactRecord(value, ALIAS_KEYS);
  if (
    record === null ||
    !isOneOf(record.source, ALIAS_SOURCES) ||
    !isText(record.native_id, 1, 255)
  ) {
    return null;
  }
  return { source: record.source, native_id: record.native_id };
}

// --- item ----------------------------------------------------------------------------------------------

function classAgreesWithBasis(raw: Raw): boolean {
  const inNetbox = raw.source === 'netbox' || raw.source === 'both';
  if (raw.known !== inNetbox) return false;
  if (!inNetbox) {
    return (
      raw.asset_class === 'unknown-asset' &&
      raw.class_basis === 'not-in-netbox' &&
      raw.role === null &&
      raw.device_type === null &&
      raw.intended_status === null
    );
  }
  if (raw.class_basis === 'unmapped') return raw.asset_class === 'unclassified';
  if (raw.class_basis === 'role-map' || raw.class_basis === 'type-map') {
    return MAPPED_CLASSES.includes(raw.asset_class as AssetClass);
  }
  return false;
}

function fieldsAgreeWithPresence(
  raw: Raw,
  fields: readonly InventoryField[],
  aliases: readonly InventoryAlias[],
): boolean {
  const inNetbox = raw.source === 'netbox' || raw.source === 'both';
  const inDiscovery = raw.source === 'discovered' || raw.source === 'both';
  for (const field of fields) {
    if (!inNetbox && field.netbox !== null) return false;
    if (!inDiscovery && field.discovered !== null) return false;
  }
  const [name] = fields;
  if (name.provenance === 'unknown') return false;
  if ((inNetbox && name.netbox === null) || (inDiscovery && name.discovered === null)) return false;
  if (!hasUniqueKeys(aliases, (alias) => alias.source)) return false;
  const names = aliases.map((alias) => alias.source);
  if (names.includes('netbox') !== inNetbox) return false;
  return (names.includes('librenms') || names.includes('wazuh')) === inDiscovery;
}

export function parseInventoryItem(value: unknown): InventoryItem | null {
  const record = exactRecord(value, ITEM_KEYS);
  if (
    record === null ||
    typeof record.id !== 'string' ||
    !DEVICE_ID.test(record.id) ||
    !isOneOf(record.asset_class, ASSET_CLASSES) ||
    !isOneOf(record.class_basis, CLASS_BASES) ||
    !isOneOf(record.source, ITEM_SOURCES) ||
    !isBoolean(record.known) ||
    !isNullableText(record.role, 128) ||
    !isNullableText(record.device_type, 128) ||
    !isNullableText(record.intended_status, 64) ||
    !(record.observed_status === null || isOneOf(record.observed_status, DEVICE_STATUSES))
  ) {
    return null;
  }
  const name = parseInventoryField(record.name);
  const site = parseInventoryField(record.site);
  const ip = parseInventoryField(record.ip_address);
  const mac = parseInventoryField(record.mac_address);
  const reconcile = parseInventoryReconcile(record.reconcile);
  const aliases = parseArray(record.sources, 1, 3, parseInventoryAlias);
  if (
    name === null ||
    site === null ||
    ip === null ||
    mac === null ||
    reconcile === null ||
    aliases === null ||
    !classAgreesWithBasis(record) ||
    !fieldsAgreeWithPresence(record, [name, site, ip, mac], aliases) ||
    (record.source === 'netbox' && record.observed_status !== null)
  ) {
    return null;
  }
  return {
    id: record.id,
    asset_class: record.asset_class,
    class_basis: record.class_basis,
    source: record.source,
    known: record.known,
    name,
    site,
    ip_address: ip,
    mac_address: mac,
    role: record.role,
    device_type: record.device_type,
    intended_status: record.intended_status,
    observed_status: record.observed_status,
    reconcile,
    sources: aliases,
  };
}

// --- summary ---------------------------------------------------------------------------------------------

function parseClassCount(value: unknown): { asset_class: AssetClass; count: number } | null {
  const record = exactRecord(value, ['asset_class', 'count']);
  if (record === null || !isOneOf(record.asset_class, ASSET_CLASSES) || !isCount(record.count)) {
    return null;
  }
  return { asset_class: record.asset_class, count: record.count };
}

function parseSourceCount(value: unknown): { source: ItemSource; count: number } | null {
  const record = exactRecord(value, ['source', 'count']);
  if (record === null || !isOneOf(record.source, ITEM_SOURCES) || !isCount(record.count)) {
    return null;
  }
  return { source: record.source, count: record.count };
}

const sum = (rows: ReadonlyArray<{ count: number }>): number =>
  rows.reduce((total, row) => total + row.count, 0);

export function parseInventorySummary(value: unknown): InventorySummary | null {
  const record = exactRecord(value, SUMMARY_KEYS);
  if (
    record === null ||
    !isCount(record.total) ||
    !isCount(record.known) ||
    !isCount(record.unknown)
  ) {
    return null;
  }
  const byClass = parseArray(record.by_class, 0, 9, parseClassCount);
  const bySource = parseArray(record.by_source, 0, 3, parseSourceCount);
  if (
    byClass === null ||
    bySource === null ||
    record.total !== record.known + record.unknown ||
    !hasUniqueKeys(byClass, (row) => row.asset_class) ||
    !hasUniqueKeys(bySource, (row) => row.source) ||
    sum(byClass) !== record.total ||
    sum(bySource) !== record.total ||
    sum(bySource.filter((row) => row.source !== 'discovered')) !== record.known
  ) {
    return null;
  }
  return {
    total: record.total,
    known: record.known,
    unknown: record.unknown,
    by_class: byClass,
    by_source: bySource,
  };
}

// --- responses -------------------------------------------------------------------------------------------

function isPositiveInt(value: unknown, maximum: number): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= maximum;
}

export function parseInventoryList(value: unknown): InventoryList | null {
  const record = exactRecord(value, LIST_KEYS);
  if (
    record === null ||
    !isOneOf(record.state, BLOCK_STATES) ||
    !isTimestamp(record.generated_at) ||
    !isPositiveInt(record.page, 100_000) ||
    !isPositiveInt(record.page_size, MAX_PAGE_SIZE) ||
    !isCount(record.total)
  ) {
    return null;
  }
  const sources = parseSourceStatuses(record.sources, 'netbox');
  const summary = record.summary === null ? null : parseInventorySummary(record.summary);
  const items = parseArray(record.items, 0, MAX_PAGE_SIZE, parseInventoryItem);
  if (sources === null || items === null || (record.summary !== null && summary === null)) {
    return null;
  }
  if (record.state !== 'ok') {
    if (items.length > 0 || record.total !== 0 || summary !== null) return null;
  } else if (
    summary === null ||
    items.length > record.page_size ||
    items.length > record.total ||
    !hasUniqueKeys(items, (item) => item.id)
  ) {
    return null;
  }
  return {
    state: record.state,
    generated_at: record.generated_at,
    page: record.page,
    page_size: record.page_size,
    total: record.total,
    sources,
    summary,
    items,
  };
}

export function parseInventoryDetail(value: unknown): InventoryDetail | null {
  const record = exactRecord(value, DETAIL_KEYS);
  if (record === null || !isOneOf(record.state, BLOCK_STATES) || !isTimestamp(record.generated_at)) {
    return null;
  }
  const sources = parseSourceStatuses(record.sources, 'netbox');
  const item = record.item === null ? null : parseInventoryItem(record.item);
  if (sources === null || (record.item !== null && item === null)) return null;
  if ((record.state === 'ok') !== (item !== null)) return null;
  return { state: record.state, generated_at: record.generated_at, sources, item };
}

export function parseInventorySummaryResponse(value: unknown): InventorySummaryResponse | null {
  const record = exactRecord(value, SUMMARY_RESPONSE_KEYS);
  if (record === null || !isOneOf(record.state, BLOCK_STATES) || !isTimestamp(record.generated_at)) {
    return null;
  }
  const sources = parseSourceStatuses(record.sources, 'netbox');
  const summary = record.summary === null ? null : parseInventorySummary(record.summary);
  if (sources === null || (record.summary !== null && summary === null)) return null;
  if ((record.state === 'ok') !== (summary !== null)) return null;
  return { state: record.state, generated_at: record.generated_at, sources, summary };
}
