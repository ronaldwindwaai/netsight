import { parseSourceStatuses, type DataSourceStatus } from './api-contracts-sources.ts';
import { BLOCK_STATES, type BlockState } from './api-contracts-inventory.ts';
import { isOneOf, isText, parseArray } from './contract-guards.ts';
import {
  exactRecord,
  hasUniqueKeys,
  isCount,
  isNullableText,
  isNullableTimestamp,
  isTimestamp,
  type Raw,
} from './contract-helpers.ts';

/**
 * IPAM contract, mirroring contracts/json-schema/ipam.schema.json (shared vectors:
 * contracts/test-vectors/ipam.vectors.json).
 *
 * Every parser is fail-closed. Prefixes, VLANs and intended addresses are NetBox's; an address is
 * active only when telemetry saw it within the window, stale only when telemetry was readable and
 * did not, unknown when it could not be read. A count that was not read is null, never zero.
 * Utilisation is shown with its basis and follows one rule (percentOf). Text is untrusted data.
 */
export const UTILISATION_BASES = [
  'netbox-addresses',
  'netbox-and-discovered',
  'marked-utilized',
  'capacity-not-meaningful',
  'addresses-unavailable',
] as const;
export const ACTIVITIES = ['active', 'stale', 'unknown', 'reserved'] as const;
export const ADDRESS_SOURCES = ['netbox', 'discovered', 'both'] as const;
export const TELEMETRY_SOURCES = ['librenms', 'wazuh'] as const;

export type UtilisationBasis = (typeof UTILISATION_BASES)[number];
export type Activity = (typeof ACTIVITIES)[number];
export type AddressSource = (typeof ADDRESS_SOURCES)[number];
export type TelemetrySource = (typeof TELEMETRY_SOURCES)[number];

export const MAX_PAGE_SIZE = 100;
const MAX_COUNT = 1_000_000;
const MAX_SIZE = 4_294_967_296;
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const PREFIX_ID = new RegExp(`^ipam-prefix-${UUID}$`);
const VLAN_ID = new RegExp(`^ipam-vlan-${UUID}$`);
const ADDRESS_ID = new RegExp(`^ipam-address-${UUID}$`);

export interface IpamCounts {
  prefixes: number | null;
  vlans: number | null;
  addresses: number | null;
  reserved_ranges: number | null;
  active_addresses: number | null;
  stale_addresses: number | null;
  unknown_activity_addresses: number | null;
  discovered_only_addresses: number | null;
}

export interface IpamTelemetry {
  state: BlockState;
  window_seconds: number;
  sources: TelemetrySource[];
}

export interface IpamUtilisation {
  state: 'ok' | 'unknown';
  basis: UtilisationBasis;
  capacity: number | null;
  netbox_addresses: number | null;
  discovered_only: number | null;
  used: number | null;
  reserved: number | null;
  free: number | null;
  percent: number | null;
}

export interface IpamReservedRange {
  start: string;
  end: string;
  size: number;
}

export interface IpamPrefix {
  id: string;
  prefix: string;
  version: 4 | 6;
  vrf: string | null;
  status: string | null;
  site: string | null;
  role: string | null;
  vlan: { vid: number; name: string } | null;
  description: string | null;
  parent_id: string | null;
  depth: number;
  children: number;
  utilisation: IpamUtilisation;
  reserved_ranges: IpamReservedRange[];
  reserved_ranges_total: number;
}

export interface IpamVlan {
  id: string;
  vid: number;
  name: string;
  status: string | null;
  site: string | null;
  group: string | null;
  description: string | null;
  prefix_count: number | null;
}

export interface IpamAddress {
  id: string;
  address: string;
  version: 4 | 6;
  prefix_id: string | null;
  vrf: string | null;
  status: string | null;
  dns_name: string | null;
  description: string | null;
  source: AddressSource;
  activity: Activity;
  seen_by: TelemetrySource[];
  last_seen: string | null;
}

export interface IpamActivityCounts {
  active: number;
  stale: number;
  unknown: number;
  reserved: number;
}

interface Listing {
  state: BlockState;
  generated_at: string;
  sources: DataSourceStatus[];
  telemetry: IpamTelemetry;
  page: number;
  page_size: number;
  total: number;
}

export interface IpamPrefixList extends Listing {
  items: IpamPrefix[];
}

export interface IpamVlanList extends Listing {
  items: IpamVlan[];
}

export interface IpamAddressList extends Listing {
  activity_counts: IpamActivityCounts | null;
  items: IpamAddress[];
}

export interface IpamSummary {
  state: BlockState;
  generated_at: string;
  sources: DataSourceStatus[];
  telemetry: IpamTelemetry;
  counts: IpamCounts | null;
}

/**
 * used over capacity as a percentage with one decimal, rounded half up, at most 100. Integer
 * arithmetic only, so the API, the checks here and the page agree to the last digit.
 */
export function percentOf(used: number, capacity: number): number {
  if (capacity <= 0) return 100;
  const tenths = Math.floor((used * 1000 + Math.floor(capacity / 2)) / capacity);
  return Math.min(tenths, 1000) / 10;
}

const COUNTS_KEYS = [
  'prefixes',
  'vlans',
  'addresses',
  'reserved_ranges',
  'active_addresses',
  'stale_addresses',
  'unknown_activity_addresses',
  'discovered_only_addresses',
] as const;
const TELEMETRY_KEYS = ['state', 'window_seconds', 'sources'] as const;
const UTILISATION_KEYS = [
  'state',
  'basis',
  'capacity',
  'netbox_addresses',
  'discovered_only',
  'used',
  'reserved',
  'free',
  'percent',
] as const;
const RANGE_KEYS = ['start', 'end', 'size'] as const;
const PREFIX_KEYS = [
  'id',
  'prefix',
  'version',
  'vrf',
  'status',
  'site',
  'role',
  'vlan',
  'description',
  'parent_id',
  'depth',
  'children',
  'utilisation',
  'reserved_ranges',
  'reserved_ranges_total',
] as const;
const VLAN_KEYS = [
  'id',
  'vid',
  'name',
  'status',
  'site',
  'group',
  'description',
  'prefix_count',
] as const;
const ADDRESS_KEYS = [
  'id',
  'address',
  'version',
  'prefix_id',
  'vrf',
  'status',
  'dns_name',
  'description',
  'source',
  'activity',
  'seen_by',
  'last_seen',
] as const;
const ACTIVITY_COUNT_KEYS = ['active', 'stale', 'unknown', 'reserved'] as const;
const LISTING_KEYS = ['state', 'generated_at', 'sources', 'telemetry', 'page', 'page_size', 'total'];
const SUMMARY_KEYS = ['state', 'generated_at', 'sources', 'telemetry', 'counts'] as const;

// --- address arithmetic (strings only; no BigInt needed for the checks we make) -------------------------

function ipv4ToInt(text: string): number | null {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255) return null;
    value = value * 256 + Number(part);
  }
  return value;
}

/** The address as a bigint with its family, only for canonical text; null for anything else. */
function parseAddress(text: string): { version: 4 | 6; value: bigint } | null {
  const v4 = ipv4ToInt(text);
  if (v4 !== null) return { version: 4, value: BigInt(v4) };
  if (!text.includes(':') || text.length > 45 || !/^[0-9a-f:.]+$/.test(text)) return null;
  const groups = expandV6(text);
  if (groups === null) return null;
  const value = groups.reduce((acc, g) => (acc << 16n) + BigInt(g), 0n);
  return canonicalV6(value) === text ? { version: 6, value } : null;
}

function expandV6(text: string): number[] | null {
  let work = text;
  const tail = work.lastIndexOf(':');
  if (work.includes('.')) {
    const v4 = ipv4ToInt(work.slice(tail + 1));
    if (v4 === null) return null;
    work = `${work.slice(0, tail + 1)}${(v4 >>> 16).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }
  const halves = work.split('::');
  if (halves.length > 2) return null;
  const toGroups = (part: string): number[] | null => {
    if (part === '') return [];
    const out: number[] = [];
    for (const g of part.split(':')) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const head = toGroups(halves[0]);
  const rest = halves.length === 2 ? toGroups(halves[1]) : [];
  if (head === null || rest === null) return null;
  if (halves.length === 1) return head.length === 8 ? head : null;
  const missing = 8 - head.length - rest.length;
  return missing >= 1 ? [...head, ...new Array<number>(missing).fill(0), ...rest] : null;
}

function canonicalV6(value: bigint): string {
  const groups: number[] = [];
  for (let i = 7; i >= 0; i -= 1) groups.push(Number((value >> BigInt(i * 16)) & 0xffffn));
  let bestStart = -1;
  let bestLength = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i += 1;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j += 1;
    if (j - i > bestLength) [bestStart, bestLength] = [i, j - i];
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestLength < 2) return hex.join(':');
  const left = hex.slice(0, bestStart).join(':');
  const right = hex.slice(bestStart + bestLength).join(':');
  return `${left}::${right}`;
}

/** A canonical network: address bits below the prefix length are zero, text is the canonical form. */
function parseNetwork(text: string): { version: 4 | 6 } | null {
  const slash = text.indexOf('/');
  if (slash < 0 || text.indexOf('/', slash + 1) >= 0) return null;
  const address = parseAddress(text.slice(0, slash));
  const lengthText = text.slice(slash + 1);
  if (address === null || !/^(0|[1-9][0-9]{0,2})$/.test(lengthText)) return null;
  const length = Number(lengthText);
  const bits = address.version === 4 ? 32 : 128;
  if (length > bits) return null;
  const host = BigInt(bits - length);
  return (address.value & ((1n << host) - 1n)) === 0n ? { version: address.version } : null;
}

// --- leaves ----------------------------------------------------------------------------------------------

export function parseIpamCounts(value: unknown): IpamCounts | null {
  const record = exactRecord(value, COUNTS_KEYS);
  if (record === null) return null;
  for (const key of COUNTS_KEYS) {
    if (record[key] !== null && !isCount(record[key], MAX_COUNT)) return null;
  }
  const r = record as Record<(typeof COUNTS_KEYS)[number], number | null>;
  const judged = [r.active_addresses, r.stale_addresses, r.unknown_activity_addresses];
  if (r.addresses !== null && judged.every((v) => v !== null)) {
    const total = (judged as number[]).reduce((a, b) => a + b, 0);
    if (total > r.addresses + (r.discovered_only_addresses ?? 0)) return null;
  }
  return { ...r };
}

export function parseIpamTelemetry(value: unknown): IpamTelemetry | null {
  const record = exactRecord(value, TELEMETRY_KEYS);
  if (
    record === null ||
    !isOneOf(record.state, BLOCK_STATES) ||
    typeof record.window_seconds !== 'number' ||
    !Number.isInteger(record.window_seconds) ||
    record.window_seconds < 3600 ||
    record.window_seconds > 604800
  ) {
    return null;
  }
  const sources = parseArray(
    record.sources,
    0,
    2,
    (item) => (isOneOf(item, TELEMETRY_SOURCES) ? item : null),
    true,
  );
  if (sources === null || (record.state === 'ok') !== (sources.length > 0)) return null;
  return { state: record.state, window_seconds: record.window_seconds, sources };
}

function nullableCount(value: unknown, maximum: number): value is number | null {
  return value === null || isCount(value, maximum);
}

export function parseIpamUtilisation(value: unknown): IpamUtilisation | null {
  const record = exactRecord(value, UTILISATION_KEYS);
  if (
    record === null ||
    !isOneOf(record.state, ['ok', 'unknown'] as const) ||
    !isOneOf(record.basis, UTILISATION_BASES) ||
    !nullableCount(record.capacity, MAX_SIZE) ||
    !nullableCount(record.netbox_addresses, MAX_COUNT) ||
    !nullableCount(record.discovered_only, MAX_COUNT) ||
    !nullableCount(record.used, MAX_COUNT * 2) ||
    !nullableCount(record.reserved, MAX_SIZE) ||
    !nullableCount(record.free, MAX_SIZE) ||
    !(
      record.percent === null ||
      (typeof record.percent === 'number' &&
        Number.isFinite(record.percent) &&
        record.percent >= 0 &&
        record.percent <= 100)
    )
  ) {
    return null;
  }
  const out: IpamUtilisation = {
    state: record.state,
    basis: record.basis,
    capacity: record.capacity,
    netbox_addresses: record.netbox_addresses,
    discovered_only: record.discovered_only,
    used: record.used,
    reserved: record.reserved,
    free: record.free,
    percent: record.percent,
  };
  return utilisationFollowsItsBasis(out) ? out : null;
}

function utilisationFollowsItsBasis(u: IpamUtilisation): boolean {
  const figures = [u.netbox_addresses, u.discovered_only, u.used, u.reserved, u.free, u.percent];
  if (u.state === 'unknown') return figures.every((v) => v === null);
  if (u.basis === 'capacity-not-meaningful' || u.basis === 'addresses-unavailable') return false;
  if (u.basis === 'marked-utilized') return u.percent === 100;
  if (u.basis === 'netbox-addresses' && u.discovered_only !== 0) return false;
  if (
    u.capacity === null ||
    u.netbox_addresses === null ||
    u.discovered_only === null ||
    u.used === null ||
    u.percent === null ||
    (u.reserved === null) !== (u.free === null)
  ) {
    return false;
  }
  const { capacity, netbox_addresses: nb, discovered_only: disc, used, percent } = u;
  if (used !== nb + disc || percent !== percentOf(used, capacity)) return false;
  return u.free === null || u.reserved === null || u.free === Math.max(0, capacity - used - u.reserved);
}

export function parseIpamReservedRange(value: unknown): IpamReservedRange | null {
  const record = exactRecord(value, RANGE_KEYS);
  if (
    record === null ||
    typeof record.start !== 'string' ||
    typeof record.end !== 'string' ||
    typeof record.size !== 'number' ||
    !Number.isInteger(record.size) ||
    record.size < 1 ||
    record.size > MAX_SIZE
  ) {
    return null;
  }
  const start = parseAddress(record.start);
  const end = parseAddress(record.end);
  if (start === null || end === null || start.version !== end.version) return null;
  if (end.value - start.value + 1n !== BigInt(record.size)) return null;
  return { start: record.start, end: record.end, size: record.size };
}

function parseFamily(value: unknown): 4 | 6 | null {
  return value === 4 || value === 6 ? value : null;
}

function parsePrefixVlan(value: unknown): { vid: number; name: string } | null {
  const record = exactRecord(value, ['vid', 'name']);
  if (
    record === null ||
    typeof record.vid !== 'number' ||
    !Number.isInteger(record.vid) ||
    record.vid < 1 ||
    record.vid > 4094 ||
    !isText(record.name, 1, 128)
  ) {
    return null;
  }
  return { vid: record.vid, name: record.name };
}

function isPrefixId(value: unknown): value is string {
  return typeof value === 'string' && PREFIX_ID.test(value);
}

export function parseIpamPrefix(value: unknown): IpamPrefix | null {
  const record = exactRecord(value, PREFIX_KEYS);
  if (
    record === null ||
    !isPrefixId(record.id) ||
    typeof record.prefix !== 'string' ||
    !isNullableText(record.vrf, 128) ||
    !isNullableText(record.status, 64) ||
    !isNullableText(record.site, 128) ||
    !isNullableText(record.role, 128) ||
    !isNullableText(record.description, 128) ||
    !(record.parent_id === null || isPrefixId(record.parent_id)) ||
    typeof record.depth !== 'number' ||
    !Number.isInteger(record.depth) ||
    record.depth < 0 ||
    record.depth > 128 ||
    !isCount(record.children, MAX_COUNT) ||
    !isCount(record.reserved_ranges_total, MAX_COUNT)
  ) {
    return null;
  }
  const version = parseFamily(record.version);
  const network = parseNetwork(record.prefix);
  const vlan = record.vlan === null ? null : parsePrefixVlan(record.vlan);
  const utilisation = parseIpamUtilisation(record.utilisation);
  const ranges = parseArray(record.reserved_ranges, 0, 16, parseIpamReservedRange);
  if (
    version === null ||
    network === null ||
    network.version !== version ||
    (record.vlan !== null && vlan === null) ||
    utilisation === null ||
    ranges === null ||
    (record.parent_id === null) !== (record.depth === 0) ||
    record.parent_id === record.id ||
    ranges.length > record.reserved_ranges_total
  ) {
    return null;
  }
  return {
    id: record.id,
    prefix: record.prefix,
    version,
    vrf: record.vrf,
    status: record.status,
    site: record.site,
    role: record.role,
    vlan,
    description: record.description,
    parent_id: record.parent_id,
    depth: record.depth,
    children: record.children,
    utilisation,
    reserved_ranges: ranges,
    reserved_ranges_total: record.reserved_ranges_total,
  };
}

export function parseIpamVlan(value: unknown): IpamVlan | null {
  const record = exactRecord(value, VLAN_KEYS);
  if (
    record === null ||
    typeof record.id !== 'string' ||
    !VLAN_ID.test(record.id) ||
    typeof record.vid !== 'number' ||
    !Number.isInteger(record.vid) ||
    record.vid < 1 ||
    record.vid > 4094 ||
    !isText(record.name, 1, 128) ||
    !isNullableText(record.status, 64) ||
    !isNullableText(record.site, 128) ||
    !isNullableText(record.group, 128) ||
    !isNullableText(record.description, 128) ||
    !nullableCount(record.prefix_count, MAX_COUNT)
  ) {
    return null;
  }
  return {
    id: record.id,
    vid: record.vid,
    name: record.name,
    status: record.status,
    site: record.site,
    group: record.group,
    description: record.description,
    prefix_count: record.prefix_count,
  };
}

export function parseIpamAddress(value: unknown): IpamAddress | null {
  const record = exactRecord(value, ADDRESS_KEYS);
  if (
    record === null ||
    typeof record.id !== 'string' ||
    !ADDRESS_ID.test(record.id) ||
    typeof record.address !== 'string' ||
    !(record.prefix_id === null || isPrefixId(record.prefix_id)) ||
    !isNullableText(record.vrf, 128) ||
    !isNullableText(record.status, 64) ||
    !isNullableText(record.dns_name, 255) ||
    !isNullableText(record.description, 128) ||
    !isOneOf(record.source, ADDRESS_SOURCES) ||
    !isOneOf(record.activity, ACTIVITIES) ||
    !isNullableTimestamp(record.last_seen)
  ) {
    return null;
  }
  const version = parseFamily(record.version);
  const parsed = parseAddress(record.address);
  const seenBy = parseArray(
    record.seen_by,
    0,
    2,
    (item) => (isOneOf(item, TELEMETRY_SOURCES) ? item : null),
    true,
  );
  if (version === null || parsed === null || parsed.version !== version || seenBy === null) {
    return null;
  }
  if (record.activity === 'active') {
    if (seenBy.length === 0 || record.last_seen === null) return null;
  } else if (seenBy.length > 0 || record.last_seen !== null) {
    return null;
  }
  if (
    record.source === 'discovered' &&
    (record.activity !== 'active' || record.status !== null || record.dns_name !== null)
  ) {
    return null;
  }
  if (record.activity === 'stale' && record.source !== 'netbox') return null;
  return {
    id: record.id,
    address: record.address,
    version,
    prefix_id: record.prefix_id,
    vrf: record.vrf,
    status: record.status,
    dns_name: record.dns_name,
    description: record.description,
    source: record.source,
    activity: record.activity,
    seen_by: seenBy,
    last_seen: record.last_seen,
  };
}

function parseActivityCounts(value: unknown): IpamActivityCounts | null {
  const record = exactRecord(value, ACTIVITY_COUNT_KEYS);
  if (
    record === null ||
    !isCount(record.active) ||
    !isCount(record.stale) ||
    !isCount(record.unknown) ||
    !isCount(record.reserved)
  ) {
    return null;
  }
  return {
    active: record.active,
    stale: record.stale,
    unknown: record.unknown,
    reserved: record.reserved,
  };
}

// --- responses ---------------------------------------------------------------------------------------------

function parseListing(record: Raw): Listing | null {
  if (
    !isOneOf(record.state, BLOCK_STATES) ||
    !isTimestamp(record.generated_at) ||
    typeof record.page !== 'number' ||
    !Number.isInteger(record.page) ||
    record.page < 1 ||
    record.page > 100_000 ||
    typeof record.page_size !== 'number' ||
    !Number.isInteger(record.page_size) ||
    record.page_size < 1 ||
    record.page_size > MAX_PAGE_SIZE ||
    !isCount(record.total, MAX_COUNT)
  ) {
    return null;
  }
  const sources = parseSourceStatuses(record.sources, 'netbox');
  const telemetry = parseIpamTelemetry(record.telemetry);
  if (sources === null || telemetry === null || !telemetryWasRead(sources, telemetry)) return null;
  return {
    state: record.state,
    generated_at: record.generated_at,
    sources,
    telemetry,
    page: record.page,
    page_size: record.page_size,
    total: record.total,
  };
}

function telemetryWasRead(sources: DataSourceStatus[], telemetry: IpamTelemetry): boolean {
  const read = new Set(sources.filter((s) => s.state === 'ok').map((s) => s.source));
  return telemetry.sources.every((source) => read.has(source));
}

function rowsFit<T extends { id: string }>(listing: Listing, items: readonly T[]): boolean {
  if (listing.state !== 'ok') return items.length === 0 && listing.total === 0;
  return (
    items.length <= listing.page_size &&
    items.length <= listing.total &&
    hasUniqueKeys(items, (item) => item.id)
  );
}

export function parseIpamPrefixList(value: unknown): IpamPrefixList | null {
  const record = exactRecord(value, [...LISTING_KEYS, 'items']);
  const listing = record === null ? null : parseListing(record);
  const items =
    record === null ? null : parseArray(record.items, 0, MAX_PAGE_SIZE, parseIpamPrefix);
  if (listing === null || items === null || !rowsFit(listing, items)) return null;
  return { ...listing, items };
}

export function parseIpamVlanList(value: unknown): IpamVlanList | null {
  const record = exactRecord(value, [...LISTING_KEYS, 'items']);
  const listing = record === null ? null : parseListing(record);
  const items = record === null ? null : parseArray(record.items, 0, MAX_PAGE_SIZE, parseIpamVlan);
  if (listing === null || items === null || !rowsFit(listing, items)) return null;
  return { ...listing, items };
}

export function parseIpamAddressList(value: unknown): IpamAddressList | null {
  const record = exactRecord(value, [...LISTING_KEYS, 'activity_counts', 'items']);
  const listing = record === null ? null : parseListing(record);
  const items =
    record === null ? null : parseArray(record.items, 0, MAX_PAGE_SIZE, parseIpamAddress);
  if (record === null || listing === null || items === null || !rowsFit(listing, items)) {
    return null;
  }
  const counts = record.activity_counts === null ? null : parseActivityCounts(record.activity_counts);
  if (record.activity_counts !== null && counts === null) return null;
  if (listing.state !== 'ok') {
    if (counts !== null) return null;
  } else {
    if (counts === null) return null;
    const everything = counts.active + counts.stale + counts.unknown + counts.reserved;
    if (items.length > everything || listing.total > everything) return null;
  }
  return { ...listing, activity_counts: counts, items };
}

export function parseIpamSummary(value: unknown): IpamSummary | null {
  const record = exactRecord(value, SUMMARY_KEYS);
  if (record === null || !isOneOf(record.state, BLOCK_STATES) || !isTimestamp(record.generated_at)) {
    return null;
  }
  const sources = parseSourceStatuses(record.sources, 'netbox');
  const telemetry = parseIpamTelemetry(record.telemetry);
  const counts = record.counts === null ? null : parseIpamCounts(record.counts);
  if (
    sources === null ||
    telemetry === null ||
    !telemetryWasRead(sources, telemetry) ||
    (record.counts !== null && counts === null) ||
    (record.state === 'ok') !== (counts !== null)
  ) {
    return null;
  }
  return { state: record.state, generated_at: record.generated_at, sources, telemetry, counts };
}
