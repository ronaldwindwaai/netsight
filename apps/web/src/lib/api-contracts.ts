export const DEVICE_STATUSES = [
  'healthy',
  'warning',
  'degraded',
  'critical',
  'offline',
  'unknown',
  'maintenance',
] as const;

export type DeviceStatus = (typeof DEVICE_STATUSES)[number];
export type FreshnessState = 'fresh' | 'stale' | 'unknown';

export interface Freshness {
  state: FreshnessState;
  observed_at: string | null;
  source: string | null;
}

export interface SourceAlias {
  source: string;
  native_id: string;
}

export interface Device {
  id: string;
  name: string;
  hostname: string | null;
  type: string;
  status: DeviceStatus;
  ip_addresses: string[];
  mac_addresses: string[];
  site_id: string | null;
  owner_identity_id: string | null;
  source_aliases: SourceAlias[];
  freshness: Freshness;
}

export interface DeviceListResponse {
  items: Device[];
  page: number;
  page_size: number;
  total: number;
  freshness: Freshness;
}

export interface DeviceDetailResponse {
  item: Device;
}

export interface ApiError {
  code: string;
  message: string;
  correlationId: string;
}

type UnknownRecord = Record<string, unknown>;

const DEVICE_ID_PATTERN =
  /^device-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ERROR_CODE_PATTERN = /^[A-Z0-9_]+$/;

const FRESHNESS_KEYS = ['state', 'observed_at', 'source'] as const;
const SOURCE_ALIAS_KEYS = ['source', 'native_id'] as const;
const DEVICE_REQUIRED_KEYS = ['id', 'name', 'status', 'source_aliases', 'freshness'] as const;
const DEVICE_KEYS = [
  ...DEVICE_REQUIRED_KEYS,
  'hostname',
  'type',
  'ip_addresses',
  'mac_addresses',
  'site_id',
  'owner_identity_id',
] as const;
const DEVICE_LIST_KEYS = ['items', 'page', 'page_size', 'total', 'freshness'] as const;
const DEVICE_DETAIL_KEYS = ['item'] as const;
const ERROR_ENVELOPE_KEYS = ['error'] as const;
const ERROR_DETAIL_KEYS = ['code', 'message', 'correlation_id'] as const;

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasContractKeys(
  value: UnknownRecord,
  required: readonly string[],
  allowed: readonly string[] = required,
): boolean {
  const keys = Object.keys(value);
  return (
    required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    keys.every((key) => allowed.includes(key))
  );
}

function isBoundedString(value: unknown, minimum: number, maximum: number): value is string {
  return (
    typeof value === 'string' &&
    value.length >= minimum &&
    value.length <= maximum
  );
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === 'string';
}

function isRfc3339(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.exec(
    value,
  );
  if (!match || Number.isNaN(Date.parse(value))) return false;

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const calendarDate = new Date(0);
  calendarDate.setUTCFullYear(year, month - 1, day);
  calendarDate.setUTCHours(0, 0, 0, 0);
  return (
    calendarDate.getUTCFullYear() === year &&
    calendarDate.getUTCMonth() === month - 1 &&
    calendarDate.getUTCDate() === day
  );
}

function parseStringArray(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    return null;
  }
  return [...value];
}

export function parseFreshness(value: unknown): Freshness | null {
  if (!isRecord(value) || !hasContractKeys(value, FRESHNESS_KEYS)) return null;
  if (
    typeof value.state !== 'string' ||
    !['fresh', 'stale', 'unknown'].includes(value.state)
  ) {
    return null;
  }
  if (!isNullableString(value.source)) return null;
  if (
    value.observed_at !== null &&
    (typeof value.observed_at !== 'string' || !isRfc3339(value.observed_at))
  ) {
    return null;
  }
  return {
    state: value.state as FreshnessState,
    observed_at: value.observed_at,
    source: value.source,
  };
}

function parseSourceAliases(value: unknown): SourceAlias[] | null {
  if (!Array.isArray(value) || value.length < 1 || value.length > 32) return null;

  const aliases: SourceAlias[] = [];
  const pairs = new Set<string>();
  for (const alias of value) {
    if (
      !isRecord(alias) ||
      !hasContractKeys(alias, SOURCE_ALIAS_KEYS) ||
      !isBoundedString(alias.source, 1, 64) ||
      !isBoundedString(alias.native_id, 1, 255)
    ) {
      return null;
    }

    const pair = JSON.stringify([alias.source, alias.native_id]);
    if (pairs.has(pair)) return null;
    pairs.add(pair);
    aliases.push({ source: alias.source, native_id: alias.native_id });
  }
  return aliases;
}

export function parseDevice(value: unknown): Device | null {
  if (
    !isRecord(value) ||
    !hasContractKeys(value, DEVICE_REQUIRED_KEYS, DEVICE_KEYS) ||
    typeof value.id !== 'string' ||
    !DEVICE_ID_PATTERN.test(value.id) ||
    typeof value.name !== 'string' ||
    !DEVICE_STATUSES.includes(value.status as DeviceStatus)
  ) {
    return null;
  }

  if (
    ('hostname' in value && !isNullableString(value.hostname)) ||
    ('type' in value && typeof value.type !== 'string') ||
    ('site_id' in value && !isNullableString(value.site_id)) ||
    ('owner_identity_id' in value && !isNullableString(value.owner_identity_id))
  ) {
    return null;
  }

  const ipAddresses = parseStringArray(value.ip_addresses === undefined ? [] : value.ip_addresses);
  const macAddresses = parseStringArray(
    value.mac_addresses === undefined ? [] : value.mac_addresses,
  );
  const sourceAliases = parseSourceAliases(value.source_aliases);
  const freshness = parseFreshness(value.freshness);
  if (
    ipAddresses === null ||
    macAddresses === null ||
    sourceAliases === null ||
    freshness === null
  ) {
    return null;
  }

  return {
    id: value.id,
    name: value.name,
    hostname: value.hostname === undefined ? null : (value.hostname as string | null),
    type: value.type === undefined ? 'unknown' : (value.type as string),
    status: value.status as DeviceStatus,
    ip_addresses: ipAddresses,
    mac_addresses: macAddresses,
    site_id: value.site_id === undefined ? null : (value.site_id as string | null),
    owner_identity_id:
      value.owner_identity_id === undefined ? null : (value.owner_identity_id as string | null),
    source_aliases: sourceAliases,
    freshness,
  };
}

function isBoundedInteger(value: unknown, minimum: number, maximum?: number): value is number {
  return (
    Number.isInteger(value) &&
    (value as number) >= minimum &&
    (maximum === undefined || (value as number) <= maximum)
  );
}

export function parseDeviceList(value: unknown): DeviceListResponse | null {
  if (
    !isRecord(value) ||
    !hasContractKeys(value, DEVICE_LIST_KEYS) ||
    !Array.isArray(value.items) ||
    !isBoundedInteger(value.page, 1) ||
    !isBoundedInteger(value.page_size, 1, 100) ||
    !isBoundedInteger(value.total, 0)
  ) {
    return null;
  }

  const items = value.items.map(parseDevice);
  const freshness = parseFreshness(value.freshness);
  if (items.some((item) => item === null) || freshness === null) return null;

  return {
    items: items as Device[],
    page: value.page,
    page_size: value.page_size,
    total: value.total,
    freshness,
  };
}

export function parseDeviceDetail(value: unknown): DeviceDetailResponse | null {
  if (!isRecord(value) || !hasContractKeys(value, DEVICE_DETAIL_KEYS)) return null;
  const item = parseDevice(value.item);
  return item ? { item } : null;
}

export function parseApiError(value: unknown): ApiError | null {
  if (!isRecord(value) || !hasContractKeys(value, ERROR_ENVELOPE_KEYS) || !isRecord(value.error)) {
    return null;
  }
  if (!hasContractKeys(value.error, ERROR_DETAIL_KEYS)) return null;

  const { code, message, correlation_id: correlationId } = value.error;
  if (
    typeof code !== 'string' ||
    !ERROR_CODE_PATTERN.test(code) ||
    typeof message !== 'string' ||
    !isBoundedString(correlationId, 1, 64)
  ) {
    return null;
  }
  return { code, message, correlationId };
}
