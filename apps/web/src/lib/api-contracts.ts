export const DEVICE_STATUSES = [
  'healthy',
  'warning',
  'degraded',
  'critical',
  'offline',
  'unknown',
  'maintenance',
] as const;

export const ALERT_SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export const ALERT_STATES = [
  'open',
  'acknowledged',
  'investigating',
  'resolved',
  'suppressed',
] as const;

export type DeviceStatus = (typeof DEVICE_STATUSES)[number];
export type AlertSeverity = (typeof ALERT_SEVERITIES)[number];
export type AlertState = (typeof ALERT_STATES)[number];
export type FreshnessState = 'fresh' | 'stale' | 'unknown';
export type SourceHealthStatus =
  | 'success'
  | 'unavailable'
  | 'forbidden'
  | 'invalid-source-data';
export type SourceHealthDetail = 'ok' | Exclude<SourceHealthStatus, 'success'>;

export interface Freshness {
  state: FreshnessState;
  observed_at: string | null;
  source: string | null;
}

export interface SourceAlias {
  source: string;
  native_id: string;
}

export type InterfaceAdminStatus = 'up' | 'down' | 'testing' | 'unknown';
export type InterfaceOperStatus =
  | 'up'
  | 'down'
  | 'testing'
  | 'dormant'
  | 'notPresent'
  | 'lowerLayerDown'
  | 'unknown';

export interface NetworkInterface {
  id: string;
  device_id: string;
  index: number | null;
  name: string;
  description: string | null;
  alias: string | null;
  hardware_type: string | null;
  mac_address: string | null;
  admin_status: InterfaceAdminStatus;
  oper_status: InterfaceOperStatus;
  status: DeviceStatus;
  speed_bps: number | null;
  source_aliases: SourceAlias[];
  freshness: Freshness;
}

export interface InterfaceListResponse {
  items: NetworkInterface[];
  total: number;
  freshness: Freshness;
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

export interface SourceHealthResponse {
  source: 'librenms';
  status: SourceHealthStatus;
  reachable: boolean;
  latency_ms: number | null;
  checked_at: string;
  detail: SourceHealthDetail;
}

export interface Alert {
  id: string;
  severity: AlertSeverity;
  state: AlertState;
  title: string;
  observed_at: string;
  device_id: string | null;
  incident_id: string | null;
}

export interface AlertListResponse {
  items: Alert[];
  page: number;
  page_size: number;
  total: number;
  freshness: Freshness;
}

export interface ApiError {
  code: string;
  message: string;
  correlationId: string;
}

export interface ProviderState {
  configured: boolean;
}

export interface AuthProvidersResponse {
  providers: {
    microsoft: ProviderState;
    google: ProviderState;
  };
}

export interface SessionInfo {
  authenticated: true;
  identity_id: string;
  provider: string;
  email: string | null;
  roles: string[];
}

export interface DeviceStatusCount {
  status: DeviceStatus;
  count: number;
}

export interface DeviceHealthSummary {
  total: number;
  by_status: DeviceStatusCount[];
  freshness: Freshness;
}

export interface SourceState {
  configured: boolean;
  status: 'success' | 'unavailable' | 'forbidden' | 'invalid-source-data' | 'not-configured';
}

export interface OverviewResponse {
  devices: DeviceHealthSummary;
  sources: {
    librenms: SourceState;
  };
}

type UnknownRecord = Record<string, unknown>;

const DEVICE_ID_PATTERN =
  /^device-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const INTERFACE_ID_PATTERN =
  /^interface-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
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
const SOURCE_HEALTH_KEYS = [
  'source',
  'status',
  'reachable',
  'latency_ms',
  'checked_at',
  'detail',
] as const;
const ALERT_REQUIRED_KEYS = ['id', 'severity', 'state', 'title', 'observed_at'] as const;
const ALERT_KEYS = [...ALERT_REQUIRED_KEYS, 'device_id', 'incident_id'] as const;
const ALERT_LIST_KEYS = ['items', 'page', 'page_size', 'total', 'freshness'] as const;
const SOURCE_HEALTH_STATUSES: readonly SourceHealthStatus[] = [
  'success',
  'unavailable',
  'forbidden',
  'invalid-source-data',
];
const SOURCE_HEALTH_DETAILS: readonly SourceHealthDetail[] = [
  'ok',
  'unavailable',
  'forbidden',
  'invalid-source-data',
];
const ERROR_ENVELOPE_KEYS = ['error'] as const;
const ERROR_DETAIL_KEYS = ['code', 'message', 'correlation_id'] as const;

const PROVIDER_STATE_KEYS = ['configured'] as const;
const AUTH_PROVIDERS_KEYS = ['providers'] as const;
const SESSION_INFO_KEYS = [
  'authenticated',
  'identity_id',
  'provider',
  'email',
  'roles',
] as const;

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

export function parseSourceHealth(value: unknown): SourceHealthResponse | null {
  if (
    !isRecord(value) ||
    !hasContractKeys(value, SOURCE_HEALTH_KEYS) ||
    value.source !== 'librenms' ||
    typeof value.status !== 'string' ||
    !SOURCE_HEALTH_STATUSES.includes(value.status as SourceHealthStatus) ||
    typeof value.reachable !== 'boolean' ||
    (value.latency_ms !== null &&
      (typeof value.latency_ms !== 'number' ||
        !Number.isFinite(value.latency_ms) ||
        value.latency_ms < 0)) ||
    typeof value.checked_at !== 'string' ||
    !isRfc3339(value.checked_at) ||
    typeof value.detail !== 'string' ||
    !SOURCE_HEALTH_DETAILS.includes(value.detail as SourceHealthDetail)
  ) {
    return null;
  }

  const status = value.status as SourceHealthStatus;
  const detail = value.detail as SourceHealthDetail;
  if (status === 'success') {
    if (!value.reachable || value.latency_ms === null || detail !== 'ok') return null;
  } else if (value.reachable || value.latency_ms !== null || detail !== status) {
    return null;
  }

  return {
    source: 'librenms',
    status,
    reachable: value.reachable,
    latency_ms: value.latency_ms,
    checked_at: value.checked_at,
    detail,
  };
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

const INTERFACE_REQUIRED_KEYS = [
  'id',
  'device_id',
  'name',
  'admin_status',
  'oper_status',
  'status',
  'source_aliases',
  'freshness',
] as const;
const INTERFACE_KEYS = [
  ...INTERFACE_REQUIRED_KEYS,
  'index',
  'description',
  'alias',
  'hardware_type',
  'mac_address',
  'speed_bps',
] as const;
const INTERFACE_LIST_KEYS = ['items', 'total', 'freshness'] as const;
const INTERFACE_ADMIN_STATUSES: readonly InterfaceAdminStatus[] = [
  'up',
  'down',
  'testing',
  'unknown',
];
const INTERFACE_OPER_STATUSES: readonly InterfaceOperStatus[] = [
  'up',
  'down',
  'testing',
  'dormant',
  'notPresent',
  'lowerLayerDown',
  'unknown',
];

export function parseInterface(value: unknown): NetworkInterface | null {
  if (
    !isRecord(value) ||
    !hasContractKeys(value, INTERFACE_REQUIRED_KEYS, INTERFACE_KEYS) ||
    typeof value.id !== 'string' ||
    !INTERFACE_ID_PATTERN.test(value.id) ||
    typeof value.device_id !== 'string' ||
    !DEVICE_ID_PATTERN.test(value.device_id) ||
    typeof value.name !== 'string' ||
    value.name.length < 1 ||
    value.name.length > 255 ||
    typeof value.admin_status !== 'string' ||
    !INTERFACE_ADMIN_STATUSES.includes(value.admin_status as InterfaceAdminStatus) ||
    typeof value.oper_status !== 'string' ||
    !INTERFACE_OPER_STATUSES.includes(value.oper_status as InterfaceOperStatus) ||
    typeof value.status !== 'string' ||
    !DEVICE_STATUSES.includes(value.status as DeviceStatus)
  ) {
    return null;
  }

  if (
    ('index' in value &&
      value.index !== null &&
      (typeof value.index !== 'number' ||
        !Number.isInteger(value.index) ||
        value.index < 0)) ||
    ('speed_bps' in value &&
      value.speed_bps !== null &&
      (typeof value.speed_bps !== 'number' ||
        !Number.isFinite(value.speed_bps) ||
        value.speed_bps < 0))
  ) {
    return null;
  }

  for (const key of ['description', 'alias', 'hardware_type', 'mac_address'] as const) {
    if (key in value && value[key] !== null && typeof value[key] !== 'string') return null;
  }
  if (
    'description' in value &&
    typeof value.description === 'string' &&
    value.description.length > 255
  ) {
    return null;
  }

  const index =
    value.index === undefined || value.index === null ? null : (value.index as number);
  const speedBps =
    value.speed_bps === undefined || value.speed_bps === null
      ? null
      : (value.speed_bps as number);
  const sourceAliases = parseSourceAliases(value.source_aliases);
  const freshness = parseFreshness(value.freshness);
  if (sourceAliases === null || freshness === null) return null;

  return {
    id: value.id,
    device_id: value.device_id,
    index,
    name: value.name,
    description: value.description === undefined ? null : (value.description as string | null),
    alias: value.alias === undefined ? null : (value.alias as string | null),
    hardware_type:
      value.hardware_type === undefined ? null : (value.hardware_type as string | null),
    mac_address: value.mac_address === undefined ? null : (value.mac_address as string | null),
    admin_status: value.admin_status as InterfaceAdminStatus,
    oper_status: value.oper_status as InterfaceOperStatus,
    status: value.status as DeviceStatus,
    speed_bps: speedBps,
    source_aliases: sourceAliases,
    freshness,
  };
}

export function parseInterfaceList(value: unknown): InterfaceListResponse | null {
  if (
    !isRecord(value) ||
    !hasContractKeys(value, INTERFACE_LIST_KEYS) ||
    !Array.isArray(value.items) ||
    !isBoundedInteger(value.total, 0)
  ) {
    return null;
  }

  const items = value.items.map(parseInterface);
  const freshness = parseFreshness(value.freshness);
  if (items.some((item) => item === null) || freshness === null) return null;

  return {
    items: items as NetworkInterface[],
    total: value.total,
    freshness,
  };
}

export function parseAlert(value: unknown): Alert | null {
  if (
    !isRecord(value) ||
    !hasContractKeys(value, ALERT_REQUIRED_KEYS, ALERT_KEYS) ||
    typeof value.id !== 'string' ||
    typeof value.severity !== 'string' ||
    !ALERT_SEVERITIES.includes(value.severity as AlertSeverity) ||
    typeof value.state !== 'string' ||
    !ALERT_STATES.includes(value.state as AlertState) ||
    typeof value.title !== 'string' ||
    typeof value.observed_at !== 'string' ||
    !isRfc3339(value.observed_at) ||
    ('device_id' in value && !isNullableString(value.device_id)) ||
    ('incident_id' in value && !isNullableString(value.incident_id))
  ) {
    return null;
  }

  return {
    id: value.id,
    severity: value.severity as AlertSeverity,
    state: value.state as AlertState,
    title: value.title,
    observed_at: value.observed_at,
    device_id: value.device_id === undefined ? null : (value.device_id as string | null),
    incident_id: value.incident_id === undefined ? null : (value.incident_id as string | null),
  };
}

export function parseAlertList(value: unknown): AlertListResponse | null {
  if (
    !isRecord(value) ||
    !hasContractKeys(value, ALERT_LIST_KEYS) ||
    !Array.isArray(value.items) ||
    !isBoundedInteger(value.page, 1) ||
    !isBoundedInteger(value.page_size, 1, 100) ||
    !isBoundedInteger(value.total, 0)
  ) {
    return null;
  }

  const items = value.items.map(parseAlert);
  const freshness = parseFreshness(value.freshness);
  if (items.some((item) => item === null) || freshness === null) return null;

  return {
    items: items as Alert[],
    page: value.page,
    page_size: value.page_size,
    total: value.total,
    freshness,
  };
}

export function parseAuthProviders(value: unknown): AuthProvidersResponse | null {
  const PROVIDER_KEYS = ['microsoft', 'google'];
  if (
    !isRecord(value) ||
    !hasContractKeys(value, AUTH_PROVIDERS_KEYS) ||
    !isRecord(value.providers) ||
    !hasContractKeys(value.providers, PROVIDER_KEYS) ||
    !isRecord(value.providers.microsoft) ||
    !isRecord(value.providers.google) ||
    !hasContractKeys(value.providers.microsoft, PROVIDER_STATE_KEYS) ||
    !hasContractKeys(value.providers.google, PROVIDER_STATE_KEYS) ||
    typeof value.providers.microsoft.configured !== 'boolean' ||
    typeof value.providers.google.configured !== 'boolean'
  ) {
    return null;
  }

  return {
    providers: {
      microsoft: { configured: value.providers.microsoft.configured },
      google: { configured: value.providers.google.configured },
    },
  };
}

export function parseSessionInfo(value: unknown): SessionInfo | null {
  if (
    !isRecord(value) ||
    !hasContractKeys(value, SESSION_INFO_KEYS) ||
    value.authenticated !== true ||
    typeof value.identity_id !== 'string' ||
    !isBoundedString(value.identity_id, 1, 128) ||
    typeof value.provider !== 'string' ||
    !isBoundedString(value.provider, 1, 32) ||
    !isNullableString(value.email) ||
    !Array.isArray(value.roles) ||
    value.roles.some((role) => typeof role !== 'string')
  ) {
    return null;
  }

  return {
    authenticated: true,
    identity_id: value.identity_id,
    provider: value.provider,
    email: value.email,
    roles: [...value.roles],
  };
}

const DEVICE_STATUS_COUNT_KEYS = ['status', 'count'] as const;
const DEVICE_HEALTH_SUMMARY_KEYS = ['total', 'by_status', 'freshness'] as const;
const SOURCE_STATE_KEYS = ['configured', 'status'] as const;
const OVERVIEW_RESPONSE_KEYS = ['devices', 'sources'] as const;
const OVERVIEW_SOURCE_STATUSES = [
  'success',
  'unavailable',
  'forbidden',
  'invalid-source-data',
  'not-configured',
] as const;

function parseDeviceStatusCount(value: unknown): DeviceStatusCount | null {
  if (
    !isRecord(value) ||
    !hasContractKeys(value, DEVICE_STATUS_COUNT_KEYS) ||
    typeof value.status !== 'string' ||
    !DEVICE_STATUSES.includes(value.status as DeviceStatus) ||
    !isBoundedInteger(value.count, 0)
  ) {
    return null;
  }
  return { status: value.status as DeviceStatus, count: value.count };
}

export function parseOverviewResponse(value: unknown): OverviewResponse | null {
  if (
    !isRecord(value) ||
    !hasContractKeys(value, OVERVIEW_RESPONSE_KEYS) ||
    !isRecord(value.devices) ||
    !hasContractKeys(value.devices, DEVICE_HEALTH_SUMMARY_KEYS) ||
    !isBoundedInteger(value.devices.total, 0) ||
    !Array.isArray(value.devices.by_status) ||
    value.devices.by_status.length > 8 ||
    value.devices.by_status.some((item) => parseDeviceStatusCount(item) === null) ||
    parseFreshness(value.devices.freshness) === null ||
    !isRecord(value.sources) ||
    !hasContractKeys(value.sources, ['librenms']) ||
    !isRecord(value.sources.librenms) ||
    !hasContractKeys(value.sources.librenms, SOURCE_STATE_KEYS) ||
    typeof value.sources.librenms.configured !== 'boolean' ||
    typeof value.sources.librenms.status !== 'string' ||
    !OVERVIEW_SOURCE_STATUSES.includes(
      value.sources.librenms.status as (typeof OVERVIEW_SOURCE_STATUSES)[number],
    )
  ) {
    return null;
  }

  return {
    devices: {
      total: value.devices.total,
      by_status: value.devices.by_status.map(
        (item) => parseDeviceStatusCount(item) as DeviceStatusCount,
      ),
      freshness: parseFreshness(value.devices.freshness) as Freshness,
    },
    sources: {
      librenms: {
        configured: value.sources.librenms.configured,
        status: value.sources.librenms.status as SourceState['status'],
      },
    },
  };
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
