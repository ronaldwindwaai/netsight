import {
  hasContractKeys,
  isRecord,
  isRfc3339,
  parseFreshness,
  type Freshness,
  type InterfaceOperStatus,
} from './api-contracts.ts';
import { PROBE_LOCATIONS, type ProbeLocation } from './api-contracts-diagnostic.ts';
import { isIntegerInRange, isOneOf, isText, parseArray } from './contract-guards.ts';

/**
 * Internet/WAN contract, mirroring contracts/json-schema/internet.schema.json and
 * internet-sla.schema.json (shared vectors: contracts/test-vectors/internet.vectors.json).
 *
 * Every parser is fail-closed: anything that does not satisfy the exact contract returns null and
 * the caller must render an explicit error state, never a guess. A block whose state is not `ok`
 * carries no values; a null measured value means "not reported", never zero. Operator-declared and
 * source-reported text is untrusted data and is never interpreted.
 */

export const BLOCK_STATES = ['not-connected', 'unknown', 'ok'] as const;
export const LINK_ROLES = ['primary', 'backup'] as const;
export const LINK_STATUSES = ['up', 'degraded', 'down', 'unknown'] as const;
export const PROBE_OUTCOMES = ['pass', 'fail', 'unknown'] as const;
export const FAILOVER_STATES = ['single-link', 'normal', 'failed-over', 'all-down', 'unknown'] as const;
export const FAILOVER_BASES = ['inferred', 'unknown'] as const;
export const WINDOW_KINDS = ['down', 'degraded', 'unknown'] as const;
export const EXPORT_PROBES = ['icmp', 'tcp', 'dns'] as const;
const OPER_STATUSES = [
  'up',
  'down',
  'testing',
  'dormant',
  'notPresent',
  'lowerLayerDown',
  'unknown',
] as const;

export type BlockState = (typeof BLOCK_STATES)[number];
export type LinkRole = (typeof LINK_ROLES)[number];
export type LinkStatus = (typeof LINK_STATUSES)[number];
export type ProbeOutcome = (typeof PROBE_OUTCOMES)[number];
export type FailoverState = (typeof FAILOVER_STATES)[number];
export type FailoverBasis = (typeof FAILOVER_BASES)[number];
export type WindowKind = (typeof WINDOW_KINDS)[number];

export const MAX_LINKS = 8;
export const MAX_EXPORT_WINDOWS = 2000;
export const MAX_EXPORT_SOURCES = 64;

export interface WanConfigured {
  isp: string | null;
  gateway: string | null;
  probe_location: ProbeLocation | null;
}

export interface WanInterfaceReading {
  state: BlockState;
  oper_status: InterfaceOperStatus | null;
  capacity_bps: number | null;
  rx_bps: number | null;
  tx_bps: number | null;
  utilisation_pct: number | null;
  public_ip: string | null;
  freshness: Freshness;
}

export interface WanQuality {
  state: BlockState;
  latency_ms: number | null;
  jitter_ms: number | null;
  loss_pct: number | null;
  dns_status: ProbeOutcome | null;
  dns_latency_ms: number | null;
  sample_count: number;
  window_seconds: number;
  freshness: Freshness;
}

export interface WanAvailability {
  state: BlockState;
  period_start: string | null;
  period_end: string | null;
  uptime_pct: number | null;
  coverage_pct: number | null;
  current_outage_started_at: string | null;
  current_outage_seconds: number | null;
  freshness: Freshness;
}

export interface WanLink {
  id: string;
  name: string;
  role: LinkRole;
  configured: WanConfigured;
  status: LinkStatus;
  interface: WanInterfaceReading;
  quality: WanQuality;
  availability: WanAvailability;
}

export interface WanFailover {
  state: FailoverState;
  basis: FailoverBasis;
}

export interface InternetResponse {
  state: BlockState;
  generated_at: string;
  links: WanLink[];
  failover: WanFailover;
  /**
   * True when the caller lacks internet:read_detail: the ISP name, gateway, public IP and per-link
   * throughput are withheld (null), so a null there means "restricted", not "not reported".
   */
  detail_redacted: boolean;
}

export interface SlaViolation {
  kind: 'uptime-below-target';
  target_pct: number;
  actual_pct: number;
}

export interface SlaLink {
  link_id: string;
  name: string;
  state: BlockState;
  uptime_target_pct: number | null;
  total_seconds: number | null;
  up_seconds: number | null;
  degraded_seconds: number | null;
  down_seconds: number | null;
  unknown_seconds: number | null;
  uptime_pct: number | null;
  coverage_pct: number | null;
  outage_count: number | null;
  longest_outage_seconds: number | null;
  cycle_count: number | null;
  /** True when the evidence export lists fewer windows than the month holds (figures stay complete). */
  windows_truncated: boolean | null;
  violations: SlaViolation[];
}

export interface SlaResponse {
  state: BlockState;
  month: string;
  period_start: string | null;
  period_end: string | null;
  generated_at: string;
  links: SlaLink[];
}

export interface SlaExportWindow {
  kind: WindowKind;
  started_at: string;
  ended_at: string;
  duration_seconds: number;
  sample_count: number;
}

export interface SlaExportSource {
  probe: (typeof EXPORT_PROBES)[number];
  target: string;
  location: ProbeLocation | null;
}

export interface SlaExportLink {
  link: SlaLink;
  isp: string | null;
  sources: SlaExportSource[];
  windows: SlaExportWindow[];
  windows_truncated: boolean;
}

export interface SlaExport {
  state: BlockState;
  month: string;
  period_start: string | null;
  period_end: string | null;
  generated_at: string;
  basis: string;
  /** True when the caller lacks internet:read_detail: the ISP name is withheld (null). */
  detail_redacted: boolean;
  links: SlaExportLink[];
}

const LINK_ID = /^[a-z0-9][a-z0-9-]{0,47}$/;
const MONTH = /^[0-9]{4}-(0[1-9]|1[0-2])$/;
const MAX_INT = Number.MAX_SAFE_INTEGER;
const MAX_MILLIS = 3_600_000;
const MAX_SECONDS = 10_000_000;

const CONFIGURED_KEYS = ['isp', 'gateway', 'probe_location'] as const;
const INTERFACE_KEYS = [
  'state',
  'oper_status',
  'capacity_bps',
  'rx_bps',
  'tx_bps',
  'utilisation_pct',
  'public_ip',
  'freshness',
] as const;
const QUALITY_KEYS = [
  'state',
  'latency_ms',
  'jitter_ms',
  'loss_pct',
  'dns_status',
  'dns_latency_ms',
  'sample_count',
  'window_seconds',
  'freshness',
] as const;
const AVAILABILITY_KEYS = [
  'state',
  'period_start',
  'period_end',
  'uptime_pct',
  'coverage_pct',
  'current_outage_started_at',
  'current_outage_seconds',
  'freshness',
] as const;
const LINK_KEYS = [
  'id',
  'name',
  'role',
  'configured',
  'status',
  'interface',
  'quality',
  'availability',
] as const;
const FAILOVER_KEYS = ['state', 'basis'] as const;
const RESPONSE_KEYS = ['state', 'generated_at', 'links', 'failover', 'detail_redacted'] as const;
const VIOLATION_KEYS = ['kind', 'target_pct', 'actual_pct'] as const;
const SLA_LINK_KEYS = [
  'link_id',
  'name',
  'state',
  'uptime_target_pct',
  'total_seconds',
  'up_seconds',
  'degraded_seconds',
  'down_seconds',
  'unknown_seconds',
  'uptime_pct',
  'coverage_pct',
  'outage_count',
  'longest_outage_seconds',
  'cycle_count',
  'windows_truncated',
  'violations',
] as const;
const SLA_RESPONSE_KEYS = [
  'state',
  'month',
  'period_start',
  'period_end',
  'generated_at',
  'links',
] as const;
const WINDOW_KEYS = ['kind', 'started_at', 'ended_at', 'duration_seconds', 'sample_count'] as const;
const SOURCE_KEYS = ['probe', 'target', 'location'] as const;
const EXPORT_LINK_KEYS = ['link', 'isp', 'sources', 'windows', 'windows_truncated'] as const;
const EXPORT_KEYS = [
  'state',
  'month',
  'period_start',
  'period_end',
  'generated_at',
  'basis',
  'detail_redacted',
  'links',
] as const;

type Raw = Record<string, unknown>;

function exactRecord(value: unknown, keys: readonly string[]): Raw | null {
  return isRecord(value) && hasContractKeys(value, keys) ? (value as Raw) : null;
}

function isNumberIn(value: unknown, minimum: number, maximum: number): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= minimum && value <= maximum;
}

function isNullableNumberIn(value: unknown, minimum: number, maximum: number): value is number | null {
  return value === null || isNumberIn(value, minimum, maximum);
}

function isNullableInt(value: unknown, maximum: number): value is number | null {
  return value === null || isIntegerInRange(value, 0, maximum);
}

function isNullableText(value: unknown, maximum: number): value is string | null {
  return value === null || isText(value, 1, maximum);
}

function isTimestamp(value: unknown): value is string {
  return typeof value === 'string' && isRfc3339(value);
}

function isNullableTimestamp(value: unknown): value is string | null {
  return value === null || isTimestamp(value);
}

function isNullableLocation(value: unknown): value is ProbeLocation | null {
  return value === null || isOneOf(value, PROBE_LOCATIONS);
}

function allNull(record: Raw, keys: readonly string[]): boolean {
  return keys.every((key) => record[key] === null);
}

// --- interface / quality / availability ------------------------------------------------------------

export function parseWanConfigured(value: unknown): WanConfigured | null {
  const record = exactRecord(value, CONFIGURED_KEYS);
  if (
    record === null ||
    !isNullableText(record.isp, 128) ||
    !isNullableText(record.gateway, 45) ||
    !isNullableLocation(record.probe_location)
  ) {
    return null;
  }
  return { isp: record.isp, gateway: record.gateway, probe_location: record.probe_location };
}

export function parseWanInterfaceReading(value: unknown): WanInterfaceReading | null {
  const record = exactRecord(value, INTERFACE_KEYS);
  if (record === null || !isOneOf(record.state, BLOCK_STATES)) return null;
  const freshness = parseFreshness(record.freshness);
  if (
    freshness === null ||
    !(record.oper_status === null || isOneOf(record.oper_status, OPER_STATUSES)) ||
    !isNullableInt(record.capacity_bps, MAX_INT) ||
    !isNullableInt(record.rx_bps, MAX_INT) ||
    !isNullableInt(record.tx_bps, MAX_INT) ||
    !isNullableNumberIn(record.utilisation_pct, 0, 1000) ||
    !isNullableText(record.public_ip, 45)
  ) {
    return null;
  }
  const values = ['oper_status', 'capacity_bps', 'rx_bps', 'tx_bps', 'utilisation_pct', 'public_ip'];
  // Fail closed: a non-ok reading must never assert a value.
  if (record.state !== 'ok' && !allNull(record, values)) return null;
  return {
    state: record.state,
    oper_status: record.oper_status as InterfaceOperStatus | null,
    capacity_bps: record.capacity_bps,
    rx_bps: record.rx_bps,
    tx_bps: record.tx_bps,
    utilisation_pct: record.utilisation_pct,
    public_ip: record.public_ip,
    freshness,
  };
}

export function parseWanQuality(value: unknown): WanQuality | null {
  const record = exactRecord(value, QUALITY_KEYS);
  if (record === null || !isOneOf(record.state, BLOCK_STATES)) return null;
  const freshness = parseFreshness(record.freshness);
  if (
    freshness === null ||
    !isNullableNumberIn(record.latency_ms, 0, MAX_MILLIS) ||
    !isNullableNumberIn(record.jitter_ms, 0, MAX_MILLIS) ||
    !isNullableNumberIn(record.loss_pct, 0, 100) ||
    !(record.dns_status === null || isOneOf(record.dns_status, PROBE_OUTCOMES)) ||
    !isNullableNumberIn(record.dns_latency_ms, 0, MAX_MILLIS) ||
    !isIntegerInRange(record.sample_count, 0, 100_000) ||
    !isIntegerInRange(record.window_seconds, 0, MAX_SECONDS)
  ) {
    return null;
  }
  const values = ['latency_ms', 'jitter_ms', 'loss_pct', 'dns_status', 'dns_latency_ms'];
  if (record.state !== 'ok' && (!allNull(record, values) || record.sample_count !== 0)) return null;
  return {
    state: record.state,
    latency_ms: record.latency_ms,
    jitter_ms: record.jitter_ms,
    loss_pct: record.loss_pct,
    dns_status: record.dns_status as ProbeOutcome | null,
    dns_latency_ms: record.dns_latency_ms,
    sample_count: record.sample_count,
    window_seconds: record.window_seconds,
    freshness,
  };
}

export function parseWanAvailability(value: unknown): WanAvailability | null {
  const record = exactRecord(value, AVAILABILITY_KEYS);
  if (record === null || !isOneOf(record.state, BLOCK_STATES)) return null;
  const freshness = parseFreshness(record.freshness);
  if (
    freshness === null ||
    !isNullableTimestamp(record.period_start) ||
    !isNullableTimestamp(record.period_end) ||
    !isNullableNumberIn(record.uptime_pct, 0, 100) ||
    !isNullableNumberIn(record.coverage_pct, 0, 100) ||
    !isNullableTimestamp(record.current_outage_started_at) ||
    !isNullableInt(record.current_outage_seconds, MAX_SECONDS)
  ) {
    return null;
  }
  const values = [
    'period_start',
    'period_end',
    'uptime_pct',
    'coverage_pct',
    'current_outage_started_at',
    'current_outage_seconds',
  ];
  if (record.state !== 'ok' && !allNull(record, values)) return null;
  // An outage has a start and a duration, or neither.
  if ((record.current_outage_started_at === null) !== (record.current_outage_seconds === null)) {
    return null;
  }
  return {
    state: record.state,
    period_start: record.period_start,
    period_end: record.period_end,
    uptime_pct: record.uptime_pct,
    coverage_pct: record.coverage_pct,
    current_outage_started_at: record.current_outage_started_at,
    current_outage_seconds: record.current_outage_seconds,
    freshness,
  };
}

// --- link / failover / response ----------------------------------------------------------------------

export function parseWanLink(value: unknown): WanLink | null {
  const record = exactRecord(value, LINK_KEYS);
  if (
    record === null ||
    typeof record.id !== 'string' ||
    !LINK_ID.test(record.id) ||
    !isText(record.name, 1, 128) ||
    !isOneOf(record.role, LINK_ROLES) ||
    !isOneOf(record.status, LINK_STATUSES)
  ) {
    return null;
  }
  const configured = parseWanConfigured(record.configured);
  const wanInterface = parseWanInterfaceReading(record.interface);
  const quality = parseWanQuality(record.quality);
  const availability = parseWanAvailability(record.availability);
  if (configured === null || wanInterface === null || quality === null || availability === null) {
    return null;
  }
  return {
    id: record.id,
    name: record.name,
    role: record.role,
    configured,
    status: record.status,
    interface: wanInterface,
    quality,
    availability,
  };
}

export function parseWanFailover(value: unknown): WanFailover | null {
  const record = exactRecord(value, FAILOVER_KEYS);
  if (
    record === null ||
    !isOneOf(record.state, FAILOVER_STATES) ||
    !isOneOf(record.basis, FAILOVER_BASES)
  ) {
    return null;
  }
  // Unknown exactly when the basis is unknown.
  if ((record.state === 'unknown') !== (record.basis === 'unknown')) return null;
  return { state: record.state, basis: record.basis };
}

function withholdsDetail(link: WanLink): boolean {
  return [
    link.configured.isp,
    link.configured.gateway,
    link.interface.public_ip,
    link.interface.rx_bps,
    link.interface.tx_bps,
    link.interface.utilisation_pct,
  ].every((value) => value === null);
}

export function parseInternetResponse(value: unknown): InternetResponse | null {
  const record = exactRecord(value, RESPONSE_KEYS);
  if (
    record === null ||
    !isOneOf(record.state, BLOCK_STATES) ||
    !isTimestamp(record.generated_at)
  ) {
    return null;
  }
  const failover = parseWanFailover(record.failover);
  const links = parseArray(record.links, 0, MAX_LINKS, parseWanLink);
  if (failover === null || links === null) return null;
  if (typeof record.detail_redacted !== 'boolean') return null;
  // Fail closed: a non-ok response must never carry links or assert a failover state.
  if (record.state !== 'ok' && (links.length > 0 || failover.state !== 'unknown')) return null;
  // A redacted response must carry none of the restricted detail (it would be a leak, not a view).
  if (record.detail_redacted && !links.every(withholdsDetail)) return null;
  return {
    state: record.state,
    generated_at: record.generated_at,
    links,
    failover,
    detail_redacted: record.detail_redacted,
  };
}

// --- SLA -------------------------------------------------------------------------------------------------

function parseViolation(value: unknown): SlaViolation | null {
  const record = exactRecord(value, VIOLATION_KEYS);
  if (
    record === null ||
    record.kind !== 'uptime-below-target' ||
    !isNumberIn(record.target_pct, 0, 100) ||
    !isNumberIn(record.actual_pct, 0, 100)
  ) {
    return null;
  }
  return { kind: record.kind, target_pct: record.target_pct, actual_pct: record.actual_pct };
}

const SECOND_FIGURES = [
  'total_seconds',
  'up_seconds',
  'degraded_seconds',
  'down_seconds',
  'unknown_seconds',
  'longest_outage_seconds',
] as const;
const COUNT_FIGURES = ['outage_count', 'cycle_count'] as const;

export function parseSlaLink(value: unknown): SlaLink | null {
  const record = exactRecord(value, SLA_LINK_KEYS);
  if (
    record === null ||
    typeof record.link_id !== 'string' ||
    !LINK_ID.test(record.link_id) ||
    !isText(record.name, 1, 128) ||
    !isOneOf(record.state, BLOCK_STATES) ||
    !(
      record.uptime_target_pct === null ||
      (isNumberIn(record.uptime_target_pct, 0, 100) && record.uptime_target_pct > 0)
    ) ||
    !isNullableNumberIn(record.uptime_pct, 0, 100) ||
    !isNullableNumberIn(record.coverage_pct, 0, 100) ||
    SECOND_FIGURES.some((key) => !isNullableInt(record[key], MAX_SECONDS)) ||
    COUNT_FIGURES.some((key) => !isNullableInt(record[key], 1_000_000))
  ) {
    return null;
  }
  const violations = parseArray(record.violations, 0, 8, parseViolation);
  if (violations === null) return null;
  const figures = [...SECOND_FIGURES, ...COUNT_FIGURES, 'uptime_pct', 'coverage_pct'];
  if (record.windows_truncated !== null && typeof record.windows_truncated !== 'boolean') {
    return null;
  }
  if (record.state !== 'ok') {
    if (!allNull(record, [...figures, 'windows_truncated']) || violations.length > 0) return null;
  } else {
    if (record.windows_truncated === null) return null;
    // Every figure is present for an ok month; only the uptime may be null (nothing was known).
    if (figures.some((key) => key !== 'uptime_pct' && record[key] === null)) return null;
    const parts =
      (record.up_seconds as number) +
      (record.degraded_seconds as number) +
      (record.down_seconds as number) +
      (record.unknown_seconds as number);
    if (parts !== record.total_seconds) return null;
  }
  return {
    link_id: record.link_id,
    name: record.name,
    state: record.state,
    uptime_target_pct: record.uptime_target_pct,
    total_seconds: record.total_seconds as number | null,
    up_seconds: record.up_seconds as number | null,
    degraded_seconds: record.degraded_seconds as number | null,
    down_seconds: record.down_seconds as number | null,
    unknown_seconds: record.unknown_seconds as number | null,
    uptime_pct: record.uptime_pct,
    coverage_pct: record.coverage_pct,
    outage_count: record.outage_count as number | null,
    longest_outage_seconds: record.longest_outage_seconds as number | null,
    cycle_count: record.cycle_count as number | null,
    windows_truncated: record.windows_truncated,
    violations,
  };
}

interface Envelope {
  state: BlockState;
  month: string;
  period_start: string | null;
  period_end: string | null;
  generated_at: string;
}

function parseEnvelope(record: Raw, hasLinks: boolean): Envelope | null {
  if (
    !isOneOf(record.state, BLOCK_STATES) ||
    typeof record.month !== 'string' ||
    !MONTH.test(record.month) ||
    !isNullableTimestamp(record.period_start) ||
    !isNullableTimestamp(record.period_end) ||
    !isTimestamp(record.generated_at)
  ) {
    return null;
  }
  if (record.state !== 'ok') {
    if (hasLinks || record.period_start !== null || record.period_end !== null) return null;
  } else if (record.period_start === null || record.period_end === null) {
    return null;
  }
  return {
    state: record.state,
    month: record.month,
    period_start: record.period_start,
    period_end: record.period_end,
    generated_at: record.generated_at,
  };
}

export function parseSlaResponse(value: unknown): SlaResponse | null {
  const record = exactRecord(value, SLA_RESPONSE_KEYS);
  if (record === null) return null;
  const links = parseArray(record.links, 0, MAX_LINKS, parseSlaLink);
  if (links === null) return null;
  const envelope = parseEnvelope(record, links.length > 0);
  return envelope === null ? null : { ...envelope, links };
}

// --- export ------------------------------------------------------------------------------------------------

export function parseSlaExportWindow(value: unknown): SlaExportWindow | null {
  const record = exactRecord(value, WINDOW_KEYS);
  if (
    record === null ||
    !isOneOf(record.kind, WINDOW_KINDS) ||
    !isTimestamp(record.started_at) ||
    !isTimestamp(record.ended_at) ||
    !isIntegerInRange(record.duration_seconds, 0, MAX_SECONDS) ||
    !isIntegerInRange(record.sample_count, 0, 1_000_000)
  ) {
    return null;
  }
  // A window ends after it starts.
  if (Date.parse(record.ended_at) <= Date.parse(record.started_at)) return null;
  return {
    kind: record.kind,
    started_at: record.started_at,
    ended_at: record.ended_at,
    duration_seconds: record.duration_seconds,
    sample_count: record.sample_count,
  };
}

export function parseSlaExportSource(value: unknown): SlaExportSource | null {
  const record = exactRecord(value, SOURCE_KEYS);
  if (
    record === null ||
    !isOneOf(record.probe, EXPORT_PROBES) ||
    !isText(record.target, 1, 253) ||
    !isNullableLocation(record.location)
  ) {
    return null;
  }
  return { probe: record.probe, target: record.target, location: record.location };
}

export function parseSlaExportLink(value: unknown): SlaExportLink | null {
  const record = exactRecord(value, EXPORT_LINK_KEYS);
  if (
    record === null ||
    !isNullableText(record.isp, 128) ||
    typeof record.windows_truncated !== 'boolean'
  ) {
    return null;
  }
  const link = parseSlaLink(record.link);
  const sources = parseArray(record.sources, 0, MAX_EXPORT_SOURCES, parseSlaExportSource);
  const windows = parseArray(record.windows, 0, MAX_EXPORT_WINDOWS, parseSlaExportWindow);
  if (link === null || sources === null || windows === null) return null;
  // Fail closed: a link the store could not read carries no evidence.
  if (link.state !== 'ok' && (sources.length > 0 || windows.length > 0 || record.windows_truncated)) {
    return null;
  }
  return { link, isp: record.isp, sources, windows, windows_truncated: record.windows_truncated };
}

export function parseSlaExport(value: unknown): SlaExport | null {
  const record = exactRecord(value, EXPORT_KEYS);
  if (record === null || !isText(record.basis, 1, 1000)) return null;
  const links = parseArray(record.links, 0, MAX_LINKS, parseSlaExportLink);
  if (links === null) return null;
  if (typeof record.detail_redacted !== 'boolean') return null;
  if (record.detail_redacted && links.some((item) => item.isp !== null)) return null;
  const envelope = parseEnvelope(record, links.length > 0);
  return envelope === null
    ? null
    : { ...envelope, basis: record.basis, detail_redacted: record.detail_redacted, links };
}
