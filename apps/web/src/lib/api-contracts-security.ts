import {
  ALERT_SEVERITIES,
  hasContractKeys,
  isBoundedString,
  isNullableString,
  isRecord,
  isRfc3339,
  parseFreshness,
  parseTrafficTimeRange,
  type AlertSeverity,
  type Freshness,
  type TrafficTimeRange,
} from './api-contracts.ts';

export const SECURITY_STATES = ['not-connected', 'ok', 'unknown'] as const;
export type SecurityState = (typeof SECURITY_STATES)[number];

export const SECURITY_SOURCES = ['wazuh', 'suricata'] as const;
export type SecuritySource = (typeof SECURITY_SOURCES)[number];

/** Every text field is source-reported, untrusted telemetry: render as data only. */
export interface SecurityEvent {
  id: string;
  observed_at: string;
  source: SecuritySource;
  severity: AlertSeverity;
  category: string | null;
  signature: string;
  source_ip: string | null;
  destination_ip: string | null;
  device_id: string | null;
}

export interface SecurityEventsResponse {
  state: SecurityState;
  time_range: TrafficTimeRange;
  events: SecurityEvent[];
  freshness: Freshness;
}

const DEVICE_ID_PATTERN =
  /^device-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_EVENTS = 500;

const SECURITY_EVENT_KEYS = [
  'id',
  'observed_at',
  'source',
  'severity',
  'category',
  'signature',
  'source_ip',
  'destination_ip',
  'device_id',
] as const;
const SECURITY_RESPONSE_KEYS = ['state', 'time_range', 'events', 'freshness'] as const;

function isNullableBoundedString(value: unknown, maximum: number): value is string | null {
  return isNullableString(value) && (value === null || isBoundedString(value, 1, maximum));
}

function parseSecurityEvent(value: unknown): SecurityEvent | null {
  if (!isRecord(value) || !hasContractKeys(value, SECURITY_EVENT_KEYS)) return null;
  if (
    !isBoundedString(value.id, 1, 128) ||
    typeof value.observed_at !== 'string' ||
    !isRfc3339(value.observed_at) ||
    typeof value.source !== 'string' ||
    !SECURITY_SOURCES.includes(value.source as SecuritySource) ||
    typeof value.severity !== 'string' ||
    !ALERT_SEVERITIES.includes(value.severity as AlertSeverity) ||
    !isNullableBoundedString(value.category, 128) ||
    !isBoundedString(value.signature, 1, 512) ||
    !isNullableBoundedString(value.source_ip, 45) ||
    !isNullableBoundedString(value.destination_ip, 45)
  ) {
    return null;
  }
  if (
    value.device_id !== null &&
    (typeof value.device_id !== 'string' || !DEVICE_ID_PATTERN.test(value.device_id))
  ) {
    return null;
  }
  return {
    id: value.id,
    observed_at: value.observed_at,
    source: value.source as SecuritySource,
    severity: value.severity as AlertSeverity,
    category: value.category,
    signature: value.signature,
    source_ip: value.source_ip,
    destination_ip: value.destination_ip,
    device_id: value.device_id,
  };
}

export function parseSecurityEventsResponse(value: unknown): SecurityEventsResponse | null {
  if (
    !isRecord(value) ||
    !hasContractKeys(value, SECURITY_RESPONSE_KEYS) ||
    typeof value.state !== 'string' ||
    !SECURITY_STATES.includes(value.state as SecurityState) ||
    !Array.isArray(value.events) ||
    value.events.length > MAX_EVENTS
  ) {
    return null;
  }

  const timeRange = parseTrafficTimeRange(value.time_range);
  const freshness = parseFreshness(value.freshness);
  if (timeRange === null || freshness === null) return null;

  const events = value.events.map(parseSecurityEvent);
  if (events.some((event) => event === null)) return null;
  // Fail closed: a non-ok state must never carry source-derived rows.
  if (value.state !== 'ok' && events.length > 0) return null;

  return {
    state: value.state as SecurityState,
    time_range: timeRange,
    events: events as SecurityEvent[],
    freshness,
  };
}
