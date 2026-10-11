import {
  asn,
  count,
  country,
  exact,
  finite,
  instant,
  isTrafficState,
  nullableCount,
  nullableInstant,
  nullableText,
  share,
} from './api-contracts-traffic-guards.ts';
import {
  cohortMatchesState,
  parseCohort,
  type CohortStatus,
} from './api-contracts-traffic-cohort.ts';
import {
  parseFreshness,
  parseTrafficTimeRange,
  type Freshness,
  type TrafficState,
  type TrafficTimeRange,
} from './api-contracts.ts';
import { isIntegerInRange, isOneOf, isText, parseArray } from './contract-guards.ts';
import {
  ATTRIBUTION_LEVELS,
  ATTRIBUTION_STATES,
  DESTINATION_SCOPES,
  FILTER_NAMES,
  FLOW_DIRECTIONS,
  FLOW_PROTOCOLS,
  IDENTITY_BASES,
  INFERRED_REASONS,
  UNKNOWN_REASONS,
  type AttributionLevel,
  type AttributionState,
  type DestinationScope,
  type FilterName,
  type FlowDirection,
  type FlowProtocol,
  type IdentityBasis,
} from './api-contracts-traffic-shared.ts';

/** Flow Explorer contract (traffic-flows.schema.json): filters, attribution, rows, aggregations. */

const INFERRED_CEILING = 0.7;
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const PERSON_ID = new RegExp(`^person-${UUID}$`);
const DEVICE_ID = new RegExp(`^device-${UUID}$`);

// --- Flow Explorer -----------------------------------------------------------------------------------

export interface FlowFilters {
  source_ip: string | null;
  destination_ip: string | null;
  device: string | null;
  vlan: number | null;
  application: string | null;
  protocol: FlowProtocol | null;
  port: number | null;
  country: string | null;
  asn: number | null;
  direction: 'inbound' | 'outbound' | 'internal' | null;
}

export function parseFlowFilters(value: unknown): FlowFilters | null {
  if (!exact(value, FILTER_NAMES)) return null;
  const v = value;
  if (
    !nullableText(v.source_ip, 45) ||
    (v.source_ip !== null && !isText(v.source_ip, 2, 45)) ||
    !nullableText(v.destination_ip, 45) ||
    (v.destination_ip !== null && !isText(v.destination_ip, 2, 45)) ||
    !nullableText(v.device, 128) ||
    !(v.vlan === null || isIntegerInRange(v.vlan, 0, 4094)) ||
    !nullableText(v.application, 128) ||
    !(v.protocol === null || isOneOf(v.protocol, FLOW_PROTOCOLS)) ||
    !(v.port === null || isIntegerInRange(v.port, 0, 65535)) ||
    !country(v.country) ||
    !asn(v.asn) ||
    !(v.direction === null || isOneOf(v.direction, ['inbound', 'outbound', 'internal'] as const))
  ) {
    return null;
  }
  return {
    source_ip: v.source_ip,
    destination_ip: v.destination_ip,
    device: v.device,
    vlan: v.vlan,
    application: v.application,
    protocol: v.protocol,
    port: v.port,
    country: v.country,
    asn: v.asn,
    direction: v.direction,
  } as FlowFilters;
}

export interface EntityLabel {
  id: string;
  /** Untrusted source text: render as data only. */
  label: string | null;
}

function parseEntity(value: unknown, pattern: RegExp): EntityLabel | null {
  if (!exact(value, ['id', 'label'])) return null;
  if (!isText(value.id, 1, 128) || !pattern.test(value.id) || !nullableText(value.label, 128)) {
    return null;
  }
  return { id: value.id, label: value.label };
}

export interface FlowAttribution {
  basis: IdentityBasis;
  reason: string | null;
  confidence: number | null;
  ambiguous: boolean;
  person: EntityLabel | null;
  device: EntityLabel | null;
}

export function parseFlowAttribution(value: unknown): FlowAttribution | null {
  if (!exact(value, ['basis', 'reason', 'confidence', 'ambiguous', 'person', 'device'])) {
    return null;
  }
  if (
    !isOneOf(value.basis, IDENTITY_BASES) ||
    typeof value.ambiguous !== 'boolean' ||
    !(value.confidence === null || (finite(value.confidence) && value.confidence >= 0 && value.confidence <= 1))
  ) {
    return null;
  }
  const person = value.person === null ? null : parseEntity(value.person, PERSON_ID);
  const device = value.device === null ? null : parseEntity(value.device, DEVICE_ID);
  if ((value.person !== null && person === null) || (value.device !== null && device === null)) {
    return null;
  }
  if (value.basis === 'unknown') {
    if (
      person !== null ||
      value.confidence !== null ||
      !isOneOf(value.reason, UNKNOWN_REASONS)
    ) {
      return null;
    }
  } else {
    if (person === null || value.confidence === null || value.ambiguous) return null;
    if (value.basis === 'observed' && value.reason !== null) return null;
    if (
      value.basis === 'inferred' &&
      (!isOneOf(value.reason, INFERRED_REASONS) || value.confidence > INFERRED_CEILING)
    ) {
      return null;
    }
  }
  return {
    basis: value.basis,
    reason: value.reason as string | null,
    confidence: value.confidence,
    ambiguous: value.ambiguous,
    person,
    device,
  };
}

export interface AttributionStatus {
  level: AttributionLevel;
  state: AttributionState;
  as_of: string | null;
}

export function parseAttributionStatus(value: unknown): AttributionStatus | null {
  if (!exact(value, ['level', 'state', 'as_of'])) return null;
  if (
    !isOneOf(value.level, ATTRIBUTION_LEVELS) ||
    !isOneOf(value.state, ATTRIBUTION_STATES) ||
    !nullableInstant(value.as_of)
  ) {
    return null;
  }
  if (value.level === 'none' && value.state !== 'withheld' && value.state !== 'not-evaluated') {
    return null;
  }
  if (value.state === 'withheld' && value.level !== 'none') return null;
  if ((value.state === 'ok') !== (value.as_of !== null)) return null;
  return { level: value.level, state: value.state, as_of: value.as_of };
}

export interface TrafficFlow {
  observed_at: string;
  source_ip: string;
  source_device_id: string | null;
  destination_ip: string;
  destination_host: string | null;
  protocol: FlowProtocol;
  destination_port: number | null;
  bytes: number;
  packets: number | null;
  direction: FlowDirection;
  application: string | null;
  attribution: FlowAttribution | null;
}

const FLOW_KEYS = [
  'observed_at',
  'source_ip',
  'source_device_id',
  'destination_ip',
  'destination_host',
  'protocol',
  'destination_port',
  'bytes',
  'packets',
  'direction',
  'application',
  'attribution',
] as const;

export function parseTrafficFlow(value: unknown): TrafficFlow | null {
  if (!exact(value, FLOW_KEYS)) return null;
  const v = value;
  if (
    !instant(v.observed_at) ||
    !isText(v.source_ip, 1, 45) ||
    !isText(v.destination_ip, 1, 45) ||
    !(v.source_device_id === null || (typeof v.source_device_id === 'string' && DEVICE_ID.test(v.source_device_id))) ||
    !nullableText(v.destination_host, 255) ||
    !isOneOf(v.protocol, FLOW_PROTOCOLS) ||
    !(v.destination_port === null || isIntegerInRange(v.destination_port, 0, 65535)) ||
    !count(v.bytes) ||
    !nullableCount(v.packets) ||
    !isOneOf(v.direction, FLOW_DIRECTIONS) ||
    !nullableText(v.application, 255)
  ) {
    return null;
  }
  const attribution = v.attribution === null ? null : parseFlowAttribution(v.attribution);
  if (v.attribution !== null && attribution === null) return null;
  return {
    observed_at: v.observed_at,
    source_ip: v.source_ip,
    source_device_id: v.source_device_id,
    destination_ip: v.destination_ip,
    destination_host: v.destination_host,
    protocol: v.protocol,
    destination_port: v.destination_port,
    bytes: v.bytes,
    packets: v.packets,
    direction: v.direction,
    application: v.application,
    attribution,
  };
}

export interface TimelineBucket {
  start: string;
  bytes: number;
  packets: number | null;
  flows: number;
}

export interface Volume {
  bytes: number;
  packets: number | null;
  flows: number;
  source_addresses: number;
  destination_addresses: number;
}

export interface ApplicationMixItem {
  application: string | null;
  bytes: number;
  share: number | null;
}

export interface ApplicationMix {
  items: ApplicationMixItem[];
  other_bytes: number;
  total_bytes: number;
}

export interface DestinationShare {
  address: string;
  host: string | null;
  /** `internal`: a private or otherwise non-routable address; only the detail tier is told. */
  scope: DestinationScope;
  bytes: number;
  share: number | null;
}

export interface FlowAggregations {
  bucket_seconds: number;
  timeline: TimelineBucket[];
  volume: Volume;
  application_mix: ApplicationMix | null;
  destinations: DestinationShare[];
}

function parseBucket(value: unknown): TimelineBucket | null {
  if (!exact(value, ['start', 'bytes', 'packets', 'flows'])) return null;
  if (!instant(value.start) || !count(value.bytes) || !nullableCount(value.packets) || !count(value.flows)) {
    return null;
  }
  return { start: value.start, bytes: value.bytes, packets: value.packets, flows: value.flows };
}

function parseVolume(value: unknown): Volume | null {
  if (!exact(value, ['bytes', 'packets', 'flows', 'source_addresses', 'destination_addresses'])) return null;
  if (
    !count(value.bytes) ||
    !nullableCount(value.packets) ||
    !count(value.flows) ||
    !count(value.source_addresses) ||
    !count(value.destination_addresses)
  ) {
    return null;
  }
  return {
    bytes: value.bytes,
    packets: value.packets,
    flows: value.flows,
    source_addresses: value.source_addresses,
    destination_addresses: value.destination_addresses,
  };
}

function parseMixItem(value: unknown): ApplicationMixItem | null {
  if (!exact(value, ['application', 'bytes', 'share'])) return null;
  if (!nullableText(value.application, 255) || !count(value.bytes) || !share(value.share)) return null;
  return { application: value.application, bytes: value.bytes, share: value.share };
}

function parseMix(value: unknown): ApplicationMix | null {
  if (!exact(value, ['items', 'other_bytes', 'total_bytes'])) return null;
  const items = parseArray(value.items, 0, 11, parseMixItem);
  if (items === null || !count(value.other_bytes) || !count(value.total_bytes)) return null;
  if (items.reduce((sum, item) => sum + item.bytes, 0) + value.other_bytes !== value.total_bytes) {
    return null;
  }
  return { items, other_bytes: value.other_bytes, total_bytes: value.total_bytes };
}

function parseDestinationShare(value: unknown): DestinationShare | null {
  if (!exact(value, ['address', 'host', 'scope', 'bytes', 'share'])) return null;
  if (
    !isText(value.address, 1, 45) ||
    !nullableText(value.host, 255) ||
    !isOneOf(value.scope, DESTINATION_SCOPES) ||
    !count(value.bytes) ||
    !share(value.share)
  ) {
    return null;
  }
  return {
    address: value.address,
    host: value.host,
    scope: value.scope,
    bytes: value.bytes,
    share: value.share,
  };
}

export function parseFlowAggregations(value: unknown): FlowAggregations | null {
  if (!exact(value, ['bucket_seconds', 'timeline', 'volume', 'application_mix', 'destinations'])) {
    return null;
  }
  const timeline = parseArray(value.timeline, 0, 200, parseBucket);
  const volume = parseVolume(value.volume);
  const mix = value.application_mix === null ? null : parseMix(value.application_mix);
  const destinations = parseArray(value.destinations, 0, 10, parseDestinationShare);
  if (
    !isIntegerInRange(value.bucket_seconds, 60, 86400) ||
    timeline === null ||
    volume === null ||
    (value.application_mix !== null && mix === null) ||
    destinations === null
  ) {
    return null;
  }
  return {
    bucket_seconds: value.bucket_seconds,
    timeline,
    volume,
    application_mix: mix,
    destinations,
  };
}

export interface TrafficFlowsResponse {
  state: TrafficState;
  time_range: TrafficTimeRange;
  filters: FlowFilters;
  /** Filters the flow source can not honour: the read is then unknown, never silently unfiltered. */
  unsupported: FilterName[];
  /** True when the caller lacks traffic:read-detail: no rows are read, aggregates only. */
  flows_restricted: boolean;
  attribution: AttributionStatus;
  flows: TrafficFlow[];
  aggregations: FlowAggregations | null;
  /** The small-cohort rule: too few sources withholds the aggregates (they are null, not thinned). */
  cohort: CohortStatus;
  freshness: Freshness;
}

const FLOWS_KEYS = [
  'state',
  'time_range',
  'filters',
  'unsupported',
  'flows_restricted',
  'attribution',
  'flows',
  'aggregations',
  'cohort',
  'freshness',
] as const;

function attributionMatchesRows(status: AttributionStatus, flows: readonly TrafficFlow[]): boolean {
  if (status.state !== 'ok') return flows.every((flow) => flow.attribution === null);
  if (flows.some((flow) => flow.attribution === null)) return false;
  if (status.level === 'endpoint') return flows.every((flow) => flow.attribution?.person === null);
  return true;
}

export function parseTrafficFlowsResponse(value: unknown): TrafficFlowsResponse | null {
  if (!exact(value, FLOWS_KEYS) || !isTrafficState(value.state)) return null;
  const timeRange = parseTrafficTimeRange(value.time_range);
  const filters = parseFlowFilters(value.filters);
  const attribution = parseAttributionStatus(value.attribution);
  const flows = parseArray(value.flows, 0, 500, parseTrafficFlow);
  const unsupported = parseArray(
    value.unsupported,
    0,
    FILTER_NAMES.length,
    (item) => (isOneOf(item, FILTER_NAMES) ? item : null),
    true,
  );
  const aggregations = value.aggregations === null ? null : parseFlowAggregations(value.aggregations);
  const freshness = parseFreshness(value.freshness);
  const cohort = parseCohort(value.cohort);
  if (
    timeRange === null ||
    cohort === null ||
    filters === null ||
    attribution === null ||
    flows === null ||
    unsupported === null ||
    freshness === null ||
    typeof value.flows_restricted !== 'boolean' ||
    (value.aggregations !== null && aggregations === null)
  ) {
    return null;
  }
  if (value.state !== 'ok' && (flows.length > 0 || aggregations !== null)) return null;
  if (value.flows_restricted && (flows.length > 0 || attribution.level !== 'none')) return null;
  if (unsupported.length > 0 && value.state !== 'unknown') return null;
  if (!attributionMatchesRows(attribution, flows)) return null;
  if (!cohortMatchesState(value.state, cohort)) return null;
  if (value.state === 'ok' && (cohort.state !== 'not-applied') !== value.flows_restricted) return null;
  if (cohort.state === 'too-few-sources' && aggregations !== null) return null;
  if (
    value.flows_restricted &&
    aggregations?.destinations.some((destination) => destination.scope === 'internal')
  ) {
    return null;
  }
  return {
    state: value.state,
    time_range: timeRange,
    filters,
    unsupported,
    flows_restricted: value.flows_restricted,
    attribution,
    flows,
    aggregations,
    cohort,
    freshness,
  };
}
