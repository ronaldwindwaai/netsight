import {
  RATIO_TOLERANCE,
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
  ranks,
  share,
} from './api-contracts-traffic-guards.ts';
import {
  cohortMatchesState,
  endpointCountsFollowCohort,
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
  APPROVALS,
  DESTINATION_SCOPES,
  POLICY_STATES,
  REPUTATIONS,
  RISK_LEVELS,
  TREND_STATES,
  type Approval,
  type DestinationScope,
  type PolicyState,
  type Reputation,
  type RiskLevel,
  type TrendState,
} from './api-contracts-traffic-shared.ts';

/** Applications and Destinations contracts (traffic-applications / traffic-destinations schemas). */

const TREND_FLAT_BAND = 0.1;

// --- Applications ----------------------------------------------------------------------------------------

export interface AppTrend {
  state: TrendState;
  previous_bytes: number | null;
  change_ratio: number | null;
}

export function parseAppTrend(value: unknown): AppTrend | null {
  if (!exact(value, ['state', 'previous_bytes', 'change_ratio'])) return null;
  if (
    !isOneOf(value.state, TREND_STATES) ||
    !nullableCount(value.previous_bytes) ||
    !(value.change_ratio === null || (finite(value.change_ratio) && value.change_ratio >= -1))
  ) {
    return null;
  }
  const { state, previous_bytes: previous, change_ratio: ratio } = value;
  if (state === 'unknown') {
    if (previous !== null || ratio !== null) return null;
  } else if (state === 'new') {
    if (previous !== 0 || ratio !== null) return null;
  } else {
    if (previous === null || previous < 1 || ratio === null) return null;
    if (state === 'up' && !(ratio > TREND_FLAT_BAND)) return null;
    if (state === 'down' && !(ratio < -TREND_FLAT_BAND)) return null;
    if (state === 'flat' && Math.abs(ratio) > TREND_FLAT_BAND) return null;
  }
  return { state, previous_bytes: previous, change_ratio: ratio };
}

export interface ApplicationRow {
  rank: number;
  /** Source-reported and untrusted. */
  application: string;
  category: string | null;
  bytes: number;
  packets: number | null;
  share: number | null;
  /** Distinct source addresses seen using the application: not people, not inventory devices. */
  endpoints: number | null;
  /** Null: counting people needs per-flow identity attribution, which is not done here. */
  users: number | null;
  trend: AppTrend;
  risk: RiskLevel;
  approval: Approval;
}

const APPLICATION_KEYS = [
  'rank',
  'application',
  'category',
  'bytes',
  'packets',
  'share',
  'endpoints',
  'users',
  'trend',
  'risk',
  'approval',
] as const;

export function parseApplicationRow(value: unknown): ApplicationRow | null {
  if (!exact(value, APPLICATION_KEYS)) return null;
  const v = value;
  const trend = parseAppTrend(v.trend);
  if (
    trend === null ||
    !isIntegerInRange(v.rank, 1, 100) ||
    !isText(v.application, 1, 255) ||
    !nullableText(v.category, 128) ||
    !count(v.bytes) ||
    !nullableCount(v.packets) ||
    !share(v.share) ||
    !nullableCount(v.endpoints) ||
    !nullableCount(v.users) ||
    !isOneOf(v.risk, RISK_LEVELS) ||
    !isOneOf(v.approval, APPROVALS)
  ) {
    return null;
  }
  if (trend.previous_bytes && trend.change_ratio !== null) {
    const expected = (v.bytes - trend.previous_bytes) / trend.previous_bytes;
    if (Math.abs(trend.change_ratio - expected) > RATIO_TOLERANCE) return null;
  }
  return {
    rank: v.rank,
    application: v.application,
    category: v.category,
    bytes: v.bytes,
    packets: v.packets,
    share: v.share,
    endpoints: v.endpoints,
    users: v.users,
    trend,
    risk: v.risk,
    approval: v.approval,
  };
}

export interface PolicyStatus {
  state: PolicyState;
}

function parsePolicy(value: unknown): PolicyStatus | null {
  if (!exact(value, ['state']) || !isOneOf(value.state, POLICY_STATES)) return null;
  return { state: value.state };
}

export interface TrafficApplicationsResponse {
  state: TrafficState;
  time_range: TrafficTimeRange;
  previous_range: TrafficTimeRange | null;
  policy: PolicyStatus;
  unsupported: 'application'[];
  total_bytes: number | null;
  items: ApplicationRow[];
  /** The aggregate tier withholds an endpoint count below the minimum (null) instead of listing it. */
  cohort: CohortStatus;
  freshness: Freshness;
}

const APPLICATIONS_KEYS = [
  'state',
  'time_range',
  'previous_range',
  'policy',
  'unsupported',
  'total_bytes',
  'items',
  'cohort',
  'freshness',
] as const;

export function parseTrafficApplicationsResponse(value: unknown): TrafficApplicationsResponse | null {
  if (!exact(value, APPLICATIONS_KEYS) || !isTrafficState(value.state)) return null;
  const timeRange = parseTrafficTimeRange(value.time_range);
  const previous = value.previous_range === null ? null : parseTrafficTimeRange(value.previous_range);
  const policy = parsePolicy(value.policy);
  const unsupported = parseArray(
    value.unsupported,
    0,
    1,
    (item) => (item === 'application' ? ('application' as const) : null),
    true,
  );
  const items = parseArray(value.items, 0, 100, parseApplicationRow);
  const freshness = parseFreshness(value.freshness);
  const cohort = parseCohort(value.cohort);
  if (
    timeRange === null ||
    cohort === null ||
    (value.previous_range !== null && previous === null) ||
    policy === null ||
    unsupported === null ||
    items === null ||
    freshness === null ||
    !nullableCount(value.total_bytes)
  ) {
    return null;
  }
  if (value.state !== 'ok' && (items.length > 0 || value.total_bytes !== null || previous !== null)) {
    return null;
  }
  if (unsupported.length > 0 && value.state !== 'unknown') return null;
  if (value.state === 'ok') {
    if (value.total_bytes === null) return null;
    if (items.reduce((sum, item) => sum + item.bytes, 0) > value.total_bytes) return null;
  }
  if (!cohortMatchesState(value.state, cohort)) return null;
  if (value.state === 'ok' && !endpointCountsFollowCohort(cohort, items.map((i) => i.endpoints))) {
    return null;
  }
  if (!ranks(items)) return null;
  return {
    state: value.state,
    time_range: timeRange,
    previous_range: previous,
    policy,
    unsupported,
    total_bytes: value.total_bytes,
    items,
    cohort,
    freshness,
  };
}

// --- Destinations --------------------------------------------------------------------------------------------

export interface DestinationRow {
  rank: number;
  address: string;
  /** `internal`: a private or otherwise non-routable address; only the detail tier is told. */
  scope: DestinationScope;
  /** Source-reported (reverse DNS or SNI) and untrusted. */
  domain: string | null;
  asn: number | null;
  country: string | null;
  first_seen: string | null;
  last_seen: string;
  bytes: number;
  packets: number | null;
  share: number | null;
  endpoints: number | null;
  users: number | null;
  reputation: Reputation;
}

const DESTINATION_KEYS = [
  'rank',
  'address',
  'scope',
  'domain',
  'asn',
  'country',
  'first_seen',
  'last_seen',
  'bytes',
  'packets',
  'share',
  'endpoints',
  'users',
  'reputation',
] as const;

export function parseDestinationRow(value: unknown): DestinationRow | null {
  if (!exact(value, DESTINATION_KEYS)) return null;
  const v = value;
  if (
    !isIntegerInRange(v.rank, 1, 100) ||
    !isText(v.address, 1, 45) ||
    !isOneOf(v.scope, DESTINATION_SCOPES) ||
    !nullableText(v.domain, 255) ||
    !asn(v.asn) ||
    !country(v.country) ||
    !nullableInstant(v.first_seen) ||
    !instant(v.last_seen) ||
    !count(v.bytes) ||
    !nullableCount(v.packets) ||
    !share(v.share) ||
    !nullableCount(v.endpoints) ||
    !nullableCount(v.users) ||
    !isOneOf(v.reputation, REPUTATIONS)
  ) {
    return null;
  }
  if (v.first_seen !== null && Date.parse(v.first_seen) > Date.parse(v.last_seen)) return null;
  return {
    rank: v.rank,
    address: v.address,
    scope: v.scope,
    domain: v.domain,
    asn: v.asn,
    country: v.country,
    first_seen: v.first_seen,
    last_seen: v.last_seen,
    bytes: v.bytes,
    packets: v.packets,
    share: v.share,
    endpoints: v.endpoints,
    users: v.users,
    reputation: v.reputation,
  };
}

export interface TrafficDestinationsResponse {
  state: TrafficState;
  time_range: TrafficTimeRange;
  first_seen_since: string | null;
  policy: PolicyStatus;
  total_bytes: number | null;
  items: DestinationRow[];
  cohort: CohortStatus;
  freshness: Freshness;
}

const DESTINATIONS_KEYS = [
  'state',
  'time_range',
  'first_seen_since',
  'policy',
  'total_bytes',
  'items',
  'cohort',
  'freshness',
] as const;

export function parseTrafficDestinationsResponse(value: unknown): TrafficDestinationsResponse | null {
  if (!exact(value, DESTINATIONS_KEYS) || !isTrafficState(value.state)) return null;
  const timeRange = parseTrafficTimeRange(value.time_range);
  const policy = parsePolicy(value.policy);
  const items = parseArray(value.items, 0, 100, parseDestinationRow);
  const freshness = parseFreshness(value.freshness);
  const cohort = parseCohort(value.cohort);
  if (
    timeRange === null ||
    cohort === null ||
    policy === null ||
    items === null ||
    freshness === null ||
    !nullableInstant(value.first_seen_since) ||
    !nullableCount(value.total_bytes)
  ) {
    return null;
  }
  if (
    value.state !== 'ok' &&
    (items.length > 0 || value.total_bytes !== null || value.first_seen_since !== null)
  ) {
    return null;
  }
  if (value.state === 'ok') {
    if (value.total_bytes === null) return null;
    if (items.reduce((sum, item) => sum + item.bytes, 0) > value.total_bytes) return null;
  }
  if (!cohortMatchesState(value.state, cohort)) return null;
  if (value.state === 'ok' && !endpointCountsFollowCohort(cohort, items.map((i) => i.endpoints))) {
    return null;
  }
  if (cohort.state !== 'not-applied' && items.some((item) => item.scope === 'internal')) return null;
  if (!ranks(items)) return null;
  const since = value.first_seen_since;
  if (
    since !== null &&
    items.some((item) => item.first_seen !== null && Date.parse(item.first_seen) < Date.parse(since))
  ) {
    return null;
  }
  return {
    state: value.state,
    time_range: timeRange,
    first_seen_since: since,
    policy,
    total_bytes: value.total_bytes,
    items,
    cohort,
    freshness,
  };
}
