import {
  RATIO_TOLERANCE,
  asn,
  count,
  exact,
  finite,
  instant,
  isTrafficState,
  nullableInstant,
  nullableText,
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
import { isIntegerInRange, isOneOf, parseArray } from './contract-guards.ts';
import {
  CONFIDENCES,
  DAYLIGHT_SAVING,
  EVALUATION_STATUSES,
  HISTORY_STATES,
  LEGITIMATE_PATTERNS,
  POLICY_STATES,
  type Confidence,
  type DaylightSaving,
  type EvaluationStatus,
  type HistoryState,
  type LegitimatePattern,
  type PolicyState,
} from './api-contracts-traffic-shared.ts';

/** Baseline comparison contract (traffic-anomalies.schema.json): anomalies and first-seen context. */

const HOUR_MS = 3_600_000;

// --- Anomalies -----------------------------------------------------------------------------------------------

export interface BaselineMethod {
  algorithm: 'same-hour-of-week-median-mad';
  weeks: number;
  min_weeks: number;
  threshold: number;
  min_difference_bytes: number;
}

function parseMethod(value: unknown): BaselineMethod | null {
  if (!exact(value, ['algorithm', 'weeks', 'min_weeks', 'threshold', 'min_difference_bytes'])) return null;
  if (
    value.algorithm !== 'same-hour-of-week-median-mad' ||
    !isIntegerInRange(value.weeks, 1, 8) ||
    !isIntegerInRange(value.min_weeks, 1, 8) ||
    value.min_weeks > value.weeks ||
    !(finite(value.threshold) && value.threshold > 0) ||
    !count(value.min_difference_bytes)
  ) {
    return null;
  }
  return {
    algorithm: value.algorithm,
    weeks: value.weeks,
    min_weeks: value.min_weeks,
    threshold: value.threshold,
    min_difference_bytes: value.min_difference_bytes,
  };
}

export interface WorkingHours {
  state: PolicyState;
  timezone: string | null;
}

export function parseWorkingHours(value: unknown): WorkingHours | null {
  if (!exact(value, ['state', 'timezone'])) return null;
  if (!isOneOf(value.state, POLICY_STATES) || !nullableText(value.timezone, 64)) return null;
  if ((value.state === 'configured') !== (value.timezone !== null)) return null;
  return { state: value.state, timezone: value.timezone };
}

export interface Evaluation {
  status: EvaluationStatus;
  series: number;
  buckets: number;
  evaluated: number;
  insufficient_baseline: number;
  no_data: number;
  anomalies_total: number;
  application_series: 'evaluated' | 'not-reported';
  /** The baseline weeks are fixed 168-hour UTC weeks: `crossed` means the policy zone changed offset. */
  daylight_saving: DaylightSaving;
}

const EVALUATION_KEYS = [
  'status',
  'series',
  'buckets',
  'evaluated',
  'insufficient_baseline',
  'no_data',
  'anomalies_total',
  'application_series',
  'daylight_saving',
] as const;

function expectedStatus(evaluated: number, insufficient: number): EvaluationStatus {
  if (evaluated === 0) return insufficient > 0 ? 'insufficient-baseline' : 'no-data';
  return insufficient > 0 ? 'partial' : 'evaluated';
}

export function parseEvaluation(value: unknown): Evaluation | null {
  if (!exact(value, EVALUATION_KEYS)) return null;
  const v = value;
  if (
    !isOneOf(v.status, EVALUATION_STATUSES) ||
    !count(v.series) ||
    !count(v.buckets) ||
    !count(v.evaluated) ||
    !count(v.insufficient_baseline) ||
    !count(v.no_data) ||
    !count(v.anomalies_total) ||
    !isOneOf(v.application_series, ['evaluated', 'not-reported'] as const) ||
    !isOneOf(v.daylight_saving, DAYLIGHT_SAVING)
  ) {
    return null;
  }
  if (v.evaluated + v.insufficient_baseline + v.no_data !== v.buckets) return null;
  if (v.evaluated === 0 && v.anomalies_total !== 0) return null;
  if (v.status !== expectedStatus(v.evaluated, v.insufficient_baseline)) return null;
  return {
    status: v.status,
    series: v.series,
    buckets: v.buckets,
    evaluated: v.evaluated,
    insufficient_baseline: v.insufficient_baseline,
    no_data: v.no_data,
    anomalies_total: v.anomalies_total,
    application_series: v.application_series,
    daylight_saving: v.daylight_saving,
  };
}

export interface FirstSeenStatus {
  state: HistoryState;
  required_days: number;
  oldest: string | null;
}

function parseHistory(value: unknown): FirstSeenStatus | null {
  if (!exact(value, ['state', 'required_days', 'oldest'])) return null;
  if (
    !isOneOf(value.state, HISTORY_STATES) ||
    !isIntegerInRange(value.required_days, 1, 31) ||
    !nullableInstant(value.oldest) ||
    (value.state === 'unknown' && value.oldest !== null)
  ) {
    return null;
  }
  return { state: value.state, required_days: value.required_days, oldest: value.oldest };
}

export interface AnomalyContext {
  outside_working_hours: boolean | null;
  common_legitimate_patterns: LegitimatePattern[];
}

function parseContext(value: unknown): AnomalyContext | null {
  if (!exact(value, ['outside_working_hours', 'common_legitimate_patterns'])) return null;
  const patterns = parseArray(
    value.common_legitimate_patterns,
    0,
    LEGITIMATE_PATTERNS.length,
    (item) => (isOneOf(item, LEGITIMATE_PATTERNS) ? item : null),
    true,
  );
  if (
    patterns === null ||
    !(value.outside_working_hours === null || typeof value.outside_working_hours === 'boolean')
  ) {
    return null;
  }
  return { outside_working_hours: value.outside_working_hours, common_legitimate_patterns: patterns };
}

export interface AnomalySubject {
  kind: 'total' | 'application';
  /** Untrusted source text when the subject is an application. */
  label: string | null;
}

function parseSubject(value: unknown): AnomalySubject | null {
  if (!exact(value, ['kind', 'label'])) return null;
  if (!isOneOf(value.kind, ['total', 'application'] as const) || !nullableText(value.label, 255)) return null;
  if ((value.kind === 'application') !== (value.label !== null)) return null;
  return { kind: value.kind, label: value.label };
}

export interface Anomaly {
  kind: 'volume-deviation';
  subject: AnomalySubject;
  bucket_start: string;
  bucket_end: string;
  direction: 'above' | 'below';
  observed: number;
  baseline: number;
  baseline_samples: number;
  difference: number;
  ratio: number | null;
  score: number;
  confidence: Confidence;
  context: AnomalyContext;
}

const ANOMALY_KEYS = [
  'kind',
  'subject',
  'bucket_start',
  'bucket_end',
  'direction',
  'observed',
  'baseline',
  'baseline_samples',
  'difference',
  'ratio',
  'score',
  'confidence',
  'context',
] as const;

function onTheHour(value: string): boolean {
  const moment = new Date(value);
  return (
    moment.getUTCMinutes() === 0 && moment.getUTCSeconds() === 0 && moment.getUTCMilliseconds() === 0
  );
}

export function parseAnomaly(value: unknown): Anomaly | null {
  if (!exact(value, ANOMALY_KEYS)) return null;
  const v = value;
  const subject = parseSubject(v.subject);
  const context = parseContext(v.context);
  if (
    v.kind !== 'volume-deviation' ||
    subject === null ||
    context === null ||
    !instant(v.bucket_start) ||
    !instant(v.bucket_end) ||
    !isOneOf(v.direction, ['above', 'below'] as const) ||
    !count(v.observed) ||
    !count(v.baseline) ||
    !isIntegerInRange(v.baseline_samples, 1, 8) ||
    !(typeof v.difference === 'number' && Number.isInteger(v.difference)) ||
    !(v.ratio === null || (finite(v.ratio) && v.ratio >= 0)) ||
    !finite(v.score) ||
    !isOneOf(v.confidence, CONFIDENCES)
  ) {
    return null;
  }
  if (!onTheHour(v.bucket_start) || Date.parse(v.bucket_end) - Date.parse(v.bucket_start) !== HOUR_MS) {
    return null;
  }
  if (v.difference !== v.observed - v.baseline) return null;
  if (v.difference === 0 || (v.direction === 'above') !== (v.difference > 0)) return null;
  if ((v.ratio === null) !== (v.baseline === 0)) return null;
  if (v.ratio !== null) {
    const expected = v.observed / v.baseline;
    if (Math.abs(v.ratio - expected) > Math.max(RATIO_TOLERANCE * Math.abs(expected), 1e-9)) return null;
  }
  return {
    kind: v.kind,
    subject,
    bucket_start: v.bucket_start,
    bucket_end: v.bucket_end,
    direction: v.direction,
    observed: v.observed,
    baseline: v.baseline,
    baseline_samples: v.baseline_samples,
    difference: v.difference,
    ratio: v.ratio,
    score: v.score,
    confidence: v.confidence,
    context,
  };
}

export interface FirstSeen {
  kind: 'first-seen-asn' | 'first-seen-destination';
  asn: number | null;
  address: string | null;
  domain: string | null;
  first_seen: string;
  bytes: number;
  context: AnomalyContext;
}

export function parseFirstSeen(value: unknown): FirstSeen | null {
  if (!exact(value, ['kind', 'asn', 'address', 'domain', 'first_seen', 'bytes', 'context'])) return null;
  const v = value;
  const context = parseContext(v.context);
  if (
    context === null ||
    !isOneOf(v.kind, ['first-seen-asn', 'first-seen-destination'] as const) ||
    !asn(v.asn) ||
    !nullableText(v.address, 45) ||
    !nullableText(v.domain, 255) ||
    !instant(v.first_seen) ||
    !count(v.bytes)
  ) {
    return null;
  }
  if (v.kind === 'first-seen-asn') {
    if (v.asn === null || v.address !== null || v.domain !== null) return null;
  } else if (v.address === null) {
    return null;
  }
  return {
    kind: v.kind,
    asn: v.asn,
    address: v.address,
    domain: v.domain,
    first_seen: v.first_seen,
    bytes: v.bytes,
    context,
  };
}

export interface TrafficAnomaliesResponse {
  state: TrafficState;
  time_range: TrafficTimeRange;
  evaluated_range: TrafficTimeRange | null;
  method: BaselineMethod;
  working_hours: WorkingHours;
  evaluation: Evaluation;
  first_seen_status: FirstSeenStatus;
  anomalies: Anomaly[];
  first_seen: FirstSeen[];
  /** The aggregate tier is not shown first-seen destinations that few sources stood behind. */
  cohort: CohortStatus;
  freshness: Freshness;
}

const ANOMALIES_KEYS = [
  'state',
  'time_range',
  'evaluated_range',
  'method',
  'working_hours',
  'evaluation',
  'first_seen_status',
  'anomalies',
  'first_seen',
  'cohort',
  'freshness',
] as const;

export function parseTrafficAnomaliesResponse(value: unknown): TrafficAnomaliesResponse | null {
  if (!exact(value, ANOMALIES_KEYS) || !isTrafficState(value.state)) return null;
  const timeRange = parseTrafficTimeRange(value.time_range);
  const evaluated = value.evaluated_range === null ? null : parseTrafficTimeRange(value.evaluated_range);
  const method = parseMethod(value.method);
  const workingHours = parseWorkingHours(value.working_hours);
  const evaluation = parseEvaluation(value.evaluation);
  const history = parseHistory(value.first_seen_status);
  const anomalies = parseArray(value.anomalies, 0, 50, parseAnomaly);
  const firstSeen = parseArray(value.first_seen, 0, 20, parseFirstSeen);
  const freshness = parseFreshness(value.freshness);
  const cohort = parseCohort(value.cohort);
  if (
    timeRange === null ||
    cohort === null ||
    (value.evaluated_range !== null && evaluated === null) ||
    method === null ||
    workingHours === null ||
    evaluation === null ||
    history === null ||
    anomalies === null ||
    firstSeen === null ||
    freshness === null
  ) {
    return null;
  }
  if (value.state !== 'ok' && (anomalies.length > 0 || firstSeen.length > 0 || evaluated !== null)) {
    return null;
  }
  if (
    (evaluation.status === 'insufficient-baseline' || evaluation.status === 'no-data') &&
    anomalies.length > 0
  ) {
    return null;
  }
  if (history.state !== 'sufficient' && firstSeen.length > 0) return null;
  if (!cohortMatchesState(value.state, cohort)) return null;
  if (anomalies.length > evaluation.anomalies_total) return null;
  for (const item of anomalies) {
    if (
      Math.abs(item.score) < method.threshold ||
      item.baseline_samples < method.min_weeks ||
      item.baseline_samples > method.weeks ||
      Math.abs(item.difference) < method.min_difference_bytes
    ) {
      return null;
    }
  }
  return {
    state: value.state,
    time_range: timeRange,
    evaluated_range: evaluated,
    method,
    working_hours: workingHours,
    evaluation,
    first_seen_status: history,
    anomalies,
    first_seen: firstSeen,
    cohort,
    freshness,
  };
}
