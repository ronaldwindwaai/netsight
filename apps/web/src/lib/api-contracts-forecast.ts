import { isIntegerInRange, isOneOf, isText } from './contract-guards.ts';
import { exactRecord, isNullableText, isNullableTimestamp, isTimestamp, type Raw } from './contract-helpers.ts';

/**
 * Capacity forecast contract, mirroring contracts/json-schema/forecast.schema.json (shared vectors:
 * contracts/test-vectors/forecast.vectors.json).
 *
 * Every parser is fail-closed: anything that does not satisfy the exact contract returns null and
 * the caller renders an explicit error state, never a guess. The invariants that JSON Schema cannot
 * express (the band contains the point, the crossing is derived from the forecast, the overall state
 * follows from the series, days run on without a gap) are checked here exactly as pydantic checks
 * them. Every value in `forecast` is a projection; `history` holds the only measured values.
 */
export const FORECAST_STATES = ['ok', 'insufficient-data', 'not-connected', 'unknown'] as const;
export const SERIES_IDS = ['traffic-volume', 'wan-utilisation', 'inventory-growth'] as const;
export const UNITS = ['bytes-per-day', 'percent', 'devices'] as const;
export const REASONS = [
  'no-source',
  'no-history-source',
  'source-unreadable',
  'too-few-days',
  'too-many-gaps',
  'history-stale',
  'horizon-too-long',
] as const;
export const METHOD_NAMES = ['linear-trend', 'seasonal-naive-weekly'] as const;
export const RECOMMENDATION_KINDS = [
  'capacity-review',
  'capacity-watch',
  'growth-no-limit',
  'weekend-headroom',
  'connect-history-source',
  'collect-more-history',
] as const;
export const NOTICE =
  'Forecast, not measurement. Values after the last measured day are projections from past ' +
  'source-reported data. They are not observations and can be wrong.';

export type ForecastState = (typeof FORECAST_STATES)[number];
export type SeriesId = (typeof SERIES_IDS)[number];
export type Unit = (typeof UNITS)[number];
export type Reason = (typeof REASONS)[number];
export type MethodName = (typeof METHOD_NAMES)[number];
export type RecommendationKind = (typeof RECOMMENDATION_KINDS)[number];

const MAX_VALUE = 10 ** 15;
const MIN_OBSERVED = 14;
const MAX_HISTORY = 120;
const MAX_HORIZON = 30;
const MAX_RECOMMENDATIONS = 8;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const REC_ID = /^[a-z][a-z0-9-]{2,63}$/;
const NO_HISTORY_REASONS: readonly Reason[] = ['no-source', 'no-history-source'];
const INSUFFICIENT_REASONS: readonly Reason[] = [
  'too-few-days',
  'too-many-gaps',
  'history-stale',
  'horizon-too-long',
];
const DAY_MS = 86_400_000;

export interface HistoryPoint {
  day: string;
  value: number;
}
export interface ForecastPoint {
  day: string;
  value: number;
  lower: number;
  upper: number;
}
export interface ForecastMethod {
  name: MethodName;
  why: string;
  observed_days: number;
  slope_per_day: number | null;
  linear_mae: number;
  seasonal_mae: number | null;
  band: 'approximate-95-percent';
}
export interface ForecastThreshold {
  value: number;
  basis: 'operator-configured';
}
export interface ForecastCrossing {
  point_day: string | null;
  upper_day: string | null;
}
export interface ForecastSeries {
  id: SeriesId;
  name: string;
  unit: Unit;
  state: ForecastState;
  reason: Reason | null;
  detail: string | null;
  source_observed_at: string | null;
  history: HistoryPoint[];
  history_missing_days: number;
  method: ForecastMethod | null;
  forecast: ForecastPoint[];
  threshold: ForecastThreshold | null;
  crossing: ForecastCrossing | null;
}
export interface ForecastRecommendation {
  id: string;
  kind: RecommendationKind;
  series_id: SeriesId;
  title: string;
  advice: string;
  evidence: string[];
  advisory: true;
  executable: false;
}
export interface ForecastResponse {
  state: ForecastState;
  generated_at: string;
  is_forecast: true;
  notice: string;
  horizon_days: number;
  history_days: number;
  history_through: string | null;
  series: ForecastSeries[];
  recommendations: ForecastRecommendation[];
}

// --- helpers ------------------------------------------------------------------------------------------------

/** A real calendar day as a UTC millisecond count, or null (`2026-02-30` is not a day). */
export function dayNumber(value: unknown): number | null {
  if (typeof value !== 'string' || !DAY.test(value)) return null;
  const [year, month, date] = value.split('-').map(Number);
  const ms = Date.UTC(year, month - 1, date);
  return new Date(ms).toISOString().slice(0, 10) === value ? ms : null;
}

const isValue = (value: unknown): value is number => isIntegerInRange(value, 0, MAX_VALUE);

function listOf<T>(
  value: unknown,
  maximum: number,
  parse: (item: unknown) => T | null,
  minimum = 0,
): T[] | null {
  if (!Array.isArray(value) || value.length > maximum || value.length < minimum) return null;
  const out: T[] = [];
  for (const raw of value) {
    const parsed = parse(raw);
    if (parsed === null) return null;
    out.push(parsed);
  }
  return out;
}

// --- points, method, threshold, crossing ---------------------------------------------------------------------

export function parseHistoryPoint(value: unknown): HistoryPoint | null {
  const r = exactRecord(value, ['day', 'value']);
  if (r === null || dayNumber(r.day) === null || !isValue(r.value)) return null;
  return { day: r.day as string, value: r.value };
}

export function parseForecastPoint(value: unknown): ForecastPoint | null {
  const r = exactRecord(value, ['day', 'value', 'lower', 'upper']);
  if (
    r === null ||
    dayNumber(r.day) === null ||
    !isValue(r.value) ||
    !isValue(r.lower) ||
    !isValue(r.upper) ||
    !(r.lower <= r.value && r.value <= r.upper)
  ) {
    return null;
  }
  return { day: r.day as string, value: r.value, lower: r.lower, upper: r.upper };
}

export function parseForecastMethod(value: unknown): ForecastMethod | null {
  const r = exactRecord(value, [
    'name',
    'why',
    'observed_days',
    'slope_per_day',
    'linear_mae',
    'seasonal_mae',
    'band',
  ]);
  if (
    r === null ||
    !isOneOf(r.name, METHOD_NAMES) ||
    !isText(r.why, 1, 400) ||
    !isIntegerInRange(r.observed_days, MIN_OBSERVED, MAX_HISTORY) ||
    !(r.slope_per_day === null || isIntegerInRange(r.slope_per_day, -MAX_VALUE, MAX_VALUE)) ||
    !isValue(r.linear_mae) ||
    !(r.seasonal_mae === null || isValue(r.seasonal_mae)) ||
    r.band !== 'approximate-95-percent'
  ) {
    return null;
  }
  const seasonal = r.name === 'seasonal-naive-weekly';
  if (seasonal !== (r.slope_per_day === null)) return null;
  if (seasonal && r.seasonal_mae === null) return null;
  return r as unknown as ForecastMethod;
}

export function parseForecastThreshold(value: unknown): ForecastThreshold | null {
  const r = exactRecord(value, ['value', 'basis']);
  if (r === null || !isIntegerInRange(r.value, 1, MAX_VALUE) || r.basis !== 'operator-configured') {
    return null;
  }
  return { value: r.value, basis: 'operator-configured' };
}

const isNullableDay = (value: unknown): value is string | null =>
  value === null || dayNumber(value) !== null;

export function parseForecastCrossing(value: unknown): ForecastCrossing | null {
  const r = exactRecord(value, ['point_day', 'upper_day']);
  if (r === null || !isNullableDay(r.point_day) || !isNullableDay(r.upper_day)) return null;
  if (r.point_day !== null) {
    // The upper band reaches a limit no later than the point forecast does.
    if (r.upper_day === null || (dayNumber(r.upper_day) as number) > (dayNumber(r.point_day) as number)) {
      return null;
    }
  }
  return { point_day: r.point_day, upper_day: r.upper_day };
}

/** The crossing implied by a forecast and a limit (what the API must have sent). */
export function crossingFor(points: readonly ForecastPoint[], limit: number): ForecastCrossing {
  return {
    point_day: points.find((p) => p.value >= limit)?.day ?? null,
    upper_day: points.find((p) => p.upper >= limit)?.day ?? null,
  };
}

// --- series ----------------------------------------------------------------------------------------------------

function daysAreOrdered(history: readonly HistoryPoint[], forecast: readonly ForecastPoint[]): boolean {
  let previous: number | null = null;
  for (const point of history) {
    const day = dayNumber(point.day) as number;
    if (previous !== null && day <= previous) return false;
    previous = day;
  }
  let expected = previous === null ? null : previous + DAY_MS;
  for (const point of forecast) {
    const day = dayNumber(point.day) as number;
    if (expected !== null && day !== expected) return false;
    expected = day + DAY_MS;
  }
  return true;
}

function okSeriesHolds(s: ForecastSeries): boolean {
  if (s.reason !== null || s.method === null || s.forecast.length === 0) return false;
  if (s.history.length < MIN_OBSERVED || s.method.observed_days !== s.history.length) return false;
  if ((s.threshold === null) !== (s.crossing === null)) return false;
  if (s.threshold === null || s.crossing === null) return true;
  const derived = crossingFor(s.forecast, s.threshold.value);
  return derived.point_day === s.crossing.point_day && derived.upper_day === s.crossing.upper_day;
}

function notOkSeriesHolds(s: ForecastSeries): boolean {
  if (s.method !== null || s.forecast.length > 0 || s.threshold !== null || s.crossing !== null) {
    return false;
  }
  if (s.reason === null || s.detail === null) return false;
  if (s.state === 'insufficient-data') return INSUFFICIENT_REASONS.includes(s.reason);
  if (s.history.length > 0 || s.history_missing_days > 0) return false;
  if (s.state === 'not-connected') return NO_HISTORY_REASONS.includes(s.reason);
  return s.reason === 'source-unreadable';
}

export function parseForecastSeries(value: unknown): ForecastSeries | null {
  const r = exactRecord(value, [
    'id',
    'name',
    'unit',
    'state',
    'reason',
    'detail',
    'source_observed_at',
    'history',
    'history_missing_days',
    'method',
    'forecast',
    'threshold',
    'crossing',
  ]);
  if (
    r === null ||
    !isOneOf(r.id, SERIES_IDS) ||
    !isText(r.name, 1, 80) ||
    !isOneOf(r.unit, UNITS) ||
    !isOneOf(r.state, FORECAST_STATES) ||
    !(r.reason === null || isOneOf(r.reason, REASONS)) ||
    !isNullableText(r.detail, 400) ||
    !isNullableTimestamp(r.source_observed_at) ||
    !isIntegerInRange(r.history_missing_days, 0, MAX_HISTORY)
  ) {
    return null;
  }
  const history = listOf(r.history, MAX_HISTORY, parseHistoryPoint);
  const forecast = listOf(r.forecast, MAX_HORIZON, parseForecastPoint);
  const method = r.method === null ? null : parseForecastMethod(r.method);
  const threshold = r.threshold === null ? null : parseForecastThreshold(r.threshold);
  const crossing = r.crossing === null ? null : parseForecastCrossing(r.crossing);
  if (history === null || forecast === null) return null;
  if ((r.method !== null && method === null) || (r.threshold !== null && threshold === null)) return null;
  if (r.crossing !== null && crossing === null) return null;
  const series = { ...r, history, forecast, method, threshold, crossing } as unknown as ForecastSeries;
  if (!daysAreOrdered(history, forecast)) return null;
  return (series.state === 'ok' ? okSeriesHolds(series) : notOkSeriesHolds(series)) ? series : null;
}

// --- recommendations and the response ------------------------------------------------------------------------

export function parseForecastRecommendation(value: unknown): ForecastRecommendation | null {
  const r = exactRecord(value, [
    'id',
    'kind',
    'series_id',
    'title',
    'advice',
    'evidence',
    'advisory',
    'executable',
  ]);
  if (
    r === null ||
    !isText(r.id, 3, 64) ||
    !REC_ID.test(r.id as string) ||
    !isOneOf(r.kind, RECOMMENDATION_KINDS) ||
    !isOneOf(r.series_id, SERIES_IDS) ||
    !isText(r.title, 1, 120) ||
    !isText(r.advice, 1, 500) ||
    r.advisory !== true ||
    r.executable !== false
  ) {
    return null;
  }
  const evidence = listOf(r.evidence, 5, (line) => (isText(line, 1, 400) ? line : null), 1);
  if (evidence === null) return null;
  return { ...(r as Raw), evidence } as unknown as ForecastRecommendation;
}

/** `ok` when any series has a forecast, else the least-informative explanation that applies. */
export function overallState(states: readonly ForecastState[]): ForecastState {
  for (const state of ['ok', 'insufficient-data', 'unknown'] as const) {
    if (states.includes(state)) return state;
  }
  return 'not-connected';
}

export function parseForecastResponse(value: unknown): ForecastResponse | null {
  const r = exactRecord(value, [
    'state',
    'generated_at',
    'is_forecast',
    'notice',
    'horizon_days',
    'history_days',
    'history_through',
    'series',
    'recommendations',
  ]);
  if (
    r === null ||
    !isOneOf(r.state, FORECAST_STATES) ||
    !isTimestamp(r.generated_at) ||
    r.is_forecast !== true ||
    r.notice !== NOTICE ||
    !isIntegerInRange(r.horizon_days, 1, MAX_HORIZON) ||
    !isIntegerInRange(r.history_days, MIN_OBSERVED, MAX_HISTORY) ||
    !isNullableDay(r.history_through)
  ) {
    return null;
  }
  const series = listOf(r.series, 3, parseForecastSeries, 1);
  const recommendations = listOf(r.recommendations, MAX_RECOMMENDATIONS, parseForecastRecommendation);
  if (series === null || recommendations === null) return null;
  if (new Set(series.map((s) => s.id)).size !== series.length) return null;
  if (r.state !== overallState(series.map((s) => s.state))) return null;
  if (series.some((s) => s.state === 'ok' && s.forecast.length !== r.horizon_days)) return null;
  return { ...r, series, recommendations } as unknown as ForecastResponse;
}
