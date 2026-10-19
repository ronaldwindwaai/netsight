import type {
  ForecastResponse,
  ForecastSeries,
  ForecastState,
  Reason,
  Unit,
} from './api-contracts-forecast.ts';
import { dayNumber } from './api-contracts-forecast.ts';
import type { FetchState } from './api-response.ts';

/**
 * Pure presentation helpers for the capacity forecast page (Step 13). Nothing here reads an API.
 *
 * The query is validated against the windows the page offers before it can reach an API path.
 * Geometry for the chart is computed here (not in the component) so it can be tested: a gap in the
 * measured days breaks the line, a forecast is a separate dashed line with its own band, and a
 * series with no forecast gets neither. Every chart has a text alternative and a data table built
 * from the same series.
 */
type RawParam = string | string[] | undefined;
type Params = Record<string, RawParam>;

export const HORIZON_OPTIONS = [7, 14, 30] as const;
export const HISTORY_OPTIONS = [28, 56, 90] as const;
export const DEFAULT_HORIZON = 14;
export const DEFAULT_HISTORY = 56;

export interface ForecastQuery {
  horizon: number;
  history: number;
}

function first(value: RawParam): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function offered(value: RawParam, options: readonly number[], fallback: number): number {
  const raw = first(value);
  if (raw === undefined || !/^[0-9]{1,3}$/.test(raw)) return fallback;
  return options.includes(Number(raw)) ? Number(raw) : fallback;
}

export function parseForecastQuery(params: Params): ForecastQuery {
  return {
    horizon: offered(params.horizon_days, HORIZON_OPTIONS, DEFAULT_HORIZON),
    history: offered(params.history_days, HISTORY_OPTIONS, DEFAULT_HISTORY),
  };
}

function queryString(query: ForecastQuery): string {
  return `horizon_days=${query.horizon}&history_days=${query.history}`;
}

export function forecastPath(query: ForecastQuery): string {
  return `/api/v1/forecast/capacity?${queryString(query)}`;
}

/** The web download route (which forwards to the API export); never the API path itself. */
export function exportPath(query: ForecastQuery): string {
  return `/forecast/export?${queryString(query)}`;
}

export function pageHref(query: ForecastQuery): string {
  return `/forecast?${queryString(query)}`;
}

// --- words ---------------------------------------------------------------------------------------------------

export interface Presentation {
  label: string;
  icon: string;
  theme: 'success' | 'warning' | 'danger' | 'secondary' | 'info';
  explanation: string;
}

const STATES: Record<ForecastState, Presentation> = {
  ok: {
    label: 'Forecast available',
    icon: 'bi-graph-up-arrow',
    theme: 'info',
    explanation:
      'Enough source-reported history exists. The values after the last measured day are a forecast, not measurements.',
  },
  'insufficient-data': {
    label: 'Not enough history',
    icon: 'bi-hourglass-split',
    theme: 'warning',
    explanation:
      'The source has been read, but there is too little recent history to project from. Nothing is estimated in its place.',
  },
  'not-connected': {
    label: 'No source',
    icon: 'bi-plug',
    theme: 'secondary',
    explanation:
      'No source reports history for this series, so there is nothing to forecast. This is not the same as having no traffic.',
  },
  unknown: {
    label: 'Unknown',
    icon: 'bi-question-circle',
    theme: 'danger',
    explanation:
      'The source is configured but could not be read. Nothing is estimated in place of its history.',
  },
};

export function statePresentation(state: ForecastState): Presentation {
  return STATES[state];
}

const REASONS: Record<Reason, string> = {
  'no-source': 'No flow source is configured.',
  'no-history-source': 'No source in this deployment reports the history of this series.',
  'source-unreadable': 'The source is configured but could not be read.',
  'too-few-days': 'Fewer observed days than the minimum needed for a forecast.',
  'too-many-gaps': 'Too many days in the window have no data; gaps are never filled in.',
  'history-stale': 'The newest observed day is too old to project from.',
  'horizon-too-long': 'The history is too short for a forecast this far ahead; choose a shorter horizon.',
};

export function reasonText(reason: Reason): string {
  return REASONS[reason];
}

const BYTE_UNITS = [
  [1e3, 'kB'],
  [1e6, 'MB'],
  [1e9, 'GB'],
  [1e12, 'TB'],
] as const;

export function formatAmount(value: number, unit: Unit): string {
  if (unit === 'percent') return `${value} %`;
  if (unit === 'devices') return `${value} ${value === 1 ? 'device' : 'devices'}`;
  for (let index = BYTE_UNITS.length - 1; index >= 0; index -= 1) {
    let [limit, name] = BYTE_UNITS[index];
    if (value < limit) continue;
    // 999.95 kB reads as 1.0 MB, never as 1000.0 kB.
    if (Number((value / limit).toFixed(1)) >= 1000 && index + 1 < BYTE_UNITS.length) {
      [limit, name] = BYTE_UNITS[index + 1];
    }
    return `${(value / limit).toFixed(1)} ${name}/day`;
  }
  return `${value} B/day`;
}

export const UNIT_LABEL: Record<Unit, string> = {
  'bytes-per-day': 'bytes per day',
  percent: 'percent',
  devices: 'devices',
};

export type PageSurface = 'permission' | 'unauthenticated' | 'error' | 'data';

export function pageSurface(state: FetchState<ForecastResponse>): PageSurface {
  if (state.kind === 'forbidden') return 'permission';
  if (state.kind === 'unauthenticated') return 'unauthenticated';
  return state.kind === 'ok' ? 'data' : 'error';
}

// --- text alternative and table ------------------------------------------------------------------------------

function methodWords(series: ForecastSeries): string {
  return series.method?.name === 'seasonal-naive-weekly' ? 'weekly repeat' : 'linear trend';
}

export function describeSeries(series: ForecastSeries): string {
  const unit = UNIT_LABEL[series.unit];
  const head = `${series.name}, ${unit}.`;
  const measured =
    series.history.length === 0
      ? 'Measured: no days.'
      : `Measured: ${series.history.length} days, ${series.history[0].day} to ${series.history.at(-1)!.day}, latest ${formatAmount(series.history.at(-1)!.value, series.unit)}.`;
  if (series.forecast.length === 0) {
    return `${head} ${measured} No forecast. ${series.detail ?? ''}`.trim();
  }
  const last = series.forecast.at(-1)!;
  const from = series.forecast[0];
  const forecast =
    `Forecast, not measured: ${series.forecast.length} days, ${from.day} to ${last.day}, ` +
    `${methodWords(series)}, from ${formatAmount(from.value, series.unit)} to ${formatAmount(last.value, series.unit)} ` +
    `with an approximate 95 % band reaching ${formatAmount(last.lower, series.unit)} to ${formatAmount(last.upper, series.unit)} on the last day.`;
  return `${head} ${measured} ${forecast}`;
}

export interface TableRow {
  day: string;
  kind: 'measured' | 'forecast';
  value: string;
  range: string | null;
}

export function tableRows(series: ForecastSeries): TableRow[] {
  return [
    ...series.history.map((p) => ({
      day: p.day,
      kind: 'measured' as const,
      value: formatAmount(p.value, series.unit),
      range: null,
    })),
    ...series.forecast.map((p) => ({
      day: p.day,
      kind: 'forecast' as const,
      value: formatAmount(p.value, series.unit),
      range: `${formatAmount(p.lower, series.unit)} to ${formatAmount(p.upper, series.unit)}`,
    })),
  ];
}

// --- chart geometry ------------------------------------------------------------------------------------------

export const CHART_WIDTH = 640;
export const CHART_HEIGHT = 240;
const MARGIN = { left: 76, right: 12, top: 12, bottom: 30 } as const;
const DAY_MS = 86_400_000;
const FAR_LIMIT_FACTOR = 2;

export interface Tick {
  value: number;
  position: number;
  label: string;
}

export interface Chart {
  width: number;
  height: number;
  measuredPaths: string[];
  isolated: Array<{ x: number; y: number }>;
  forecastPath: string | null;
  bandPath: string | null;
  boundaryX: number;
  thresholdY: number | null;
  yTicks: Tick[];
  xTicks: Array<{ x: number; label: string }>;
  plot: { left: number; right: number; top: number; bottom: number };
}

/** The smallest "round" ceiling (1, 2, 2.5 or 5 times a power of ten) at or above ``value``. */
function niceCeiling(value: number): number {
  if (value <= 0) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  for (const step of [1, 2, 2.5, 5, 10]) {
    if (step * magnitude >= value) return step * magnitude;
  }
  return 10 * magnitude;
}

const fixed = (n: number): string => n.toFixed(1);

interface Scales {
  x: (day: string) => number;
  y: (value: number) => number;
  top: number;
}

function scales(series: ForecastSeries): Scales {
  const days = [...series.history.map((p) => p.day), ...series.forecast.map((p) => p.day)];
  const first = dayNumber(days[0]) as number;
  const span = Math.max(1, ((dayNumber(days.at(-1)) as number) - first) / DAY_MS);
  const values = [...series.history.map((p) => p.value), ...series.forecast.map((p) => p.upper)];
  const dataMax = Math.max(...values, 1);
  const limit = series.threshold?.value;
  const withLimit = limit !== undefined && limit <= dataMax * FAR_LIMIT_FACTOR ? Math.max(dataMax, limit) : dataMax;
  const top = niceCeiling(withLimit);
  const width = CHART_WIDTH - MARGIN.left - MARGIN.right;
  const height = CHART_HEIGHT - MARGIN.top - MARGIN.bottom;
  return {
    x: (day) => MARGIN.left + ((((dayNumber(day) as number) - first) / DAY_MS) / span) * width,
    y: (value) => MARGIN.top + (1 - value / top) * height,
    top,
  };
}

function runs(series: ForecastSeries): Array<typeof series.history> {
  const groups: Array<typeof series.history> = [];
  let previous: number | null = null;
  for (const point of series.history) {
    const day = dayNumber(point.day) as number;
    if (previous === null || day - previous !== DAY_MS) groups.push([]);
    groups.at(-1)!.push(point);
    previous = day;
  }
  return groups;
}

function yTicks(series: ForecastSeries, scale: Scales): Tick[] {
  return [0, 0.5, 1].map((fraction) => {
    const value = scale.top * fraction;
    return { value, position: scale.y(value), label: formatAmount(Math.round(value), series.unit) };
  });
}

/** Geometry for the series, or null when there is nothing measured to draw. */
export function buildChart(series: ForecastSeries): Chart | null {
  if (series.history.length === 0) return null;
  const scale = scales(series);
  const point = (day: string, value: number): string => `${fixed(scale.x(day))} ${fixed(scale.y(value))}`;
  const groups = runs(series);
  const lines = groups.filter((g) => g.length > 1);
  const last = series.history.at(-1)!;
  const forecast = series.forecast;
  const upper = forecast.map((p) => `L ${point(p.day, p.upper)}`);
  const lower = [...forecast].reverse().map((p) => `L ${point(p.day, p.lower)}`);
  const limit = series.threshold?.value;
  return {
    width: CHART_WIDTH,
    height: CHART_HEIGHT,
    measuredPaths: lines.map((g) => `M ${g.map((p) => point(p.day, p.value)).join(' L ')}`),
    isolated: groups
      .filter((g) => g.length === 1)
      .map((g) => ({ x: scale.x(g[0].day), y: scale.y(g[0].value) })),
    forecastPath:
      forecast.length === 0
        ? null
        : `M ${point(last.day, last.value)} ${forecast.map((p) => `L ${point(p.day, p.value)}`).join(' ')}`,
    bandPath:
      forecast.length === 0
        ? null
        : `M ${point(last.day, last.value)} ${upper.join(' ')} ${lower.join(' ')} L ${point(last.day, last.value)} Z`,
    boundaryX: scale.x(last.day),
    thresholdY: limit !== undefined && limit <= scale.top ? scale.y(limit) : null,
    yTicks: yTicks(series, scale),
    xTicks: [
      { x: scale.x(series.history[0].day), label: series.history[0].day },
      ...(forecast.length === 0 ? [] : [{ x: scale.x(forecast.at(-1)!.day), label: forecast.at(-1)!.day }]),
    ],
    plot: {
      left: MARGIN.left,
      right: CHART_WIDTH - MARGIN.right,
      top: MARGIN.top,
      bottom: CHART_HEIGHT - MARGIN.bottom,
    },
  };
}
