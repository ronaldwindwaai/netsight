import assert from 'node:assert/strict';
import test from 'node:test';

import type { ForecastPoint, ForecastSeries, HistoryPoint } from './api-contracts-forecast.ts';
import {
  buildChart,
  describeSeries,
  exportPath,
  forecastPath,
  formatAmount,
  parseForecastQuery,
  reasonText,
  statePresentation,
  tableRows,
} from './forecast-view.ts';

const GB = 1e9;

function day(offset: number): string {
  return new Date(Date.UTC(2026, 8, 20 + offset)).toISOString().slice(0, 10);
}

function history(days: number[], value = (i: number) => (100 + i) * GB): HistoryPoint[] {
  return days.map((d, i) => ({ day: day(d), value: value(i) }));
}

function projection(from: number, count: number): ForecastPoint[] {
  return Array.from({ length: count }, (_, i) => ({
    day: day(from + i),
    value: (140 + i) * GB,
    lower: (130 + i) * GB,
    upper: (150 + i) * GB,
  }));
}

function series(over: Partial<ForecastSeries> = {}): ForecastSeries {
  const measured = history(Array.from({ length: 14 }, (_, i) => i));
  return {
    id: 'traffic-volume',
    name: 'Network traffic volume',
    unit: 'bytes-per-day',
    state: 'ok',
    reason: null,
    detail: null,
    source_observed_at: '2026-10-03T23:58:00Z',
    history: measured,
    history_missing_days: 0,
    method: {
      name: 'linear-trend',
      why: 'A straight-line trend fitted to 14 observed days (0 missing days left out).',
      observed_days: 14,
      slope_per_day: 1 * GB,
      linear_mae: 0,
      seasonal_mae: null,
      band: 'approximate-95-percent',
    },
    forecast: projection(14, 7),
    threshold: null,
    crossing: null,
    ...over,
  };
}

test('query: only the offered windows are accepted, anything else is the default', () => {
  assert.deepEqual(parseForecastQuery({}), { horizon: 14, history: 56 });
  assert.deepEqual(parseForecastQuery({ horizon_days: '30', history_days: '90' }), {
    horizon: 30,
    history: 90,
  });
  assert.deepEqual(parseForecastQuery({ horizon_days: '31', history_days: 'x' }), {
    horizon: 14,
    history: 56,
  });
  assert.deepEqual(parseForecastQuery({ horizon_days: ['7', '30'] }), { horizon: 7, history: 56 });
});

test('paths carry only validated numbers', () => {
  const query = parseForecastQuery({ horizon_days: '7', history_days: '28' });
  assert.equal(forecastPath(query), '/api/v1/forecast/capacity?horizon_days=7&history_days=28');
  assert.equal(exportPath(query), '/forecast/export?horizon_days=7&history_days=28');
});

test('every state has a word, an icon and a meaning (never colour alone)', () => {
  for (const state of ['ok', 'insufficient-data', 'not-connected', 'unknown'] as const) {
    const view = statePresentation(state);
    assert.ok(view.label.length > 0 && view.icon.startsWith('bi-') && view.explanation.length > 20);
  }
  assert.notEqual(statePresentation('unknown').label, statePresentation('not-connected').label);
});

test('every reason has plain text', () => {
  for (const reason of [
    'no-source',
    'no-history-source',
    'source-unreadable',
    'too-few-days',
    'too-many-gaps',
    'history-stale',
    'horizon-too-long',
  ] as const) {
    assert.ok(reasonText(reason).length > 10);
  }
});

test('amounts are written for a person', () => {
  assert.equal(formatAmount(129 * GB, 'bytes-per-day'), '129.0 GB/day');
  assert.equal(formatAmount(950, 'bytes-per-day'), '950 B/day');
  assert.equal(formatAmount(12, 'percent'), '12 %');
  assert.equal(formatAmount(1, 'devices'), '1 device');
  assert.equal(formatAmount(40, 'devices'), '40 devices');
});

test('the chart has measured, forecast and band geometry inside its box', () => {
  const chart = buildChart(series());
  assert.notEqual(chart, null);
  if (chart === null) return;
  assert.equal(chart.measuredPaths.length, 1);
  assert.ok(chart.forecastPath !== null && chart.bandPath !== null);
  const numbers = [chart.measuredPaths[0], chart.forecastPath, chart.bandPath].join(' ').match(/-?\d+(\.\d+)?/g) ?? [];
  for (const n of numbers) assert.ok(Number.isFinite(Number(n)));
  assert.ok(chart.boundaryX > 0 && chart.boundaryX < chart.width);
  assert.ok(chart.yTicks.at(-1)!.value >= 150 * GB);
  assert.equal(chart.yTicks[0].value, 0);
});

test('a gap in the measured days breaks the line, it is never bridged', () => {
  const days = [0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 13, 14, 15, 16];
  const chart = buildChart(series({ history: history(days), forecast: projection(17, 7) }))!;
  assert.equal(chart.measuredPaths.length, 2);
});

test('an isolated measured day is still drawn', () => {
  const days = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 20];
  const chart = buildChart(series({ history: history(days), forecast: projection(21, 7) }))!;
  assert.equal(chart.isolated.length, 1);
});

test('a series that is not ok has no forecast line and no band', () => {
  const chart = buildChart(
    series({ state: 'insufficient-data', reason: 'too-few-days', detail: 'x', method: null, forecast: [] }),
  )!;
  assert.equal(chart.forecastPath, null);
  assert.equal(chart.bandPath, null);
  assert.equal(buildChart(series({ state: 'not-connected', history: [], forecast: [], method: null, reason: 'no-source', detail: 'x' })), null);
});

test('a limit near the data is drawn; a far-away limit is only stated', () => {
  const near = buildChart(series({ threshold: { value: 160 * GB, basis: 'operator-configured' }, crossing: { point_day: null, upper_day: null } }))!;
  assert.notEqual(near.thresholdY, null);
  const far = buildChart(series({ threshold: { value: 5000 * GB, basis: 'operator-configured' }, crossing: { point_day: null, upper_day: null } }))!;
  assert.equal(far.thresholdY, null);
});

test('the text alternative states what is measured and what is forecast', () => {
  const text = describeSeries(series());
  assert.match(text, /Measured: 14 days/);
  assert.match(text, /Forecast, not measured: 7 days/);
  assert.match(text, /linear trend/i);
  assert.match(text, /approximate 95 %/);
  assert.match(text, /113\.0 GB\/day/); // latest measured
});

test('the text alternative of a series without a forecast says why', () => {
  const text = describeSeries(
    series({ state: 'insufficient-data', reason: 'too-few-days', detail: '9 observed days', method: null, forecast: [] }),
  );
  assert.match(text, /No forecast/);
  assert.match(text, /9 observed days/);
});

test('the data table labels every row measured or forecast', () => {
  const rows = tableRows(series());
  assert.equal(rows.filter((r) => r.kind === 'measured').length, 14);
  assert.equal(rows.filter((r) => r.kind === 'forecast').length, 7);
  const forecast = rows.find((r) => r.kind === 'forecast')!;
  assert.ok(forecast.range !== null && rows.find((r) => r.kind === 'measured')!.range === null);
});

test('an amount never rounds up to 1000 of a smaller unit', () => {
  assert.equal(formatAmount(999_949, 'bytes-per-day'), '999.9 kB/day');
  assert.equal(formatAmount(999_950, 'bytes-per-day'), '1.0 MB/day');
  assert.equal(formatAmount(999_950_000_000, 'bytes-per-day'), '1.0 TB/day');
  assert.equal(formatAmount(999, 'bytes-per-day'), '999 B/day');
});
