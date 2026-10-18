import type {
  ForecastRecommendation,
  ForecastResponse,
  ForecastSeries,
} from '@/lib/api-contracts-forecast';
import { NOTICE } from '@/lib/api-contracts-forecast';

export const GB = 1e9;
export const GENERATED = '2026-10-04T06:00:00Z';

export function day(offset: number): string {
  return new Date(Date.UTC(2026, 8, 20 + offset)).toISOString().slice(0, 10);
}

export function okSeries(over: Partial<ForecastSeries> = {}): ForecastSeries {
  return {
    id: 'traffic-volume',
    name: 'Network traffic volume',
    unit: 'bytes-per-day',
    state: 'ok',
    reason: null,
    detail: null,
    source_observed_at: '2026-10-03T23:58:00Z',
    history: Array.from({ length: 14 }, (_, i) => ({ day: day(i), value: (100 + i) * GB })),
    history_missing_days: 0,
    method: {
      name: 'linear-trend',
      why: 'A straight-line trend fitted to 14 observed days (0 missing days left out).',
      observed_days: 14,
      slope_per_day: GB,
      linear_mae: 0,
      seasonal_mae: null,
      band: 'approximate-95-percent',
    },
    forecast: Array.from({ length: 7 }, (_, i) => ({
      day: day(14 + i),
      value: (114 + i) * GB,
      lower: (110 + i) * GB,
      upper: (118 + i) * GB,
    })),
    threshold: null,
    crossing: null,
    ...over,
  };
}

export function offSeries(
  id: 'wan-utilisation' | 'inventory-growth' | 'traffic-volume' = 'wan-utilisation',
  over: Partial<ForecastSeries> = {},
): ForecastSeries {
  const names = {
    'wan-utilisation': ['WAN link utilisation', 'percent'],
    'inventory-growth': ['Inventory growth', 'devices'],
    'traffic-volume': ['Network traffic volume', 'bytes-per-day'],
  } as const;
  return {
    id,
    name: names[id][0],
    unit: names[id][1],
    state: 'not-connected',
    reason: 'no-history-source',
    detail: 'No source in this deployment reports this series history.',
    source_observed_at: null,
    history: [],
    history_missing_days: 0,
    method: null,
    forecast: [],
    threshold: null,
    crossing: null,
    ...over,
  };
}

export const RECOMMENDATION: ForecastRecommendation = {
  id: 'connect-history-source-wan-utilisation',
  kind: 'connect-history-source',
  series_id: 'wan-utilisation',
  title: 'Connect a history source for wan link utilisation',
  advice: 'This cannot be forecast until a source reports its history.',
  evidence: ['No source in this deployment reports this series history.'],
  advisory: true,
  executable: false,
};

export function response(over: Partial<ForecastResponse> = {}): ForecastResponse {
  return {
    state: 'ok',
    generated_at: GENERATED,
    is_forecast: true,
    notice: NOTICE,
    horizon_days: 7,
    history_days: 14,
    history_through: '2026-10-03',
    series: [okSeries(), offSeries(), offSeries('inventory-growth')],
    recommendations: [RECOMMENDATION],
    ...over,
  };
}
