import { HISTORY_OPTIONS, HORIZON_OPTIONS, type ForecastQuery } from './forecast-view.ts';

/**
 * Pure rules for the capacity report download route (`/forecast/export`): which requests are
 * accepted and which upstream headers may be relayed. The route itself only forwards the session
 * cookie to the API; the API enforces `forecast:export`, the rate limit and the audit.
 */
const DISPOSITION = 'attachment; filename="netsight-capacity-forecast.csv"';
const DIGITS = /^[0-9]{1,3}$/;

export type ExportQuery = { ok: true; query: ForecastQuery } | { ok: false };

function one(params: URLSearchParams, name: string, options: readonly number[], fallback: number): number | null {
  const values = params.getAll(name);
  if (values.length === 0) return fallback;
  if (values.length > 1 || !DIGITS.test(values[0]) || !options.includes(Number(values[0]))) return null;
  return Number(values[0]);
}

/** At most one of each known parameter, each one of the offered windows; nothing else. */
export function parseExportQuery(params: URLSearchParams): ExportQuery {
  if ([...params.keys()].some((name) => name !== 'horizon_days' && name !== 'history_days')) {
    return { ok: false };
  }
  const horizon = one(params, 'horizon_days', HORIZON_OPTIONS, 14);
  const history = one(params, 'history_days', HISTORY_OPTIONS, 56);
  return horizon === null || history === null ? { ok: false } : { ok: true, query: { horizon, history } };
}

export function apiExportPath(query: ForecastQuery): string {
  if (!HORIZON_OPTIONS.some((n) => n === query.horizon) || !HISTORY_OPTIONS.some((n) => n === query.history)) {
    throw new Error('horizon and history must be offered windows');
  }
  return `/api/v1/forecast/capacity/export?horizon_days=${query.horizon}&history_days=${query.history}`;
}

/**
 * The headers to relay for the download, or null when the upstream answer is not the expected
 * attachment. Only text/csv with the fixed file name passes; cookies and every other upstream
 * header are dropped, and the answer is never cached or sniffed.
 */
export function safeDownloadHeaders(upstream: Headers): Headers | null {
  const type = upstream.get('content-type');
  if (type === null || type.split(';')[0].trim().toLowerCase() !== 'text/csv') return null;
  if (upstream.get('content-disposition') !== DISPOSITION) return null;
  const headers = new Headers();
  headers.set('content-type', type);
  headers.set('content-disposition', DISPOSITION);
  headers.set('cache-control', 'no-store');
  headers.set('x-content-type-options', 'nosniff');
  return headers;
}
