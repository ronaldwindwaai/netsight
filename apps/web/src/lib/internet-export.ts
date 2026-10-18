import { monthOptions } from './internet-view.ts';
import { sameOrigin, type OriginPolicy } from './request-origin.ts';

/**
 * Pure rules for the read-only evidence download route (`/internet/export`): which requests are
 * accepted and which upstream headers may be relayed. The route itself only forwards the session
 * cookie to the API; the API enforces `internet:export`, the rate limit and the audit.
 */

export type ExportFormat = 'csv' | 'json';
const FORMATS: readonly ExportFormat[] = ['csv', 'json'];
const MONTH_PATTERN = /^[0-9]{4}-(0[1-9]|1[0-2])$/;
const DISPOSITION = /^attachment; filename="netsight-wan-sla-[0-9]{4}-(0[1-9]|1[0-2])\.(csv|json)"$/;
const CONTENT_TYPES: Readonly<Record<string, string>> = {
  csv: 'text/csv',
  json: 'application/json',
};

export type ExportQuery = { ok: true; month: string; format: ExportFormat } | { ok: false };

/** Exactly one `month` the server would accept and exactly one known `format`; nothing else. */
export function parseExportQuery(params: URLSearchParams, now: Date): ExportQuery {
  const months = params.getAll('month');
  const formats = params.getAll('format');
  if (months.length !== 1 || formats.length !== 1) return { ok: false };
  const [month] = months;
  const [format] = formats;
  if (!MONTH_PATTERN.test(month) || !monthOptions(now).includes(month)) return { ok: false };
  if (!FORMATS.includes(format as ExportFormat)) return { ok: false };
  return { ok: true, month, format: format as ExportFormat };
}

export function apiExportPath(month: string, format: ExportFormat): string {
  if (!MONTH_PATTERN.test(month) || !FORMATS.includes(format)) {
    throw new Error('month must be YYYY-MM and format csv or json');
  }
  return `/api/v1/internet/sla/export?month=${month}&format=${format}`;
}

/**
 * The headers to relay for a download, or null when the upstream answer is not the expected
 * attachment. Only a known content type and a fixed, anchored attachment name pass; cookies and
 * every other upstream header are dropped, and the answer is never cached or sniffed.
 */
export function safeDownloadHeaders(upstream: Headers): Headers | null {
  const type = upstream.get('content-type');
  const disposition = upstream.get('content-disposition');
  if (type === null || disposition === null) return null;
  const base = type.split(';')[0].trim().toLowerCase();
  const extension = DISPOSITION.exec(disposition)?.[2];
  if (extension === undefined || CONTENT_TYPES[extension] !== base) return null;
  const headers = new Headers();
  headers.set('content-type', type);
  headers.set('content-disposition', disposition);
  headers.set('cache-control', 'no-store');
  headers.set('x-content-type-options', 'nosniff');
  return headers;
}

/**
 * True for a request that cannot be shown to come from this application. An export is a read, but
 * it spends the identity's export rate limit and writes an audit record, so it is only ever started
 * from this application (a link here) or by typing the address.
 *
 * `Sec-Fetch-Site`, when the browser sends it, decides: `same-origin` and `none` (typed URL) pass,
 * anything else is refused. Without it (old browsers, non-browser clients, stripped headers) the
 * request must carry an `Origin` (else `Referer`) naming this very site; a request with neither is
 * refused rather than assumed safe. The same rule applies to every export route.
 */
export function isCrossSiteRequest(headers: Headers, policy: OriginPolicy): boolean {
  const site = headers.get('sec-fetch-site');
  if (site !== null) return site !== 'same-origin' && site !== 'none';
  return !sameOrigin(
    {
      host: headers.get('host'),
      forwardedHost: headers.get('x-forwarded-host'),
      forwardedProto: headers.get('x-forwarded-proto'),
      origin: headers.get('origin'),
      referer: headers.get('referer'),
    },
    policy,
  );
}
