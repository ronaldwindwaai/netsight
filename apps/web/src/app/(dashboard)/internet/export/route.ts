import { apiGetRaw } from '@/lib/api';
import { originPolicyFromEnv } from '@/lib/request-origin';
import {
  apiExportPath,
  isCrossSiteRequest,
  parseExportQuery,
  safeDownloadHeaders,
} from '@/lib/internet-export';

/**
 * Read-only evidence download for ISP disputes: `GET /internet/export?month=YYYY-MM&format=csv|json`.
 *
 * It forwards the session cookie to the API, which enforces `internet:export`, the export rate
 * limit and the audit record. The route validates the query first (a supported month, a known
 * format), refuses a request that is cross-site or that cannot show a same-site Origin/Referer, relays only a known attachment type with
 * a fixed file name, and answers failures with fixed text: nothing the API said is echoed.
 */

const TEXT_HEADERS = {
  'content-type': 'text/plain; charset=utf-8',
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
} as const;

function refusal(status: number, message: string): Response {
  return new Response(`${message}\n`, { status, headers: TEXT_HEADERS });
}

const UPSTREAM_REFUSALS: Readonly<Record<number, readonly [number, string]>> = {
  401: [401, 'Sign in to export evidence.'],
  403: [403, 'Your role cannot export WAN evidence.'],
  422: [400, 'The export request is not valid.'],
  429: [429, 'Too many exports; wait a minute and try again.'],
};

export async function GET(request: Request): Promise<Response> {
  if (isCrossSiteRequest(request.headers, originPolicyFromEnv(process.env))) {
    return refusal(403, 'Exports can only be started from Netsight.');
  }
  const query = parseExportQuery(new URL(request.url).searchParams, new Date());
  if (!query.ok) return refusal(400, 'The export request is not valid.');

  const result = await apiGetRaw(
    apiExportPath(query.month, query.format),
    query.format === 'csv' ? 'text/csv' : 'application/json',
  );
  if (!result.ok) return refusal(502, 'The Netsight API is unavailable.');
  if (result.response.status !== 200) {
    const [status, message] = UPSTREAM_REFUSALS[result.response.status] ?? [
      502,
      'The export could not be produced.',
    ];
    return refusal(status, message);
  }
  const headers = safeDownloadHeaders(result.response.headers);
  if (headers === null) return refusal(502, 'The export could not be produced.');
  return new Response(result.response.body, { status: 200, headers });
}
