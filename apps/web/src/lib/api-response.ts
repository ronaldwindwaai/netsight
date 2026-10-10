/**
 * Pure response handling for the Netsight API client.
 *
 * Kept free of `server-only` / `next/headers` so the failure mapping and contract enforcement can be
 * unit-tested directly. `api.ts` performs the cookie-authenticated fetch and delegates the decision
 * about what a response means to these functions.
 */
import { parseApiError } from './api-contracts.ts';

export type FetchFailureKind =
  | 'unauthenticated'
  | 'forbidden'
  | 'not_found'
  | 'rate_limited'
  | 'invalid_source_data'
  | 'source_unavailable'
  | 'maintenance'
  | 'invalid_response'
  | 'error';

export type FetchState<T> =
  | { kind: 'ok'; data: T; correlationId: string }
  | {
      kind: FetchFailureKind;
      code: string;
      message: string;
      correlationId: string;
      status: number | null;
    };

export type ResponseParser<T> = (value: unknown) => T | null;

/** Map an HTTP status plus canonical error code to the UI failure class. */
export function failureKind(status: number, code: string): FetchFailureKind {
  if (status === 401) return 'unauthenticated';
  if (status === 403) return 'forbidden';
  if (status === 404) return 'not_found';
  if (status === 429 || code === 'RATE_LIMITED') return 'rate_limited';
  if (code === 'SOURCE_INVALID_DATA') return 'invalid_source_data';
  if (code === 'SOURCE_MAINTENANCE') return 'maintenance';
  if (code.startsWith('SOURCE_') || status === 502 || status === 503 || status === 504) {
    return 'source_unavailable';
  }
  return 'error';
}

/**
 * Turn a fetch response into a `FetchState`. An ok response must parse against the canonical
 * contract; an error response must carry a canonical error envelope. Anything else is an explicit
 * `invalid_response` — never a silent success.
 */
export async function stateFromResponse<T>(
  response: Response,
  requestCorrelationId: string,
  parse: ResponseParser<T>,
): Promise<FetchState<T>> {
  const correlationId = response.headers.get('x-correlation-id') ?? requestCorrelationId;
  let payload: unknown;

  try {
    payload = await response.json();
  } catch {
    return {
      kind: 'invalid_response',
      code: 'INVALID_API_RESPONSE',
      message: 'The Netsight API returned an unreadable response.',
      correlationId,
      status: response.status,
    };
  }

  if (!response.ok) {
    const error = parseApiError(payload);
    if (error === null) {
      return {
        kind: 'invalid_response',
        code: 'INVALID_API_RESPONSE',
        message: 'The Netsight API returned an invalid error response.',
        correlationId,
        status: response.status,
      };
    }
    return {
      kind: failureKind(response.status, error.code),
      code: error.code,
      message: error.message,
      correlationId: error.correlationId,
      status: response.status,
    };
  }

  const data = parse(payload);
  if (data === null) {
    return {
      kind: 'invalid_response',
      code: 'INVALID_API_RESPONSE',
      message: 'The Netsight API response did not match the canonical contract.',
      correlationId,
      status: response.status,
    };
  }

  return { kind: 'ok', data, correlationId };
}
