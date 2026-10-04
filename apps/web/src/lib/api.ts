import 'server-only';

import { cookies } from 'next/headers';

import { parseApiError } from '@/lib/api-contracts';

const DEFAULT_API_URL = 'http://127.0.0.1:8000';
const API_TIMEOUT_MS = 10_000;
const SESSION_COOKIE = 'netsight_session';

export type FetchFailureKind =
  | 'unauthenticated'
  | 'forbidden'
  | 'not_found'
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

function apiUrl(path: string): URL {
  if (!path.startsWith('/api/v1/') || path.startsWith('//')) {
    throw new Error('Only Netsight API v1 paths are allowed');
  }

  const base = new URL(process.env.NETSIGHT_API_URL ?? DEFAULT_API_URL);
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password) {
    throw new Error('NETSIGHT_API_URL must be an HTTP(S) URL without embedded credentials');
  }
  const isLoopback = ['127.0.0.1', '::1', '[::1]', 'localhost'].includes(base.hostname);
  if (base.protocol !== 'https:' && !isLoopback) {
    throw new Error('NETSIGHT_API_URL must use HTTPS unless it targets loopback');
  }
  const resolved = new URL(path, `${base.toString().replace(/\/$/, '')}/`);
  if (resolved.origin !== base.origin || !resolved.pathname.startsWith('/api/v1/')) {
    throw new Error('Only Netsight API v1 paths are allowed');
  }
  return resolved;
}

function failureKind(status: number, code: string): FetchFailureKind {
  if (status === 401) return 'unauthenticated';
  if (status === 403) return 'forbidden';
  if (status === 404) return 'not_found';
  if (code === 'SOURCE_INVALID_DATA') return 'invalid_source_data';
  if (code === 'SOURCE_MAINTENANCE') return 'maintenance';
  if (code.startsWith('SOURCE_') || status === 502 || status === 503 || status === 504) {
    return 'source_unavailable';
  }
  return 'error';
}

export async function apiGet<T>(path: string, parse: ResponseParser<T>): Promise<FetchState<T>> {
  const requestCorrelationId = crypto.randomUUID();

  try {
    const session = (await cookies()).get(SESSION_COOKIE)?.value;
    const response = await fetch(apiUrl(path), {
      cache: 'no-store',
      headers: {
        Accept: 'application/json',
        'X-Correlation-ID': requestCorrelationId,
        ...(session ? { Cookie: `${SESSION_COOKIE}=${encodeURIComponent(session)}` } : {}),
      },
      redirect: 'error',
      signal: AbortSignal.timeout(API_TIMEOUT_MS),
    });
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
  } catch (error) {
    return {
      kind: 'error',
      code: error instanceof Error && error.name === 'TimeoutError' ? 'API_TIMEOUT' : 'API_UNAVAILABLE',
      message:
        error instanceof Error && error.name === 'TimeoutError'
          ? 'The Netsight API did not respond in time.'
          : 'The Netsight API is unavailable.',
      correlationId: requestCorrelationId,
      status: null,
    };
  }
}
