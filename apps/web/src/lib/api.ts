import 'server-only';

import { cookies } from 'next/headers';

import { stateFromResponse } from '@/lib/api-response';
import type { FetchState, ResponseParser } from '@/lib/api-response';

export type { FetchFailureKind, FetchState, ResponseParser } from '@/lib/api-response';

const DEFAULT_API_URL = 'http://127.0.0.1:8000';
const API_TIMEOUT_MS = 10_000;
const SESSION_COOKIE = 'netsight_session';
const CSRF_HEADER = 'X-CSRF-Token';

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
    return await stateFromResponse(response, requestCorrelationId, parse);
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

export interface ApiPostOptions {
  /** Overall budget for the CSRF token fetch and the write itself, in milliseconds. */
  timeoutMs?: number;
}

/**
 * Server-side state-changing call. The API is loopback-only and its write guard
 * needs the session CSRF token, so the token is fetched with the same session
 * cookie immediately before the call (a browser-driven client could never be
 * forced to do this — it would need CORS, which the API never grants).
 */
export async function apiPost<T, B>(
  path: string,
  body: B,
  parse: ResponseParser<T>,
  options: ApiPostOptions = {},
): Promise<FetchState<T>> {
  const requestCorrelationId = crypto.randomUUID();
  const timeoutMs = options.timeoutMs ?? API_TIMEOUT_MS;
  // One deadline for the whole operation: the token fetch and the write share the budget, so a slow
  // API cannot hold a server-action worker for twice the documented timeout.
  const deadline = Date.now() + timeoutMs;
  const remainingMs = (): number => Math.max(1, deadline - Date.now());

  try {
    const session = (await cookies()).get(SESSION_COOKIE)?.value;
    if (session === undefined) {
      return {
        kind: 'unauthenticated',
        code: 'AUTHENTICATION_REQUIRED',
        message: 'A Netsight session is required.',
        correlationId: requestCorrelationId,
        status: 401,
      };
    }
    const cookieHeader = `${SESSION_COOKIE}=${encodeURIComponent(session)}`;

    const csrfResponse = await fetch(apiUrl('/api/v1/auth/csrf'), {
      cache: 'no-store',
      headers: { Accept: 'application/json', Cookie: cookieHeader },
      redirect: 'error',
      signal: AbortSignal.timeout(remainingMs()),
    });
    if (!csrfResponse.ok) {
      // Only a rejected session means "sign in again"; a server-side fault is not the user's to fix.
      if (csrfResponse.status === 401 || csrfResponse.status === 403) {
        return {
          kind: 'unauthenticated',
          code: 'AUTHENTICATION_REQUIRED',
          message: 'A Netsight session is required.',
          correlationId: requestCorrelationId,
          status: csrfResponse.status,
        };
      }
      return {
        kind: 'source_unavailable',
        code: 'TOKEN_UNAVAILABLE',
        message: 'The Netsight API could not issue a session token for this request.',
        correlationId: requestCorrelationId,
        status: csrfResponse.status,
      };
    }
    let payload: unknown;
    try {
      payload = await csrfResponse.json();
    } catch {
      payload = null;
    }
    const token = (payload as { csrf_token?: unknown } | null)?.csrf_token;
    if (typeof token !== 'string' || token.length === 0) {
      return {
        kind: 'invalid_response',
        code: 'INVALID_API_RESPONSE',
        message: 'The Netsight API returned an unusable session token.',
        correlationId: requestCorrelationId,
        status: csrfResponse.status,
      };
    }

    const response = await fetch(apiUrl(path), {
      method: 'POST',
      cache: 'no-store',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'X-Correlation-ID': requestCorrelationId,
        [CSRF_HEADER]: token,
        Cookie: cookieHeader,
      },
      body: JSON.stringify(body),
      redirect: 'error',
      signal: AbortSignal.timeout(remainingMs()),
    });
    return await stateFromResponse(response, requestCorrelationId, parse);
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
