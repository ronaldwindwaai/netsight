import 'server-only';

import { cookies } from 'next/headers';

import { stateFromResponse } from '@/lib/api-response';
import type { FetchState, ResponseParser } from '@/lib/api-response';
import { isSafeApiPath, resolveApiBase, safeApiUrl } from '@/lib/api-url';

export type { FetchFailureKind, FetchState, ResponseParser } from '@/lib/api-response';

const API_TIMEOUT_MS = 10_000;
const SESSION_COOKIE = 'netsight_session';
const CSRF_HEADER = 'X-CSRF-Token';

/**
 * The single egress point to the Netsight API. The path is checked against a strict allowlist
 * (`isSafeApiPath`) and the final URL is re-checked against the configured API origin immediately
 * before `fetch`, so no caller-supplied value can steer the request to another host or path.
 */
async function apiFetch(path: string, init: RequestInit): Promise<Response> {
  if (!isSafeApiPath(path) || !path.startsWith('/api/v1/')) {
    throw new Error('Only Netsight API v1 paths are allowed');
  }
  const base = resolveApiBase(process.env.NETSIGHT_API_URL);
  const target = safeApiUrl(path, process.env.NETSIGHT_API_URL).href;
  if (!target.startsWith(`${base.origin}/api/v1/`)) {
    throw new Error('Only Netsight API v1 paths are allowed');
  }
  return fetch(target, init);
}

export async function apiGet<T>(path: string, parse: ResponseParser<T>): Promise<FetchState<T>> {
  const requestCorrelationId = crypto.randomUUID();

  try {
    const session = (await cookies()).get(SESSION_COOKIE)?.value;
    const response = await apiFetch(path, {
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

export type RawGetResult =
  | { ok: true; response: Response; correlationId: string }
  | { ok: false; status: number | null; correlationId: string };

/**
 * Cookie-authenticated GET that hands back the raw response (a file download). Only the status is
 * ever relayed on failure: nothing the upstream said is surfaced. Same path rules as `apiGet`.
 */
export async function apiGetRaw(path: string, accept: string): Promise<RawGetResult> {
  const correlationId = crypto.randomUUID();
  try {
    const session = (await cookies()).get(SESSION_COOKIE)?.value;
    const response = await apiFetch(path, {
      cache: 'no-store',
      headers: {
        Accept: accept,
        'X-Correlation-ID': correlationId,
        ...(session ? { Cookie: `${SESSION_COOKIE}=${encodeURIComponent(session)}` } : {}),
      },
      redirect: 'error',
      signal: AbortSignal.timeout(API_TIMEOUT_MS),
    });
    return { ok: true, response, correlationId };
  } catch {
    return { ok: false, status: null, correlationId };
  }
}

export interface ApiPostOptions {
  /** Overall budget for the CSRF token fetch and the write itself, in milliseconds. */
  timeoutMs?: number;
  /** HTTP verb of the state-changing call; defaults to POST (PUT for full-replacement edits). */
  method?: 'POST' | 'PUT';
  /** Sent as the Idempotency-Key header (controlled actions: a retry returns the first result). */
  idempotencyKey?: string;
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

    const csrfResponse = await apiFetch('/api/v1/auth/csrf', {
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

    const response = await apiFetch(path, {
      method: options.method ?? 'POST',
      cache: 'no-store',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'X-Correlation-ID': requestCorrelationId,
        [CSRF_HEADER]: token,
        ...(options.idempotencyKey !== undefined ? { 'Idempotency-Key': options.idempotencyKey } : {}),
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
