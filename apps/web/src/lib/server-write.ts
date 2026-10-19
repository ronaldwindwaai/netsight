import 'server-only';

import { headers } from 'next/headers';

import { apiPost } from '@/lib/api';
import type { ResponseParser } from '@/lib/api';
import { readTrustProxy, sameOrigin } from '@/lib/request-origin';
import { NOT_SAME_ORIGIN_MESSAGE, type WriteActionResult } from '@/lib/write-result';
import { describeWriteFailure } from '@/lib/write-outcome';

/**
 * A server action is a public POST. Its own cross-site control is asserted here rather than left
 * to the framework default: the browser's Origin (Referer only when Origin is absent) must be
 * this very site, scheme and host. `X-Forwarded-Host` / `-Proto` count only when
 * `NETSIGHT_TRUST_PROXY_HEADERS=true` (a proxy that overwrites them). This is defence in depth in
 * front of `apiPost`, which attaches the session cookie and the CSRF token server-side; the API
 * enforces its own origin allow-list as well.
 */
export async function fromSameOrigin(): Promise<boolean> {
  const headerList = await headers();
  return sameOrigin(
    {
      host: headerList.get('host'),
      forwardedHost: headerList.get('x-forwarded-host'),
      forwardedProto: headerList.get('x-forwarded-proto'),
      origin: headerList.get('origin'),
      referer: headerList.get('referer'),
    },
    { trustProxy: readTrustProxy(process.env), production: process.env.NODE_ENV === 'production' },
  );
}

export function rejected(message: string): WriteActionResult {
  return { ok: false, kind: 'rejected', message };
}

export interface PlannedWrite {
  method: 'POST' | 'PUT';
  path: string;
  body: Record<string, unknown>;
  /** Controlled actions only: the Idempotency-Key header, already validated by the planner. */
  idempotencyKey?: string;
}

/**
 * Perform one planned write and describe the outcome. The response must parse against the
 * canonical contract for the record the write returns: an answer that does not is an
 * unverifiable result, never a success.
 */
export async function runWrite<T>(
  write: PlannedWrite,
  parse: ResponseParser<T>,
  pick?: (data: T) => { id?: string; state?: string },
): Promise<WriteActionResult> {
  const state = await apiPost(write.path, write.body, parse, {
    method: write.method,
    ...(write.idempotencyKey !== undefined ? { idempotencyKey: write.idempotencyKey } : {}),
  });
  if (state.kind === 'ok') return { ok: true, ...(pick !== undefined ? pick(state.data) : {}) };
  return { ok: false, kind: 'failed', failure: describeWriteFailure(state) };
}

export { NOT_SAME_ORIGIN_MESSAGE };
