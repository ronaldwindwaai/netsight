import 'server-only';

import { headers } from 'next/headers';

import { apiPost } from '@/lib/api';
import type { ResponseParser } from '@/lib/api';
import { sameOrigin } from '@/lib/request-origin';
import { NOT_SAME_ORIGIN_MESSAGE, type WriteActionResult } from '@/lib/write-result';
import { describeWriteFailure } from '@/lib/write-outcome';

/**
 * A server action is a public POST. Its own cross-site control is asserted here rather than left
 * to the framework default: the browser's Origin (or Referer) must match the host the request was
 * addressed to. This is defence in depth in front of `apiPost`, which attaches the session cookie
 * and the CSRF token server-side; the API enforces its own origin allow-list as well.
 */
export async function fromSameOrigin(): Promise<boolean> {
  const headerList = await headers();
  const host = headerList.get('x-forwarded-host') ?? headerList.get('host');
  return sameOrigin(host, headerList.get('origin'), headerList.get('referer'));
}

export function rejected(message: string): WriteActionResult {
  return { ok: false, kind: 'rejected', message };
}

export interface PlannedWrite {
  method: 'POST' | 'PUT';
  path: string;
  body: Record<string, unknown>;
}

/**
 * Perform one planned write and describe the outcome. The response must parse against the
 * canonical contract for the record the write returns: an answer that does not is an
 * unverifiable result, never a success.
 */
export async function runWrite<T>(
  write: PlannedWrite,
  parse: ResponseParser<T>,
): Promise<WriteActionResult> {
  const state = await apiPost(write.path, write.body, parse, { method: write.method });
  if (state.kind === 'ok') return { ok: true };
  return { ok: false, kind: 'failed', failure: describeWriteFailure(state) };
}

export { NOT_SAME_ORIGIN_MESSAGE };
