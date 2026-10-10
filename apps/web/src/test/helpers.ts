import assert from 'node:assert/strict';

import type { WriteFailureCategory } from '@/lib/write-outcome';
import type { FetchState } from '@/lib/api-response';
import { describeWriteFailure } from '@/lib/write-outcome';
import type { WriteActionResult } from '@/lib/write-result';
import type { Viewer } from '@/lib/incident-actions';

/** A promise settled from outside, to hold a server action in flight. */
export function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: unknown) => void;
} {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((onResolve, onReject) => {
    resolve = onResolve;
    reject = onReject;
  });
  return { promise, resolve, reject };
}

type Failure = Exclude<FetchState<unknown>, { kind: 'ok' }>;

/** A failed write as the server action reports it, built from an API-style failure. */
export function failedWrite(failure: Failure): WriteActionResult {
  return { ok: false, kind: 'failed', failure: describeWriteFailure(failure) };
}

const CORRELATION_ID = 'corr-123';

/** The failures the API produces, keyed by what the operator is meant to learn from them. */
export const FAILURES: Record<string, { failure: Failure; category: WriteFailureCategory }> = {
  conflict: {
    category: 'conflict',
    failure: { kind: 'error', code: 'CONFLICT', message: 'Incident moved on.', correlationId: CORRELATION_ID, status: 409 },
  },
  invalid: {
    category: 'invalid',
    failure: { kind: 'error', code: 'VALIDATION', message: 'Summary is too long.', correlationId: CORRELATION_ID, status: 422 },
  },
  unavailable: {
    category: 'unavailable',
    failure: { kind: 'error', code: 'UNAVAILABLE', message: '', correlationId: CORRELATION_ID, status: 503 },
  },
  unauthenticated: {
    category: 'sign-in',
    failure: { kind: 'unauthenticated', code: 'AUTHENTICATION_REQUIRED', message: '', correlationId: CORRELATION_ID, status: 401 },
  },
  rateLimited: {
    category: 'rate-limited',
    failure: { kind: 'rate_limited', code: 'RATE_LIMITED', message: '', correlationId: CORRELATION_ID, status: 429 },
  },
  stepUp: {
    category: 'step-up',
    failure: { kind: 'forbidden', code: 'STEP_UP_REQUIRED', message: '', correlationId: CORRELATION_ID, status: 403 },
  },
  forbidden: {
    category: 'forbidden',
    failure: { kind: 'forbidden', code: 'FORBIDDEN', message: '', correlationId: CORRELATION_ID, status: 403 },
  },
  unknownResult: {
    category: 'unknown-result',
    failure: { kind: 'error', code: 'API_UNAVAILABLE', message: '', correlationId: CORRELATION_ID, status: null },
  },
};

export const CORRELATION = CORRELATION_ID;

const READ = ['incidents:read', 'incidents:read-summary', 'alert-rules:read', 'maintenance:read'];

/** Viewers with the permission sets the API grants each role (apps/api/src/netsight_api/rbac.py). */
export const VIEWERS: Record<string, Viewer> = {
  administrator: {
    identityId: 'microsoft:admin',
    permissions: [
      ...READ,
      'incidents:transition',
      'incidents:assign',
      'incidents:comment',
      'incidents:resolve',
      'incidents:reopen',
      'alert-rules:write',
      'alert-rules:approve',
      'alert-rules:disable',
      'maintenance:write',
      'maintenance:write-organisation',
    ],
  },
  technician: {
    identityId: 'microsoft:tech',
    permissions: ['incidents:read', 'incidents:read-summary', 'incidents:write-assigned'],
  },
  management: {
    identityId: 'microsoft:manager',
    permissions: ['incidents:read-summary', 'alert-rules:read', 'maintenance:read'],
  },
  auditor: {
    identityId: 'microsoft:auditor',
    permissions: [...READ, 'audit:read'],
  },
};

/** Asserts absence without handing a DOM node to the assertion (a failure would dump the whole tree). */
export function assertAbsent(element: Element | null, message = 'expected no matching element'): void {
  assert.equal(element === null ? 'absent' : element.outerHTML.slice(0, 200), 'absent', message);
}

/** Asserts which element has focus, describing both by markup instead of dumping the document. */
export function assertFocus(expected: Element | null): void {
  const describe = (element: Element | null): string =>
    element === null ? 'nothing' : element.outerHTML.slice(0, 120);
  assert.equal(describe(document.activeElement), describe(expected), 'unexpected focus');
}
