/**
 * How a failed write is described to the operator.
 *
 * A write that fails is not the same as a read that fails: the operator must learn whether the
 * change was applied, whether retrying is safe, and what to do next. The categories below map
 * the API's statuses and codes (409 conflict, 422 validation, 503 store, 403 step-up ...) to
 * messages and one piece of advice the UI acts on. Pure, so every mapping is unit-tested.
 */
import type { FetchState } from './api-response.ts';

type Failure = Exclude<FetchState<unknown>, { kind: 'ok' }>;

export type WriteFailureCategory =
  | 'sign-in'
  | 'step-up'
  | 'forbidden'
  | 'not-found'
  | 'conflict'
  | 'invalid'
  | 'rate-limited'
  | 'unavailable'
  | 'unknown-result'
  | 'error';

export type WriteAdvice = 'sign-in' | 'step-up' | 'reload' | 'fix-input' | 'retry-later' | 'none';

export interface WriteFailure {
  category: WriteFailureCategory;
  title: string;
  message: string;
  advice: WriteAdvice;
  correlationId: string;
}

export const STEP_UP_CODE = 'STEP_UP_REQUIRED';
export const STALE_EVIDENCE_CODE = 'STALE_EVIDENCE';
export const KILL_SWITCH_CODE = 'KILL_SWITCH';
export const ACTIONS_NOT_ENABLED_CODE = 'ACTIONS_NOT_ENABLED';
const MAX_SERVER_MESSAGE = 500;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/g;

/** Server text is plain data: strip control characters and bound the length before display. */
function cleanServerMessage(message: string): string {
  return message.replace(CONTROL_CHARACTERS, ' ').trim().slice(0, MAX_SERVER_MESSAGE);
}

function withServerText(fallback: string, message: string): string {
  const cleaned = cleanServerMessage(message);
  return cleaned.length > 0 ? cleaned : fallback;
}

function build(
  category: WriteFailureCategory,
  title: string,
  message: string,
  advice: WriteAdvice,
  failure: Failure,
): WriteFailure {
  return { category, title, message, advice, correlationId: failure.correlationId };
}

export function describeWriteFailure(failure: Failure): WriteFailure {
  if (failure.kind === 'unauthenticated') {
    return build(
      'sign-in',
      'Sign in required',
      'Your Netsight session is missing or has expired. Nothing was changed. Sign in and try again.',
      'sign-in',
      failure,
    );
  }
  if (failure.kind === 'forbidden') {
    if (failure.code === STEP_UP_CODE) {
      return build(
        'step-up',
        'Recent multi-factor sign-in required',
        'This action needs multi-factor authentication performed recently. Nothing was changed. Sign in again, then repeat the action.',
        'step-up',
        failure,
      );
    }
    return build(
      'forbidden',
      'Not permitted',
      'The Netsight API refused this action for your role or request. Nothing was changed.',
      'none',
      failure,
    );
  }
  if (failure.kind === 'not_found') {
    return build(
      'not-found',
      'No longer found',
      'The record no longer exists or is not visible to you. Nothing was changed. Reload to see the current state.',
      'reload',
      failure,
    );
  }
  if (failure.kind === 'rate_limited') {
    return build(
      'rate-limited',
      'Too many changes',
      'Too many changes were made in a short time. Nothing was changed. Wait a minute and try again.',
      'retry-later',
      failure,
    );
  }
  if (failure.status === 409 && failure.code === STALE_EVIDENCE_CODE) {
    return build(
      'conflict',
      'The evidence changed',
      'The evidence for this finding changed after you opened it, so your decision was not applied. Nothing was changed. Reload to see the current evidence, then decide again.',
      'reload',
      failure,
    );
  }
  if (failure.status === 409) {
    return build(
      'conflict',
      'The record changed',
      withServerText(
        'The record was changed by someone else or is no longer in the expected state.',
        failure.message,
      ) + ' Nothing was changed. Reload to see the current version, then decide whether to repeat the action.',
      'reload',
      failure,
    );
  }
  if (failure.status === 422) {
    return build(
      'invalid',
      'The request was not accepted',
      withServerText('The values were rejected by validation.', failure.message) +
        ' Nothing was changed. Correct the form and try again.',
      'fix-input',
      failure,
    );
  }
  if (failure.status === 503 && failure.code === KILL_SWITCH_CODE) {
    return build(
      'unavailable',
      'Remote actions are stopped',
      'The action kill switch is engaged, so no action can be proposed, approved or run. Nothing was changed. An administrator can release it.',
      'none',
      failure,
    );
  }
  if (failure.status === 503 && failure.code === ACTIONS_NOT_ENABLED_CODE) {
    return build(
      'unavailable',
      'The action engine is not enabled',
      'This deployment has not enabled controlled actions, so nothing was stored or run. Nothing was changed.',
      'none',
      failure,
    );
  }
  if (failure.status === 503 || failure.kind === 'source_unavailable') {
    return build(
      'unavailable',
      'Storage unavailable',
      'The store behind this action is not connected or is temporarily unavailable. Nothing was changed. Try again later.',
      'retry-later',
      failure,
    );
  }
  if (failure.kind === 'invalid_response' || failure.status === null) {
    return build(
      'unknown-result',
      'Result could not be confirmed',
      'The change may or may not have been applied: the API did not return a usable answer. Reload to check the current state before repeating it.',
      'reload',
      failure,
    );
  }
  return build(
    'error',
    'The action failed',
    'The Netsight API could not complete this action. Reload to check the current state before repeating it.',
    'reload',
    failure,
  );
}
