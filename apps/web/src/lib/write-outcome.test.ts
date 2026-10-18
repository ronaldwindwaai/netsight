import assert from 'node:assert/strict';
import test from 'node:test';

import type { FetchState } from './api-response.ts';
import { describeWriteFailure, type WriteFailure } from './write-outcome.ts';

type Failure = Exclude<FetchState<unknown>, { kind: 'ok' }>;

function failure(partial: Partial<Failure> & Pick<Failure, 'kind'>): Failure {
  return {
    code: 'X',
    message: 'server text',
    correlationId: 'corr-1',
    status: null,
    ...partial,
  };
}

function describe(partial: Parameters<typeof failure>[0]): WriteFailure {
  return describeWriteFailure(failure(partial));
}

test('a missing or rejected session asks the operator to sign in', () => {
  const result = describe({ kind: 'unauthenticated', code: 'AUTHENTICATION_REQUIRED', status: 401 });
  assert.equal(result.category, 'sign-in');
  assert.equal(result.advice, 'sign-in');
});

test('STEP_UP_REQUIRED is distinct from a plain permission failure', () => {
  const stepUp = describe({ kind: 'forbidden', code: 'STEP_UP_REQUIRED', status: 403 });
  assert.equal(stepUp.category, 'step-up');
  assert.equal(stepUp.advice, 'step-up');
  assert.match(stepUp.message, /multi-factor/i);

  const denied = describe({ kind: 'forbidden', code: 'FORBIDDEN', status: 403 });
  assert.equal(denied.category, 'forbidden');
  assert.equal(denied.advice, 'none');
});

test('other 403 codes (CSRF, origin) are not mistaken for step-up', () => {
  for (const code of ['CSRF_VALIDATION_FAILED', 'ORIGIN_NOT_ALLOWED']) {
    const result = describe({ kind: 'forbidden', code, status: 403 });
    assert.equal(result.category, 'forbidden', code);
  }
});

test('a 409 is a conflict and tells the operator to reload before retrying', () => {
  for (const code of ['CONFLICT', 'ILLEGAL_TRANSITION']) {
    const result = describe({ kind: 'error', code, status: 409, message: 'The rule is already active' });
    assert.equal(result.category, 'conflict', code);
    assert.equal(result.advice, 'reload');
    assert.match(result.message, /already active/);
  }
});

test('a stale-evidence 409 says the evidence changed and to reload, not a generic conflict', () => {
  const result = describe({ kind: 'error', code: 'STALE_EVIDENCE', status: 409, message: 'ignored' });
  assert.equal(result.category, 'conflict');
  assert.equal(result.advice, 'reload');
  assert.match(result.message, /evidence.*changed/i);
  assert.match(result.message, /reload/i);
  assert.match(result.message, /nothing was changed/i);
});

test('a 422 is a validation failure the operator can fix', () => {
  const result = describe({ kind: 'error', code: 'VALIDATION_ERROR', status: 422 });
  assert.equal(result.category, 'invalid');
  assert.equal(result.advice, 'fix-input');
});

test('INVALID_OPERATION (422) keeps the domain explanation', () => {
  const result = describe({
    kind: 'error',
    code: 'INVALID_OPERATION',
    status: 422,
    message: 'resolution is required',
  });
  assert.equal(result.category, 'invalid');
  assert.match(result.message, /resolution is required/);
});

test('503 store failures say nothing was changed and to retry later', () => {
  for (const code of ['STORE_NOT_CONNECTED', 'STORE_UNAVAILABLE']) {
    const result = describe({ kind: 'source_unavailable', code, status: 503 });
    assert.equal(result.category, 'unavailable', code);
    assert.equal(result.advice, 'retry-later');
    assert.match(result.message, /not changed|nothing was changed/i);
  }
});

test('404 says the record no longer exists and to reload', () => {
  const result = describe({ kind: 'not_found', code: 'NOT_FOUND', status: 404 });
  assert.equal(result.category, 'not-found');
  assert.equal(result.advice, 'reload');
});

test('429 says to wait', () => {
  const result = describe({ kind: 'rate_limited', code: 'RATE_LIMITED', status: 429 });
  assert.equal(result.category, 'rate-limited');
  assert.equal(result.advice, 'retry-later');
});

test('a timeout or network failure may have applied the change, so it says reload first', () => {
  for (const code of ['API_TIMEOUT', 'API_UNAVAILABLE']) {
    const result = describe({ kind: 'error', code, status: null });
    assert.equal(result.category, 'unknown-result', code);
    assert.equal(result.advice, 'reload');
    assert.match(result.message, /may or may not/i);
  }
});

test('an unreadable or contract-violating response is an unverifiable result, not a success', () => {
  const result = describe({ kind: 'invalid_response', code: 'INVALID_API_RESPONSE', status: 200 });
  assert.equal(result.category, 'unknown-result');
  assert.equal(result.advice, 'reload');
});

test('the correlation id travels with every failure for support', () => {
  assert.equal(describe({ kind: 'error', code: 'CONFLICT', status: 409 }).correlationId, 'corr-1');
});

test('a server message is bounded and stripped of control characters before display', () => {
  const nasty = `bad\u0000\u0007 text ${'x'.repeat(2000)}`;
  const result = describe({ kind: 'error', code: 'ILLEGAL_TRANSITION', status: 409, message: nasty });
  assert.equal(/[\u0000-\u001f]/.test(result.message), false);
  assert.ok(result.message.length <= 600);
});

test('an unknown status is reported as a generic failure without leaking internals', () => {
  const result = describe({ kind: 'error', code: 'INTERNAL_ERROR', status: 500, message: 'An internal error occurred' });
  assert.equal(result.category, 'error');
  assert.equal(result.advice, 'reload');
});

test('the action kill switch is described as a stop, not as broken storage', () => {
  const result = describe({ kind: 'error', code: 'KILL_SWITCH', status: 503 });
  assert.equal(result.category, 'unavailable');
  assert.match(result.title, /stopped/i);
  assert.match(result.message, /kill switch/i);
  assert.match(result.message, /nothing was changed/i);
  assert.doesNotMatch(result.message, /store/i);
  assert.equal(result.advice, 'none');
});

test('a disabled action engine is described as not enabled, with no retry advice', () => {
  const result = describe({ kind: 'error', code: 'ACTIONS_NOT_ENABLED', status: 503 });
  assert.match(result.title, /not enabled/i);
  assert.equal(result.advice, 'none');
});

test('a stale action request tells the operator to reload and review before deciding again', () => {
  const result = describe({ kind: 'error', code: 'STALE_REQUEST', status: 409, message: 'The request changed since you looked at it; reload and review it again' });
  assert.equal(result.category, 'conflict');
  assert.equal(result.advice, 'reload');
  assert.match(result.message, /nothing was changed/i);
});
