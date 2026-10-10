import assert from 'node:assert/strict';
import test from 'node:test';

import { failureKind, stateFromResponse, type FetchState } from './api-response.ts';

function response(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): Response {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

test('failureKind maps the canonical status and code combinations', () => {
  assert.equal(failureKind(401, 'AUTHENTICATION_REQUIRED'), 'unauthenticated');
  assert.equal(failureKind(403, 'FORBIDDEN'), 'forbidden');
  assert.equal(failureKind(404, 'NOT_FOUND'), 'not_found');
  // A 429 with any code, and a RATE_LIMITED code with any status, are both rate limited.
  assert.equal(failureKind(429, 'ANYTHING'), 'rate_limited');
  assert.equal(failureKind(503, 'RATE_LIMITED'), 'rate_limited');
  assert.equal(failureKind(500, 'SOURCE_INVALID_DATA'), 'invalid_source_data');
  assert.equal(failureKind(500, 'SOURCE_MAINTENANCE'), 'maintenance');
  assert.equal(failureKind(500, 'SOURCE_UNAVAILABLE'), 'source_unavailable');
  assert.equal(failureKind(502, 'ANYTHING'), 'source_unavailable');
  assert.equal(failureKind(500, 'INTERNAL_ERROR'), 'error');
});

test('stateFromResponse returns ok only when the parser accepts the body', async () => {
  const parse = (value: unknown): { id: string } | null =>
    typeof value === 'object' && value !== null && typeof (value as { id?: unknown }).id === 'string'
      ? { id: (value as { id: string }).id }
      : null;

  const ok = await stateFromResponse(response(200, { id: 'abc' }, { 'x-correlation-id': 'cid-1' }), 'req-1', parse);
  assert.deepEqual(ok, { kind: 'ok', data: { id: 'abc' }, correlationId: 'cid-1' });

  // A 2xx that does not match the contract is never a silent success.
  const mismatch = await stateFromResponse(response(200, { id: 7 }), 'req-2', parse);
  assert.equal(mismatch.kind, 'invalid_response');
  assert.equal(mismatch.status, 200);
  assert.equal(mismatch.correlationId, 'req-2');
});

test('stateFromResponse maps a canonical error envelope to its failure class', async () => {
  const parse = (value: unknown): unknown => value;
  const state = await stateFromResponse(
    response(429, {
      error: { code: 'RATE_LIMITED', message: 'slow down', correlation_id: 'cid-9' },
    }),
    'req-3',
    parse,
  );
  assert.equal(state.kind, 'rate_limited');
  assert.equal(state.code, 'RATE_LIMITED');
  assert.equal(state.message, 'slow down');
  assert.equal(state.status, 429);
});

test('stateFromResponse reports an invalid error envelope and an unreadable body distinctly', async () => {
  const parse = (value: unknown): unknown => value;
  const badEnvelope = await stateFromResponse(response(500, { unexpected: true }), 'req-4', parse);
  assert.equal(badEnvelope.kind, 'invalid_response');
  assert.equal(badEnvelope.status, 500);

  const unreadable = await stateFromResponse(response(200, 'not json'), 'req-5', parse);
  assert.equal(unreadable.kind, 'invalid_response');
  assert.equal(unreadable.message, 'The Netsight API returned an unreadable response.');
});

test('the failure state shape always carries a correlation id and status', async () => {
  const parse = (value: unknown): unknown => value;
  const state: FetchState<unknown> = await stateFromResponse(
    response(403, {
      error: { code: 'FORBIDDEN', message: 'no', correlation_id: 'cid-7' },
    }),
    'req-6',
    parse,
  );
  assert.notEqual(state.kind, 'ok');
  if (state.kind !== 'ok') {
    assert.equal(state.correlationId, 'cid-7');
    assert.equal(state.status, 403);
  }
});
