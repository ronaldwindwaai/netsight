import assert from 'node:assert/strict';
import test from 'node:test';

import { apiExportPath, parseExportQuery, safeDownloadHeaders } from './forecast-export.ts';

const params = (query: string) => new URLSearchParams(query);

test('an export query is validated against the windows the page offers', () => {
  assert.deepEqual(parseExportQuery(params('horizon_days=7&history_days=28')), {
    ok: true,
    query: { horizon: 7, history: 28 },
  });
  assert.deepEqual(parseExportQuery(params('')), { ok: true, query: { horizon: 14, history: 56 } });
});

test('anything else is refused, not silently replaced', () => {
  for (const bad of [
    'horizon_days=8',
    'history_days=1000',
    'horizon_days=7&horizon_days=14',
    'horizon_days=%0d%0a',
    'extra=1',
    'horizon_days=7&history_days=x',
  ]) {
    assert.deepEqual(parseExportQuery(params(bad)), { ok: false }, bad);
  }
});

test('the API path carries only the two validated numbers', () => {
  assert.equal(
    apiExportPath({ horizon: 30, history: 90 }),
    '/api/v1/forecast/capacity/export?horizon_days=30&history_days=90',
  );
  assert.throws(() => apiExportPath({ horizon: 31, history: 90 }));
});

test('only the fixed attachment is relayed, with the other headers dropped', () => {
  const good = new Headers({
    'content-type': 'text/csv; charset=utf-8',
    'content-disposition': 'attachment; filename="netsight-capacity-forecast.csv"',
    'set-cookie': 'x=1',
  });
  const relayed = safeDownloadHeaders(good);
  assert.notEqual(relayed, null);
  assert.equal(relayed!.get('set-cookie'), null);
  assert.equal(relayed!.get('cache-control'), 'no-store');
  assert.equal(relayed!.get('x-content-type-options'), 'nosniff');
  for (const [type, disposition] of [
    ['text/html', 'attachment; filename="netsight-capacity-forecast.csv"'],
    ['text/csv', 'attachment; filename="other.csv"'],
    ['text/csv', 'inline'],
    ['application/json', 'attachment; filename="netsight-capacity-forecast.csv"'],
  ]) {
    assert.equal(
      safeDownloadHeaders(new Headers({ 'content-type': type, 'content-disposition': disposition })),
      null,
    );
  }
  assert.equal(safeDownloadHeaders(new Headers()), null);
});
