import assert from 'node:assert/strict';
import test from 'node:test';

import {
  apiExportPath,
  isCrossSiteRequest,
  parseExportQuery,
  safeDownloadHeaders,
} from './internet-export.ts';

const NOW = new Date('2026-10-11T12:00:00Z');

function query(text: string): URLSearchParams {
  return new URLSearchParams(text);
}

test('a valid month and format are accepted', () => {
  assert.deepEqual(parseExportQuery(query('month=2026-09&format=csv'), NOW), {
    ok: true,
    month: '2026-09',
    format: 'csv',
  });
  assert.deepEqual(parseExportQuery(query('month=2026-10&format=json'), NOW), {
    ok: true,
    month: '2026-10',
    format: 'json',
  });
});

test('anything else is refused before any API call', () => {
  for (const text of [
    '',
    'month=2026-09',
    'format=csv',
    'month=2026-11&format=csv',
    'month=2024-09&format=csv',
    'month=2026-09&format=xml',
    'month=2026-09&format=CSV',
    'month=2026-09&format=csv&format=json',
    'month=2026-09&month=2026-08&format=csv',
    'month=2026-09%0d%0aSet-Cookie:a=b&format=csv',
    'month=../../auth/session&format=csv',
    'month=2026-09&format=csv%0d%0a',
  ]) {
    assert.deepEqual(parseExportQuery(query(text), NOW), { ok: false }, text);
  }
});

test('the API path is built only from validated parts', () => {
  assert.equal(
    apiExportPath('2026-09', 'csv'),
    '/api/v1/internet/sla/export?month=2026-09&format=csv',
  );
  assert.throws(() => apiExportPath('2026-09&x=1', 'csv'));
});

test('a download is passed through only with a known type and a fixed attachment name', () => {
  const headers = safeDownloadHeaders(
    new Headers({
      'content-type': 'text/csv; charset=utf-8',
      'content-disposition': 'attachment; filename="netsight-wan-sla-2026-09.csv"',
    }),
  );
  assert.ok(headers);
  assert.equal(headers.get('content-type'), 'text/csv; charset=utf-8');
  assert.equal(headers.get('content-disposition'), 'attachment; filename="netsight-wan-sla-2026-09.csv"');
  assert.equal(headers.get('cache-control'), 'no-store');
  assert.equal(headers.get('x-content-type-options'), 'nosniff');
  assert.equal(headers.has('set-cookie'), false);
});

test('the JSON download keeps its type', () => {
  const headers = safeDownloadHeaders(
    new Headers({
      'content-type': 'application/json',
      'content-disposition': 'attachment; filename="netsight-wan-sla-2026-09.json"',
    }),
  );
  assert.equal(headers?.get('content-type'), 'application/json');
});

test('an unexpected type or disposition is refused, not relayed', () => {
  const bad: Array<Record<string, string>> = [
    { 'content-type': 'text/html', 'content-disposition': 'attachment; filename="netsight-wan-sla-2026-09.csv"' },
    { 'content-type': 'text/csv', 'content-disposition': 'inline' },
    { 'content-type': 'text/csv', 'content-disposition': 'attachment; filename="../../x.csv"' },
    { 'content-type': 'text/csv', 'content-disposition': 'attachment; filename="netsight-wan-sla-2026-09.exe"' },
    { 'content-type': 'text/csv' },
    { 'content-disposition': 'attachment; filename="netsight-wan-sla-2026-09.csv"' },
  ];
  for (const init of bad) {
    assert.equal(safeDownloadHeaders(new Headers(init)), null, JSON.stringify(init));
  }
});

const POLICY = { trustProxy: false, production: true };
const HOST = 'noc.example.com';

test('a cross-site request cannot trigger an export (it would spend the identity rate limit and audit trail)', () => {
  const blocked = (init: Record<string, string>) =>
    isCrossSiteRequest(new Headers({ host: HOST, ...init }), POLICY);
  assert.equal(blocked({ 'sec-fetch-site': 'cross-site' }), true);
  assert.equal(blocked({ 'sec-fetch-site': 'same-site' }), true);
  assert.equal(blocked({ 'sec-fetch-site': 'same-origin' }), false);
  assert.equal(blocked({ 'sec-fetch-site': 'none' }), false); // typed URL
});

test('a request with no Sec-Fetch-Site must carry a matching Origin or Referer', () => {
  const blocked = (init: Record<string, string>) =>
    isCrossSiteRequest(new Headers({ host: HOST, ...init }), POLICY);
  assert.equal(blocked({}), true); // no signal at all: refused, not assumed safe
  assert.equal(blocked({ origin: 'https://evil.example' }), true);
  assert.equal(blocked({ origin: 'null' }), true);
  assert.equal(blocked({ referer: 'https://evil.example/x' }), true);
  assert.equal(blocked({ origin: 'https://evil.example', referer: `https://${HOST}/x` }), true);
  assert.equal(blocked({ origin: `https://${HOST}` }), false);
  assert.equal(blocked({ referer: `https://${HOST}/internet` }), false);
});

test('Sec-Fetch-Site cross-site is refused even when a matching Origin is present', () => {
  const headers = new Headers({ host: HOST, 'sec-fetch-site': 'cross-site', origin: `https://${HOST}` });
  assert.equal(isCrossSiteRequest(headers, POLICY), true);
});
