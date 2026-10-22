import assert from 'node:assert/strict';
import test from 'node:test';

import { resolveApiBase, safeApiUrl } from './api-url.ts';

const BASE = 'http://127.0.0.1:8000';

test('accepts plain v1 paths and keeps query strings intact', () => {
  assert.equal(safeApiUrl('/api/v1/auth/session', BASE).href, 'http://127.0.0.1:8000/api/v1/auth/session');
  assert.equal(
    safeApiUrl('/api/v1/traffic/destinations?preset=24h&limit=5', BASE).href,
    'http://127.0.0.1:8000/api/v1/traffic/destinations?preset=24h&limit=5',
  );
  assert.equal(
    safeApiUrl(`/api/v1/devices/${encodeURIComponent('a b')}?page=1&page_size=50`, BASE).search,
    '?page=1&page_size=50',
  );
  assert.equal(
    safeApiUrl('/api/v1/traffic/flows?src=10.0.0.0%2F8&q=a%20b', BASE).search,
    '?src=10.0.0.0%2F8&q=a%20b',
  );
});

test('rejects traversal, encoded dot segments and non-v1 paths', () => {
  for (const bad of [
    '/api/v1/../x',
    '/api/v1/%2e%2e/x',
    '/api/v1/%2E%2E/x',
    '/api/v1/a/./b',
    '/api/v1/a/%2e/b',
    '/api/v1/..',
    '/api/v1/x/..?y=1',
    '//evil.example/api/v1/x',
    '/api/v1//evil.example',
    String.raw`/api/v1\..\x`,
    String.raw`/api/v1/a\b`,
    'http://evil.example/api/v1/x',
    'https://evil.example',
    '/api/v2/x',
    'api/v1/x',
    '/api/v1',
    '/api/v1/x#frag',
    '/api/v1/x\r\nHost: evil',
    '/api/v1/x\u0000',
    '/api/v1/x y',
    '/api/v1/x?a=b\nc',
    '/api/v1/x@evil',
  ]) {
    assert.throws(() => safeApiUrl(bad, BASE), /Only Netsight API v1 paths are allowed/, bad);
  }
});

test('rejects encoded slashes and backslashes in the path (proxy and backend decode them differently)', () => {
  for (const bad of [
    '/api/v1/a%2fb',
    '/api/v1/a%2Fb',
    '/api/v1/a%5cb',
    '/api/v1/a%5Cb',
    '/api/v1/devices/%2f..%2fadmin',
    '/api/v1/x%2F?ok=1',
    '/api/v1/a%252fb',
    '/api/v1/a%252Fb',
    '/api/v1/%252e%252e/x',
    '/api/v1/a%255cb',
    '/api/v1/a%25b',
  ]) {
    assert.throws(() => safeApiUrl(bad, BASE), /Only Netsight API v1 paths are allowed/, bad);
  }
});

test('an encoded slash in the query string stays allowed (CIDR filters)', () => {
  assert.equal(safeApiUrl('/api/v1/x?pct=100%25&q=%252f', BASE).search, '?pct=100%25&q=%252f');
  assert.equal(safeApiUrl('/api/v1/x?src=10.0.0.0%2F8&p=a%5Cb', BASE).search, '?src=10.0.0.0%2F8&p=a%5Cb');
  assert.equal(safeApiUrl('/api/v1/devices/a%20b%2e', BASE).pathname, '/api/v1/devices/a%20b%2e');
});

test('resolved URL always stays on the configured origin under /api/v1/', () => {
  const url = safeApiUrl('/api/v1/x?next=http://evil.example/', 'https://api.example.test');
  assert.equal(url.origin, 'https://api.example.test');
  assert.ok(url.pathname.startsWith('/api/v1/'));
});

test('base validation', () => {
  assert.equal(resolveApiBase(undefined).origin, 'http://127.0.0.1:8000');
  assert.throws(() => resolveApiBase('http://api.example.test'), /HTTPS/);
  assert.throws(() => resolveApiBase('https://u:p@api.example.test'), /credentials/);
  assert.throws(() => resolveApiBase('ftp://127.0.0.1'), /HTTP/);
});
