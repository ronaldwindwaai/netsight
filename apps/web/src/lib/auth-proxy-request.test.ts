import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import {
  buildResponseHeaders,
  buildUpstreamRequest,
  hasNoBody,
} from './auth-proxy-request.ts';

/**
 * Regression tests for the auth proxy's request translation.
 *
 * The proxy originally forwarded `body: null` for every non-GET method. That
 * was invisible while the only POSTed auth flow (logout) carried no body, and
 * broke the moment local credential sign-in posted JSON: the API received an
 * empty request and rejected it with 422, so no password sign-in could ever
 * complete through the browser.
 */

function post(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request('https://netsight.example/auth/local/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

function decode(init: { body: ArrayBuffer | undefined }): string {
  return new TextDecoder().decode(init.body as ArrayBuffer);
}

describe('buildUpstreamRequest', () => {
  test('forwards a JSON request body', async () => {
    const payload = { username: 'ops', password: 'a-strong-unique-passphrase' };
    const upstream = await buildUpstreamRequest(post(payload));

    // The body must survive the hop, or the API rejects it with 422.
    assert.ok(upstream.body, 'body was dropped');
    assert.deepEqual(JSON.parse(decode(upstream)), payload);
  });

  test('forwards the content type so the API parses the body as JSON', async () => {
    const upstream = await buildUpstreamRequest(post({ username: 'ops' }));
    assert.equal(upstream.headers.get('Content-Type'), 'application/json');
  });

  test('preserves byte content exactly', async () => {
    const payload = { challenge_id: 'xXqookw1PYEJx5TDOlFi5fvDqc', code: '012345' };
    const upstream = await buildUpstreamRequest(post(payload));
    assert.deepEqual(JSON.parse(decode(upstream)), payload);
  });

  test('preserves the method', async () => {
    const upstream = await buildUpstreamRequest(post({ username: 'ops' }));
    assert.equal(upstream.method, 'POST');
  });

  test('sends an empty body for a POST with no payload, not a dropped one', async () => {
    // An absent body and an empty body are different to the API, and logout
    // relies on the distinction being a well-formed empty request.
    const upstream = await buildUpstreamRequest(
      new Request('https://netsight.example/auth/logout', { method: 'POST' }),
    );
    assert.ok(upstream.body instanceof ArrayBuffer);
    assert.equal(upstream.body.byteLength, 0);
  });

  test('sends no body for GET', async () => {
    const upstream = await buildUpstreamRequest(
      new Request('https://netsight.example/auth/providers'),
    );
    assert.equal(upstream.method, 'GET');
    assert.equal(upstream.body, undefined);
  });

  test('forwards the CSRF token and cookies when present', async () => {
    const upstream = await buildUpstreamRequest(
      post({ a: 1 }, { 'x-csrf-token': 'token-value', cookie: 'netsight_session=abc' }),
    );
    assert.equal(upstream.headers.get('x-csrf-token'), 'token-value');
    assert.equal(upstream.headers.get('cookie'), 'netsight_session=abc');
  });

  test('normalises a correlation id casing', async () => {
    const upstream = await buildUpstreamRequest(
      post({ a: 1 }, { 'X-Correlation-ID': 'abc-123' }),
    );
    assert.equal(upstream.headers.get('X-Correlation-ID'), 'abc-123');
  });

  test('does not relay arbitrary inbound headers to the API', async () => {
    const upstream = await buildUpstreamRequest(
      post(
        { a: 1 },
        {
          'X-Forwarded-Host': 'evil.example',
          Host: 'evil.example',
          Authorization: 'Bearer leak',
          'X-Real-IP': '1.2.3.4',
        },
      ),
    );

    // Only the flow's own headers, plus the payload type.
    assert.equal(upstream.headers.get('X-Forwarded-Host'), null);
    assert.equal(upstream.headers.get('Host'), null);
    assert.equal(upstream.headers.get('Authorization'), null);
    assert.equal(upstream.headers.get('X-Real-IP'), null);
    assert.equal(upstream.headers.get('Accept'), 'application/json');
  });

  test('is not fooled by a JSON content type with a hostile charset', async () => {
    // The declared type is echoed, not reinterpreted, so a charset cannot be
    // used to smuggle a different interpretation of the same bytes.
    const upstream = await buildUpstreamRequest(
      post({ a: 1 }, { 'Content-Type': 'application/json; charset=utf-7' }),
    );
    assert.equal(upstream.headers.get('Content-Type'), 'application/json; charset=utf-7');
  });
});

describe('buildResponseHeaders', () => {
  test('passes the session cookie back so the browser stays on this origin', () => {
    const headers = buildResponseHeaders(
      new Headers({
        'Set-Cookie': 'netsight_session=abc; HttpOnly; Secure; SameSite=Lax; Path=/',
      }),
    );
    const cookie = headers.get('set-cookie') ?? '';
    assert.match(cookie, /netsight_session=abc/);
    assert.match(cookie, /HttpOnly/);
    assert.match(cookie, /Secure/);
  });

  test('relays the retry-after so the client can tell the user how long to wait', () => {
    const headers = buildResponseHeaders(new Headers({ 'Retry-After': '120' }));
    assert.equal(headers.get('Retry-After'), '120');
  });

  test('relays a redirect location for the OIDC flows', () => {
    const headers = buildResponseHeaders(new Headers({ Location: 'https://login.example/x' }));
    assert.equal(headers.get('Location'), 'https://login.example/x');
  });

  test('does not relay upstream headers that are not part of the flow', () => {
    const headers = buildResponseHeaders(
      new Headers({
        'X-Powered-By': 'uvicorn',
        Server: 'uvicorn',
        'Set-Cookie': 'a=b',
        'Content-Type': 'application/json',
      }),
    );
    assert.equal(headers.get('X-Powered-By'), null);
    assert.equal(headers.get('Server'), null);
    assert.equal(headers.get('Content-Type'), 'application/json');
  });
});

describe('hasNoBody', () => {
  test('recognises the statuses that must not carry a body', () => {
    assert.equal(hasNoBody(204), true);
    assert.equal(hasNoBody(304), true);
    assert.equal(hasNoBody(200), false);
    // 202 must keep its body: the challenge id is what the client needs.
    assert.equal(hasNoBody(202), false);
  });
});