import assert from 'node:assert/strict';
import test from 'node:test';

import {
  originOf,
  readTrustProxy,
  sameOrigin,
  type OriginPolicy,
  type RequestHeaders,
} from './request-origin.ts';

const DIRECT: OriginPolicy = { trustProxy: false, production: true };
const BEHIND_PROXY: OriginPolicy = { trustProxy: true, production: true };

function request(overrides: Partial<RequestHeaders>): RequestHeaders {
  return {
    host: 'noc.example.com',
    forwardedHost: null,
    forwardedProto: null,
    origin: null,
    referer: null,
    ...overrides,
  };
}

test('originOf extracts the lowercased scheme and host including port', () => {
  assert.deepEqual(originOf('https://NOC.example.com'), { scheme: 'https', host: 'noc.example.com' });
  assert.deepEqual(originOf('http://localhost:3000'), { scheme: 'http', host: 'localhost:3000' });
  assert.deepEqual(originOf('https://noc.example.com/some/path?q=1'), {
    scheme: 'https',
    host: 'noc.example.com',
  });
  for (const bad of [null, '', '   ', 'null', 'not a url', 'javascript:alert(1)', 'ftp://x/y']) {
    assert.equal(originOf(bad), null, String(bad));
  }
});

test('a matching Origin is accepted', () => {
  assert.equal(sameOrigin(request({ origin: 'https://noc.example.com' }), DIRECT), true);
  assert.equal(sameOrigin(request({ origin: 'https://NOC.Example.com' }), DIRECT), true);
});

test('a cross-site Origin is rejected, even with a matching Referer', () => {
  assert.equal(
    sameOrigin(
      request({ origin: 'https://evil.example', referer: 'https://noc.example.com/alerts' }),
      DIRECT,
    ),
    false,
  );
});

test('Referer is consulted only when Origin is absent', () => {
  assert.equal(
    sameOrigin(request({ referer: 'https://noc.example.com/diagnostics' }), DIRECT),
    true,
  );
  assert.equal(sameOrigin(request({ referer: 'https://evil.example/x' }), DIRECT), false);
});

test('a present but unusable Origin (null, malformed) never falls back to the Referer', () => {
  const referer = 'https://noc.example.com/alerts';
  assert.equal(sameOrigin(request({ origin: 'null', referer }), DIRECT), false);
  assert.equal(sameOrigin(request({ origin: 'garbage', referer }), DIRECT), false);
  assert.equal(sameOrigin(request({ origin: '', referer }), DIRECT), false);
});

test('neither header, or no host, is rejected', () => {
  assert.equal(sameOrigin(request({}), DIRECT), false);
  assert.equal(sameOrigin(request({ host: null, origin: 'https://noc.example.com' }), DIRECT), false);
  assert.equal(sameOrigin(request({ host: '  ', origin: 'https://noc.example.com' }), DIRECT), false);
});

test('the port is significant', () => {
  assert.equal(
    sameOrigin(request({ host: 'noc.example.com:3000', origin: 'https://noc.example.com' }), DIRECT),
    false,
  );
  assert.equal(
    sameOrigin(
      request({ host: 'noc.example.com:8443', origin: 'https://noc.example.com:8443' }),
      DIRECT,
    ),
    true,
  );
});

test('the scheme is compared: an http Origin does not match a production https site', () => {
  assert.equal(sameOrigin(request({ origin: 'http://noc.example.com' }), DIRECT), false);
});

test('outside production an http origin matches, and loopback may use http in production', () => {
  const development: OriginPolicy = { trustProxy: false, production: false };
  assert.equal(
    sameOrigin(request({ host: 'noc.example.com', origin: 'http://noc.example.com' }), development),
    true,
  );
  assert.equal(
    sameOrigin(request({ host: 'localhost:3000', origin: 'http://localhost:3000' }), DIRECT),
    true,
  );
  assert.equal(
    sameOrigin(request({ host: '127.0.0.1:3000', origin: 'http://127.0.0.1:3000' }), DIRECT),
    true,
  );
  assert.equal(
    sameOrigin(request({ host: '[::1]:3000', origin: 'http://[::1]:3000' }), DIRECT),
    true,
  );
});

test('X-Forwarded-Host is ignored unless the proxy is explicitly trusted', () => {
  const spoofed = request({
    host: 'internal:3000',
    forwardedHost: 'evil.example',
    origin: 'https://evil.example',
  });
  assert.equal(sameOrigin(spoofed, DIRECT), false);
  // Trusted: the proxy's statement decides.
  assert.equal(sameOrigin(spoofed, BEHIND_PROXY), true);
});

test('a trusted proxy that forwards the real host and scheme', () => {
  const proxied = request({
    host: 'internal:3000',
    forwardedHost: 'noc.example.com',
    forwardedProto: 'https',
    origin: 'https://noc.example.com',
  });
  assert.equal(sameOrigin(proxied, BEHIND_PROXY), true);
  assert.equal(sameOrigin({ ...proxied, origin: 'https://evil.example' }, BEHIND_PROXY), false);
  // Without trust the internal Host is what counts, so the public origin does not match.
  assert.equal(sameOrigin(proxied, DIRECT), false);
});

test('a trusted proxy uses only the first entry of a forwarded list', () => {
  const chained = request({
    host: 'internal:3000',
    forwardedHost: 'noc.example.com, evil.example',
    forwardedProto: 'https, http',
    origin: 'https://noc.example.com',
  });
  assert.equal(sameOrigin(chained, BEHIND_PROXY), true);
});

test('a trusted proxy scheme must be http or https, else the default applies', () => {
  const odd = request({
    forwardedProto: 'gopher',
    origin: 'https://noc.example.com',
  });
  assert.equal(sameOrigin(odd, BEHIND_PROXY), true);
  const httpProxy = request({
    forwardedHost: 'noc.example.com',
    forwardedProto: 'http',
    origin: 'https://noc.example.com',
  });
  assert.equal(sameOrigin(httpProxy, BEHIND_PROXY), false);
});

test('readTrustProxy is on only for the exact value true', () => {
  assert.equal(readTrustProxy({ NETSIGHT_TRUST_PROXY_HEADERS: 'true' }), true);
  for (const value of [undefined, '', 'false', '1', 'TRUE', 'yes', ' true']) {
    assert.equal(readTrustProxy({ NETSIGHT_TRUST_PROXY_HEADERS: value }), false, String(value));
  }
});
