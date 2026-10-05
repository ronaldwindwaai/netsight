import assert from 'node:assert/strict';
import test from 'node:test';

import { resolveAuthProxyTarget } from './auth-proxy-target.ts';

function withApiUrl<T>(value: string | undefined, run: () => T): T {
  const original = process.env.NETSIGHT_API_URL;
  try {
    if (value === undefined) delete process.env.NETSIGHT_API_URL;
    else process.env.NETSIGHT_API_URL = value;
    return run();
  } finally {
    if (original === undefined) delete process.env.NETSIGHT_API_URL;
    else process.env.NETSIGHT_API_URL = original;
  }
}

test('allow-lists only the browser-driven auth paths', () => {
  for (const path of [
    'providers',
    'csrf',
    'session',
    'callback',
    'login/microsoft',
    'login/google',
    'local/login',
    'local/mfa/verify',
    'local/mfa/enroll',
    'local/mfa/activate',
    'local/password/change',
  ]) {
    assert.notEqual(resolveAuthProxyTarget(path), null, path);
  }

  for (const path of [
    '',
    'unknown',
    'devices',
    'api/v1/devices',
    '../api/v1/devices',
    'providers/../devices',
    'csrf/../../etc/passwd',
    'providers/extra',
  ]) {
    assert.equal(resolveAuthProxyTarget(path), null, path);
  }
});

test('defaults to a loopback upstream', () => {
  withApiUrl(undefined, () => {
    const target = resolveAuthProxyTarget('providers');
    assert.equal(target?.protocol, 'http:');
    assert.equal(target?.host, '127.0.0.1:8000');
    assert.equal(target?.pathname, '/api/v1/auth/providers');
  });
});

test('rejects plain-HTTP non-loopback upstreams and embedded credentials', () => {
  withApiUrl('http://api.example.test', () => {
    assert.equal(resolveAuthProxyTarget('providers'), null);
  });

  withApiUrl('https://user:pass@api.example.test', () => {
    assert.equal(resolveAuthProxyTarget('providers'), null);
  });

  withApiUrl('not-a-url', () => {
    assert.equal(resolveAuthProxyTarget('providers'), null);
  });

  withApiUrl('file:///etc/passwd', () => {
    assert.equal(resolveAuthProxyTarget('providers'), null);
  });

  withApiUrl('https://api.example.test', () => {
    const target = resolveAuthProxyTarget('csrf');
    assert.equal(target?.origin, 'https://api.example.test');
    assert.equal(target?.pathname, '/api/v1/auth/csrf');
    assert.equal(target?.username, '');
    assert.equal(target?.password, '');
  });
});