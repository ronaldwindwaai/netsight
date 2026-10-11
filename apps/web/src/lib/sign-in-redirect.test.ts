import assert from 'node:assert/strict';
import test from 'node:test';

import {
  providerLoginHref,
  safeNextPath,
  signInHref,
  stepUpHref,
} from './sign-in-redirect.ts';

test('safeNextPath keeps same-origin absolute paths with a query', () => {
  assert.equal(safeNextPath('/incidents/abc'), '/incidents/abc');
  assert.equal(safeNextPath('/alerts?rules_offset=50'), '/alerts?rules_offset=50');
});

test('safeNextPath returns to the inventory, IPAM and unknown-device areas after a sign-in', () => {
  assert.equal(safeNextPath('/inventory?known=false'), '/inventory?known=false');
  assert.equal(safeNextPath('/ipam'), '/ipam');
  assert.equal(
    safeNextPath('/unknown-devices/unknown-device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc'),
    '/unknown-devices/unknown-device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc',
  );
});

test('safeNextPath takes the first value of a repeated parameter', () => {
  assert.equal(safeNextPath(['/alerts', '/evil']), '/alerts');
});

test('safeNextPath rejects anything that could leave the origin or smuggle a scheme', () => {
  for (const bad of [
    undefined,
    '',
    'incidents',
    '//evil.example',
    '/\\evil.example',
    '\\\\evil.example',
    'https://evil.example/',
    'javascript:alert(1)',
    '/ok\nSet-Cookie: x=1',
    '/ok\r',
    '/a\u0000b',
    `/${'a'.repeat(600)}`,
    '/%2F%2Fevil.example',
    '/\u202ehidden',
  ]) {
    assert.equal(safeNextPath(bad), null, JSON.stringify(bad));
  }
});

test('providerLoginHref forwards the destination and the step-up request', () => {
  assert.equal(providerLoginHref('/auth/login/microsoft', null, false), '/auth/login/microsoft');
  assert.equal(
    providerLoginHref('/auth/login/microsoft', '/incidents/x?after_seq=3', true),
    '/auth/login/microsoft?redirect_to=%2Fincidents%2Fx%3Fafter_seq%3D3&step_up=true',
  );
  assert.equal(
    providerLoginHref('/auth/login/google', null, true),
    '/auth/login/google?step_up=true',
  );
});

test('stepUpHref sends the operator to sign in again and back to where they were', () => {
  assert.equal(
    stepUpHref('/incidents/abc'),
    '/login?step_up=true&next=%2Fincidents%2Fabc',
  );
});

test('stepUpHref drops an unsafe return path rather than echoing it', () => {
  assert.equal(stepUpHref('//evil.example'), '/login?step_up=true');
});

test('safeNextPath only allows the dashboard areas, never the API or auth routes', () => {
  for (const good of [
    '/overview',
    '/network/map',
    '/devices/device-1',
    '/traffic',
    '/security',
    '/diagnostics',
    '/incidents/incident-1?after_seq=2#timeline',
    '/alerts',
  ]) {
    assert.equal(safeNextPath(good), good, good);
  }
  for (const bad of [
    '/',
    '/api/v1/incidents',
    '/api',
    '/auth/logout',
    '/login',
    '/_next/static/x.js',
    '/unknown',
    '/overviewx',
    '/%61pi/v1/incidents',
    '/Overview',
  ]) {
    assert.equal(safeNextPath(bad), null, bad);
  }
});

test('safeNextPath rejects a tab or newline smuggled after the first slash', () => {
  assert.equal(safeNextPath('/' + String.fromCharCode(9) + '/evil.example'), null);
  assert.equal(safeNextPath('/' + String.fromCharCode(10) + '/evil.example'), null);
  assert.equal(safeNextPath('/%09/evil.example'), null);
  assert.equal(safeNextPath('/%5Cevil.example'), null);
});

test('signInHref asks for a sign-in and returns to the current page', () => {
  assert.equal(signInHref('/incidents/abc'), '/login?next=%2Fincidents%2Fabc');
  assert.equal(signInHref('/alerts?rules_offset=50'), '/login?next=%2Falerts%3Frules_offset%3D50');
});

test('signInHref drops an unsafe or non-dashboard return path rather than echoing it', () => {
  assert.equal(signInHref('//evil.example'), '/login');
  assert.equal(signInHref('/' + String.fromCharCode(92) + 'evil.example'), '/login');
  assert.equal(signInHref('/api/v1/incidents'), '/login');
});
