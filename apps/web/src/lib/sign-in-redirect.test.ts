import assert from 'node:assert/strict';
import test from 'node:test';

import {
  providerLoginHref,
  safeNextPath,
  stepUpHref,
} from './sign-in-redirect.ts';

test('safeNextPath keeps same-origin absolute paths with a query', () => {
  assert.equal(safeNextPath('/incidents/abc'), '/incidents/abc');
  assert.equal(safeNextPath('/alerts?rules_offset=50'), '/alerts?rules_offset=50');
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
