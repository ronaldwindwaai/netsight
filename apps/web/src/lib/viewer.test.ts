import assert from 'node:assert/strict';
import test from 'node:test';

import type { SessionInfo } from './api-contracts.ts';
import {
  canChangeAnything,
  canExportInternet,
  canReadInternet,
  canReadPeople,
  canReadUsersSummary,
  canResolveIdentity,
  canUseDiagnostics,
  viewerFromSession,
} from './viewer.ts';

function session(permissions: string[]): SessionInfo {
  return {
    authenticated: true,
    identity_id: 'microsoft:ana',
    provider: 'microsoft',
    email: null,
    roles: ['x'],
    permissions,
  };
}

test('a session becomes a viewer with its identity and reported permissions', () => {
  assert.deepEqual(viewerFromSession(session(['incidents:read'])), {
    identityId: 'microsoft:ana',
    permissions: ['incidents:read'],
  });
});

test('no session is no viewer', () => {
  assert.equal(viewerFromSession(null), null);
});

test('the viewer is detached from the session object', () => {
  const info = session(['incidents:read']);
  const viewer = viewerFromSession(info);
  info.permissions.push('incidents:resolve');
  assert.deepEqual(viewer?.permissions, ['incidents:read']);
});

test('read-only roles cannot change anything; any write permission can', () => {
  assert.equal(canChangeAnything(null), false);
  assert.equal(canChangeAnything(viewerFromSession(session(['incidents:read', 'alert-rules:read']))), false);
  assert.equal(canChangeAnything(viewerFromSession(session(['incidents:read-summary', 'audit:read']))), false);
  for (const permission of [
    'incidents:transition',
    'incidents:assign',
    'incidents:comment',
    'incidents:resolve',
    'incidents:reopen',
    'incidents:write-assigned',
    'alert-rules:write',
    'alert-rules:approve',
    'alert-rules:disable',
    'maintenance:write',
    'maintenance:write-organisation',
  ]) {
    assert.equal(canChangeAnything(viewerFromSession(session([permission]))), true, permission);
  }
});

test('diagnostics are available only to a viewer holding diagnostics:read', () => {
  assert.equal(canUseDiagnostics(null), false);
  assert.equal(canUseDiagnostics(viewerFromSession(session([]))), false);
  // Management and Auditor read other things but hold no diagnostics permission.
  assert.equal(canUseDiagnostics(viewerFromSession(session(['incidents:read-summary', 'audit:read']))), false);
  assert.equal(canUseDiagnostics(viewerFromSession(session(['diagnostics:read']))), true);
});

test('the Internet permissions are read from the session and fail closed', () => {
  const reader = viewerFromSession(session(['internet:read']));
  const exporter = viewerFromSession(session(['internet:read', 'internet:export']));
  assert.equal(canReadInternet(reader), true);
  assert.equal(canExportInternet(reader), false);
  assert.equal(canExportInternet(exporter), true);
  assert.equal(canReadInternet(viewerFromSession(session(['incidents:read']))), false);
  assert.equal(canReadInternet(null), false);
  assert.equal(canExportInternet(null), false);
});

test('the users helpers follow the permission ladder and fail closed without a viewer', () => {
  const full = viewerFromSession(session(['users:read', 'users:read-limited', 'users:read-summary']));
  const limited = viewerFromSession(session(['users:read-limited', 'users:read-summary']));
  const summary = viewerFromSession(session(['users:read-summary']));
  assert.deepEqual([canReadPeople(full), canResolveIdentity(full), canReadUsersSummary(full)], [true, true, true]);
  assert.deepEqual([canReadPeople(limited), canResolveIdentity(limited), canReadUsersSummary(limited)], [false, true, true]);
  assert.deepEqual([canReadPeople(summary), canResolveIdentity(summary), canReadUsersSummary(summary)], [false, false, true]);
  assert.deepEqual([canReadPeople(null), canResolveIdentity(null), canReadUsersSummary(null)], [false, false, false]);
});
