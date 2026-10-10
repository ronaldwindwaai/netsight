import assert from 'node:assert/strict';
import test from 'node:test';

import type { SessionInfo } from './api-contracts.ts';
import { canChangeAnything, viewerFromSession } from './viewer.ts';

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
