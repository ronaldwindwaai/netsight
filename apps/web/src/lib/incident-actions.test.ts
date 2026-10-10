import assert from 'node:assert/strict';
import test from 'node:test';

import {
  availableIncidentActions,
  planIncidentRequest,
  type ActionAvailability,
  type IncidentActionName,
  type Viewer,
} from './incident-actions.ts';
import type { IncidentState } from './api-contracts-incident.ts';

const ID = 'incident-3f2b8a40-1c2d-4e5f-8a9b-0c1d2e3f4a5b';
const NOW = Date.parse('2026-10-10T12:00:00Z');

const FULL: Viewer = {
  identityId: 'microsoft:lead',
  permissions: [
    'incidents:read',
    'incidents:transition',
    'incidents:assign',
    'incidents:comment',
    'incidents:resolve',
    'incidents:reopen',
  ],
};
const TECHNICIAN: Viewer = {
  identityId: 'microsoft:tech',
  permissions: ['incidents:read', 'incidents:write-assigned'],
};
const AUDITOR: Viewer = { identityId: 'microsoft:aud', permissions: ['incidents:read'] };

function actions(
  state: IncidentState,
  viewer: Viewer | null,
  assignee: string | null = null,
): Record<IncidentActionName, ActionAvailability> {
  const list = availableIncidentActions({ state, assignee_id: assignee }, viewer);
  return Object.fromEntries(list.map((item) => [item.action, item])) as Record<
    IncidentActionName,
    ActionAvailability
  >;
}

test('every action is always listed, in a stable order, so a disabled one can explain itself', () => {
  const list = availableIncidentActions({ state: 'open', assignee_id: null }, FULL);
  assert.deepEqual(
    list.map((item) => item.action),
    ['acknowledge', 'progress', 'assign', 'comment', 'resolve', 'reopen'],
  );
});

test('a full role can act exactly where the state machine allows', () => {
  assert.equal(actions('open', FULL).acknowledge.enabled, true);
  assert.equal(actions('open', FULL).progress.enabled, false);
  assert.equal(actions('acknowledged', FULL).progress.enabled, true);
  assert.equal(actions('investigating', FULL).progress.enabled, true);
  assert.equal(actions('mitigated', FULL).progress.enabled, false);
  assert.equal(actions('mitigated', FULL).resolve.enabled, true);
  assert.equal(actions('open', FULL).resolve.enabled, false);
  assert.equal(actions('resolved', FULL).reopen.enabled, true);
  assert.equal(actions('closed', FULL).reopen.enabled, true);
  assert.equal(actions('open', FULL).reopen.enabled, false);
});

test('progress is labelled with the step it performs', () => {
  assert.equal(actions('acknowledged', FULL).progress.label, 'Mark investigating');
  assert.equal(actions('investigating', FULL).progress.label, 'Mark mitigated');
});

test('assign and comment need only the permission, in any state', () => {
  for (const state of ['open', 'mitigated', 'resolved'] as const) {
    assert.equal(actions(state, FULL).assign.enabled, true, state);
    assert.equal(actions(state, FULL).comment.enabled, true, state);
  }
});

test('a read-only role gets every action disabled with a permission reason', () => {
  const list = availableIncidentActions({ state: 'mitigated', assignee_id: null }, AUDITOR);
  for (const item of list) {
    assert.equal(item.enabled, false, item.action);
    assert.match(item.reason ?? '', /role/i, item.action);
  }
});

test('a technician may act only on incidents assigned to them', () => {
  const own = actions('open', TECHNICIAN, TECHNICIAN.identityId);
  assert.equal(own.acknowledge.enabled, true);
  assert.equal(own.comment.enabled, true);
  assert.equal(own.assign.enabled, false);
  assert.equal(own.resolve.enabled, false);

  const other = actions('open', TECHNICIAN, 'microsoft:someone-else');
  assert.equal(other.acknowledge.enabled, false);
  assert.match(other.acknowledge.reason ?? '', /assigned to you/i);
  assert.equal(other.comment.enabled, false);

  const unassigned = actions('open', TECHNICIAN, null);
  assert.equal(unassigned.acknowledge.enabled, false);
});

test('the permission reason wins over the state reason so the UI never hints at hidden states', () => {
  const item = actions('open', AUDITOR).resolve;
  assert.equal(item.enabled, false);
  assert.match(item.reason ?? '', /role/i);
});

test('a state reason explains what is missing for an allowed role', () => {
  assert.match(actions('open', FULL).resolve.reason ?? '', /mitigated/i);
  assert.match(actions('open', FULL).reopen.reason ?? '', /resolved or closed/i);
  assert.match(actions('acknowledged', FULL).acknowledge.reason ?? '', /open/i);
});

test('no session means nothing is enabled and the reason is to sign in', () => {
  const list = availableIncidentActions({ state: 'open', assignee_id: null }, null);
  for (const item of list) {
    assert.equal(item.enabled, false);
    assert.match(item.reason ?? '', /sign in/i);
  }
});

test('resolve and reopen are flagged as needing a recent multi-factor sign-in', () => {
  const byAction = actions('mitigated', FULL);
  assert.equal(byAction.resolve.needsStepUp, true);
  assert.equal(byAction.reopen.needsStepUp, true);
  assert.equal(byAction.acknowledge.needsStepUp, false);
  assert.equal(byAction.comment.needsStepUp, false);
});

test('an unknown permission string grants nothing', () => {
  const odd: Viewer = { identityId: 'x', permissions: ['incidents:*', 'admin', ''] };
  for (const item of availableIncidentActions({ state: 'open', assignee_id: null }, odd)) {
    assert.equal(item.enabled, false);
  }
});

// --- request planning ----------------------------------------------------------------

function plan(input: unknown) {
  return planIncidentRequest(input, NOW);
}

test('acknowledge posts to the acknowledge route with an empty body', () => {
  assert.deepEqual(plan({ action: 'acknowledge', incidentId: ID }), {
    ok: true,
    path: `/api/v1/incidents/${ID}/acknowledge`,
    body: {},
    result: 'incident',
  });
});

test('progress uses the transition route and only the two forward steps', () => {
  assert.deepEqual(plan({ action: 'progress', incidentId: ID, toState: 'mitigated' }), {
    ok: true,
    path: `/api/v1/incidents/${ID}/transition`,
    body: { to_state: 'mitigated' },
    result: 'incident',
  });
  for (const toState of ['closed', 'open', 'resolved', 'acknowledged', 'x', undefined, 1]) {
    assert.equal(plan({ action: 'progress', incidentId: ID, toState }).ok, false, String(toState));
  }
});

test('assign trims the identity and treats blank as unassign only when asked', () => {
  assert.deepEqual(plan({ action: 'assign', incidentId: ID, assigneeId: '  microsoft:ana  ' }), {
    ok: true,
    path: `/api/v1/incidents/${ID}/assign`,
    body: { assignee_id: 'microsoft:ana' },
    result: 'incident',
  });
  assert.deepEqual(plan({ action: 'assign', incidentId: ID, assigneeId: null }), {
    ok: true,
    path: `/api/v1/incidents/${ID}/assign`,
    body: { assignee_id: null },
    result: 'incident',
  });
  assert.equal(plan({ action: 'assign', incidentId: ID, assigneeId: '   ' }).ok, false);
  assert.equal(plan({ action: 'assign', incidentId: ID, assigneeId: 'x'.repeat(256) }).ok, false);
  assert.equal(plan({ action: 'assign', incidentId: ID, assigneeId: 5 }).ok, false);
});

test('comment keeps the text verbatim and rejects blank or oversized text', () => {
  const text = '<img src=x onerror=alert(1)>\n  keep spacing  ';
  assert.deepEqual(plan({ action: 'comment', incidentId: ID, message: text }), {
    ok: true,
    path: `/api/v1/incidents/${ID}/comment`,
    body: { message: text },
    result: 'event',
  });
  assert.equal(plan({ action: 'comment', incidentId: ID, message: ' \n\t ' }).ok, false);
  assert.equal(plan({ action: 'comment', incidentId: ID, message: 'x'.repeat(4001) }).ok, false);
  assert.equal(plan({ action: 'comment', incidentId: ID, message: 'x'.repeat(4000) }).ok, true);
  assert.equal(plan({ action: 'comment', incidentId: ID, message: 7 }).ok, false);
});

const RESOLVE_INPUT = {
  action: 'resolve',
  incidentId: ID,
  summary: 'Replaced failed optic',
  rootCauseStatus: 'determined',
  rootCause: 'Failed SFP',
  impact: 'Guest Wi-Fi down for 40 minutes',
  restoredAt: '2026-10-10T11:30',
  followUps: 'Order spare SFPs\n\n  Review monitoring  \n',
};

test('resolve builds the contract body: UTC restore time, trimmed follow-ups, no blank lines', () => {
  assert.deepEqual(plan(RESOLVE_INPUT), {
    ok: true,
    path: `/api/v1/incidents/${ID}/resolve`,
    body: {
      summary: 'Replaced failed optic',
      root_cause_status: 'determined',
      root_cause: 'Failed SFP',
      impact: 'Guest Wi-Fi down for 40 minutes',
      restored_at: '2026-10-10T11:30:00Z',
      follow_up_actions: ['Order spare SFPs', 'Review monitoring'],
    },
    result: 'incident',
  });
});

test('resolve with an undetermined cause carries no root cause text', () => {
  const result = plan({ ...RESOLVE_INPUT, rootCauseStatus: 'not-determined', rootCause: 'ignored' });
  assert.equal(result.ok, true);
  if (result.ok) assert.equal((result.body as { root_cause: unknown }).root_cause, null);
});

test('resolve rejects what the contract would reject, before any request is made', () => {
  const bad: Array<[string, Record<string, unknown>]> = [
    ['blank summary', { summary: '  ' }],
    ['summary too long', { summary: 'x'.repeat(2001) }],
    ['blank impact', { impact: '' }],
    ['determined without a cause', { rootCause: '   ' }],
    ['unknown status', { rootCauseStatus: 'maybe' }],
    ['no restore time', { restoredAt: '' }],
    ['malformed restore time', { restoredAt: 'yesterday' }],
    ['restore time in the future', { restoredAt: '2026-10-10T12:01' }],
    ['too many follow-ups', { followUps: Array.from({ length: 33 }, (_, i) => `a${i}`).join('\n') }],
    ['follow-up too long', { followUps: 'x'.repeat(501) }],
  ];
  for (const [name, override] of bad) {
    const result = plan({ ...RESOLVE_INPUT, ...override });
    assert.equal(result.ok, false, name);
    if (!result.ok) assert.ok(result.message.length > 0, name);
  }
});

test('reopen requires a reason and keeps it verbatim', () => {
  assert.deepEqual(plan({ action: 'reopen', incidentId: ID, reason: 'Recurred after failover' }), {
    ok: true,
    path: `/api/v1/incidents/${ID}/reopen`,
    body: { reason: 'Recurred after failover' },
    result: 'incident',
  });
  assert.equal(plan({ action: 'reopen', incidentId: ID, reason: '   ' }).ok, false);
  assert.equal(plan({ action: 'reopen', incidentId: ID, reason: 'x'.repeat(1001) }).ok, false);
});

test('a malformed incident id never reaches a path', () => {
  for (const incidentId of ['', 'incident-1', '../x', `${ID}/../comment`, `${ID}?x=1`, 5, null]) {
    assert.equal(plan({ action: 'acknowledge', incidentId }).ok, false, String(incidentId));
  }
});

test('unknown actions and non-objects are rejected', () => {
  for (const input of [null, undefined, 'x', 1, [], { action: 'close', incidentId: ID }, { incidentId: ID }]) {
    assert.equal(plan(input).ok, false);
  }
});
