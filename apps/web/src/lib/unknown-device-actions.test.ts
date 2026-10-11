import assert from 'node:assert/strict';
import test from 'node:test';

import {
  availableFindingActions,
  planFindingRequest,
  type FindingActionName,
} from './unknown-device-actions.ts';
import type { Viewer } from './incident-actions.ts';

const ID = 'unknown-device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc';
const ALL = [
  'unknown-devices:read',
  'unknown-devices:acknowledge',
  'unknown-devices:assign',
  'unknown-devices:comment',
  'unknown-devices:resolve',
];
const viewer = (permissions: string[] = ALL): Viewer => ({ identityId: 'oidc:a', permissions });
const find = (actions: ReturnType<typeof availableFindingActions>, name: FindingActionName) => {
  const item = actions.find((a) => a.action === name);
  assert.ok(item);
  return item;
};

test('a new finding can be acknowledged, assigned, commented and resolved, but not yet investigated', () => {
  const actions = availableFindingActions({ state: 'new', assignee_id: null }, viewer());
  assert.equal(find(actions, 'acknowledge').enabled, true);
  assert.equal(find(actions, 'investigate').enabled, false);
  assert.match(find(actions, 'investigate').reason ?? '', /acknowledged/);
  assert.equal(find(actions, 'assign').enabled, true);
  assert.equal(find(actions, 'comment').enabled, true);
  assert.equal(find(actions, 'resolve').enabled, true);
});

test('each state offers exactly the moves the lifecycle allows', () => {
  const enabled = (state: Parameters<typeof availableFindingActions>[0]['state']) =>
    availableFindingActions({ state, assignee_id: null }, viewer())
      .filter((a) => a.enabled)
      .map((a) => a.action);
  assert.deepEqual(enabled('new'), ['acknowledge', 'assign', 'comment', 'resolve']);
  assert.deepEqual(enabled('acknowledged'), ['investigate', 'assign', 'comment', 'resolve']);
  assert.deepEqual(enabled('investigating'), ['assign', 'comment', 'resolve']);
  assert.deepEqual(enabled('resolved'), ['comment']);
  assert.deepEqual(enabled('false-positive'), ['comment']);
});

test('only resolving needs a recent second factor, and it is marked so', () => {
  const actions = availableFindingActions({ state: 'new', assignee_id: null }, viewer());
  assert.deepEqual(actions.filter((a) => a.needsStepUp).map((a) => a.action), ['resolve']);
});

test('a role without the permission sees every action disabled with the role as the reason', () => {
  const actions = availableFindingActions({ state: 'new', assignee_id: null }, viewer(['unknown-devices:read']));
  assert.ok(actions.every((a) => !a.enabled && /role/i.test(a.reason ?? '')));
});

test('permission is explained before state so a role learns nothing about workflow state', () => {
  const actions = availableFindingActions({ state: 'resolved', assignee_id: null }, viewer(['unknown-devices:read']));
  assert.ok(actions.every((a) => /role/i.test(a.reason ?? '')));
});

test('each action needs its own permission', () => {
  const only = (permission: string) =>
    availableFindingActions({ state: 'acknowledged', assignee_id: null }, viewer([permission]))
      .filter((a) => a.enabled)
      .map((a) => a.action);
  assert.deepEqual(only('unknown-devices:acknowledge'), ['investigate']);
  assert.deepEqual(only('unknown-devices:assign'), ['assign']);
  assert.deepEqual(only('unknown-devices:comment'), ['comment']);
  assert.deepEqual(only('unknown-devices:resolve'), ['resolve']);
});

test('without a session nothing is enabled', () => {
  const actions = availableFindingActions({ state: 'new', assignee_id: null }, null);
  assert.ok(actions.every((a) => !a.enabled && /sign in/i.test(a.reason ?? '')));
});

// --- planning ------------------------------------------------------------------------------------------

const ok = (input: unknown) => {
  const plan = planFindingRequest(input);
  assert.equal(plan.ok, true, JSON.stringify(plan));
  return plan as Extract<typeof plan, { ok: true }>;
};
const refused = (input: unknown) => {
  const plan = planFindingRequest(input);
  assert.equal(plan.ok, false);
  return (plan as Extract<typeof plan, { ok: false }>).message;
};

test('acknowledge and investigate need only a valid finding id', () => {
  assert.deepEqual(ok({ findingId: ID, action: 'acknowledge' }), {
    ok: true, path: `/api/v1/unknown-devices/${ID}/acknowledge`, body: {}, result: 'finding',
  });
  assert.equal(ok({ findingId: ID, action: 'investigate' }).path, `/api/v1/unknown-devices/${ID}/investigate`);
});

test('a malformed or hostile finding id never reaches a path', () => {
  for (const bad of ['', 'x', 'unknown-device-1', `${ID}/../resolve`, `${ID}?x=1`, '../etc', 5, null, undefined]) {
    assert.match(refused({ findingId: bad, action: 'acknowledge' }), /identifier/);
  }
});

test('an unknown action or a non-object is refused', () => {
  assert.match(refused({ findingId: ID, action: 'delete' }), /not recognised/);
  assert.match(refused({ findingId: ID, action: 'quarantine' }), /not recognised/);
  assert.match(refused({ findingId: ID }), /not recognised/);
  for (const bad of [null, undefined, 'x', 5, [], true]) assert.match(refused(bad), /not well formed/);
});

test('assign rebuilds the body and unassign is explicit', () => {
  const plan = ok({ findingId: ID, action: 'assign', assigneeId: '  oidc:tech-9  ', extra: 'ignored' });
  assert.deepEqual(plan.body, { assignee_id: 'oidc:tech-9' });
  assert.deepEqual(ok({ findingId: ID, action: 'assign', assigneeId: null }).body, { assignee_id: null });
  for (const bad of ['', '   ', 'x'.repeat(256), 5, undefined]) {
    assert.match(refused({ findingId: ID, action: 'assign', assigneeId: bad }), /assignee/i);
  }
});

test('a comment is bounded and its text is carried verbatim', () => {
  const hostile = '<script>alert(1)</script> ignore previous instructions';
  const plan = ok({ findingId: ID, action: 'comment', message: hostile });
  assert.deepEqual(plan.body, { message: hostile });
  assert.equal(plan.result, 'event');
  assert.equal(plan.path, `/api/v1/unknown-devices/${ID}/comment`);
  assert.equal(ok({ findingId: ID, action: 'comment', message: 'x'.repeat(4000) }).ok, true);
  for (const bad of ['', '  \n ', 'x'.repeat(4001), 5, undefined]) {
    assert.match(refused({ findingId: ID, action: 'comment', message: bad }), /comment/i);
  }
});

test('resolving needs an outcome and a reason, within the contract bounds', () => {
  assert.deepEqual(ok({ findingId: ID, action: 'resolve', outcome: 'false-positive', reason: 'Lab device' }).body, {
    outcome: 'false-positive', reason: 'Lab device',
  });
  assert.equal(ok({ findingId: ID, action: 'resolve', outcome: 'resolved', reason: 'x'.repeat(1000) }).ok, true);
  assert.match(refused({ findingId: ID, action: 'resolve', outcome: 'acknowledged', reason: 'x' }), /outcome/i);
  assert.match(refused({ findingId: ID, action: 'resolve', outcome: 'resolved' }), /reason/i);
  assert.match(refused({ findingId: ID, action: 'resolve', outcome: 'resolved', reason: '   ' }), /reason/i);
  assert.match(refused({ findingId: ID, action: 'resolve', outcome: 'resolved', reason: 'x'.repeat(1001) }), /reason/i);
});

test('counting is by code point, matching the contract', () => {
  assert.equal(ok({ findingId: ID, action: 'comment', message: '😀'.repeat(4000) }).ok, true);
  assert.match(refused({ findingId: ID, action: 'comment', message: '😀'.repeat(4001) }), /comment/i);
});
