import assert from 'node:assert/strict';
import test from 'node:test';

import {
  actionPath,
  actionsPath,
  decisionAvailability,
  describeDecisionOutcome,
  executionSummary,
  listSurface,
  pageHrefs,
  parseActionsQuery,
  planDecision,
  planFindingProposal,
  planKillSwitch,
  riskPresentation,
  shortId,
  statePresentation,
} from './actions-view.ts';
import { REQUEST_STATES, type ActionList, type ActionRequest, type ActionStatus } from './api-contracts-actions.ts';
import type { FetchState } from './api-response.ts';
import { buildInstance, loadVectorFile } from './contract-vectors.ts';
import type { Viewer } from './incident-actions.ts';

const VECTORS = loadVectorFile('actions.vectors.json');
const request = (changes: Record<string, unknown> = {}): ActionRequest =>
  ({ ...(buildInstance(VECTORS.action_request, { name: 'base', valid: true }) as object), ...changes }) as unknown as ActionRequest;
const status = (changes: Record<string, unknown> = {}): ActionStatus =>
  ({ ...(buildInstance(VECTORS.action_status, { name: 'base', valid: true }) as object), ...changes }) as unknown as ActionStatus;

const ID = 'action-11111111-2222-4333-8444-555555555555';
const DIGEST = `sha256:${'ab'.repeat(32)}`;
const KEY = 'ui-key-0123456789abcdef';
const ADMIN: Viewer = {
  identityId: 'admin-1',
  permissions: ['actions:read', 'actions:approve', 'actions:execute', 'actions:propose', 'actions:kill-switch'],
};
const ENGINEER: Viewer = {
  identityId: 'user-eng',
  permissions: ['actions:read', 'actions:propose', 'actions:propose-high'],
};

// --- the URL is untrusted ---------------------------------------------------------------------------------------

test('the list query is validated before it can reach an API path', () => {
  assert.deepEqual(parseActionsQuery({}), { state: null, page: 1 });
  assert.deepEqual(parseActionsQuery({ state: 'approved', page: '3' }), { state: 'approved', page: 3 });
  for (const hostile of ['../x', 'approved&page_size=999', 'APPROVED', ['approved', 'failed'][1] + '%0d%0a']) {
    assert.equal(parseActionsQuery({ state: hostile }).state, null, hostile);
  }
  for (const page of ['0', '-1', '1e3', '1.5', '99999999', 'abc', '']) {
    assert.equal(parseActionsQuery({ page }).page, 1, page);
  }
  assert.equal(actionsPath({ state: 'pending-approval', page: 2 }), '/api/v1/actions?page=2&page_size=25&state=pending-approval');
  assert.equal(actionsPath({ state: null, page: 1 }), '/api/v1/actions?page=1&page_size=25');
});

test('only a well-formed id becomes an API path', () => {
  assert.equal(actionPath(ID), `/api/v1/actions/${ID}`);
  for (const bad of ['', 'status', '../status', `${ID}/approve`, `${ID}\n`, 'action-1']) {
    assert.equal(actionPath(bad), null, bad);
  }
});

test('page links keep the filter and stop at the ends', () => {
  const hrefs = pageHrefs({ state: 'failed', page: 2 }, 80, 25);
  assert.equal(hrefs.previous, '/actions?state=failed');
  assert.equal(hrefs.next, '/actions?state=failed&page=3');
  assert.deepEqual(pageHrefs({ state: null, page: 1 }, 10, 25), { previous: null, next: null });
});

// --- honest presentation -----------------------------------------------------------------------------------------------

test('every state has a word, an icon and an explanation, and none says executed unless it ran', () => {
  for (const state of REQUEST_STATES) {
    const view = statePresentation(state);
    assert.ok(view.label.length > 0 && view.icon.startsWith('bi-') && view.explanation.length > 10, state);
  }
  assert.match(statePresentation('succeeded').explanation, /dry run|recorded/i);
  assert.doesNotMatch(statePresentation('approved').label, /executed|applied/i);
});

test('a dry run is described as recording what would happen and changing nothing', () => {
  const dry = request({
    state: 'succeeded',
    execution: {
      executor: 'dry-run', mode: 'dry-run', effect: 'none', started_at: '2026-10-18T12:05:00Z',
      finished_at: '2026-10-18T12:05:00Z', planned_steps: ['Would do it'],
      verification: { state: 'not-applicable', detail: 'dry-run' }, rollback: null, failure: null,
    },
  });
  const summary = executionSummary(dry);
  assert.match(summary.headline, /dry run/i);
  assert.match(summary.detail, /nothing was changed/i);
  assert.equal(summary.tone, 'info');
  assert.equal(executionSummary(request()).headline, 'Not run');
});

test('a failed or rolled-back run says so and never claims success', () => {
  const base = {
    executor: 'live', mode: 'live', effect: 'unknown', started_at: '2026-10-18T12:05:00Z',
    finished_at: '2026-10-18T12:05:01Z', planned_steps: [],
    verification: { state: 'unknown', detail: 'not-run' }, rollback: null, failure: 'executor-timeout',
  };
  const failed = executionSummary(request({ state: 'failed', execution: base }));
  assert.match(failed.headline, /failed/i);
  assert.equal(failed.tone, 'danger');
  assert.match(failed.detail, /may have changed/i);
  const rolled = executionSummary(request({ state: 'rolled-back', execution: { ...base, effect: 'applied', failure: null } }));
  assert.match(rolled.headline, /rolled back/i);
});

test('risk classes are explained', () => {
  for (const risk of ['A', 'B', 'C', 'D'] as const) assert.ok(riskPresentation(risk).explanation.length > 10);
  assert.match(riskPresentation('D').explanation, /two/i);
});

test('the list surface separates not-connected, empty and filtered-empty', () => {
  const list = (changes: Record<string, unknown>): FetchState<ActionList> => ({
    kind: 'ok',
    correlationId: 'corr-1',
    data: { ...(buildInstance(VECTORS.action_list, { name: 'base', valid: true }) as object), ...changes } as unknown as ActionList,
  });
  assert.equal(listSurface(list({}), { state: null, page: 1 }), 'data');
  assert.equal(listSurface(list({ items: [], total: 0 }), { state: null, page: 1 }), 'empty');
  assert.equal(listSurface(list({ items: [], total: 0 }), { state: 'failed', page: 1 }), 'filtered-empty');
  assert.equal(listSurface(list({ state: 'not-connected', items: [], total: 0 }), { state: null, page: 1 }), 'not-connected');
  assert.equal(
    listSurface({ kind: 'forbidden', code: 'FORBIDDEN', message: '', correlationId: 'c', status: 403 }, { state: null, page: 1 }),
    'permission',
  );
  assert.equal(
    listSurface({ kind: 'error', code: 'X', message: '', correlationId: 'c', status: 500 }, { state: null, page: 1 }),
    'error',
  );
});

test('ids are shortened for display only', () => {
  assert.equal(shortId(ID), 'action-11111111');
});

// --- who can decide, and why not ----------------------------------------------------------------------------------------

const by = (list: ReturnType<typeof decisionAvailability>, verb: string) => {
  const found = list.find((a) => a.verb === verb);
  assert.ok(found, verb);
  return found;
};

test('an approver sees approve, reject and cancel on a pending request, with step-up on approve', () => {
  const list = decisionAvailability(request(), ADMIN, status());
  assert.equal(by(list, 'approve').enabled, true);
  assert.equal(by(list, 'approve').needsStepUp, true);
  assert.equal(by(list, 'reject').enabled, true);
  assert.equal(by(list, 'cancel').enabled, true);
  assert.equal(by(list, 'execute').enabled, false);
  assert.match(by(list, 'execute').reason ?? '', /approved/i);
});

test('the requester is told that a different person must approve', () => {
  const own = request({ requester: { id: 'admin-1', kind: 'human' } });
  const approve = by(decisionAvailability(own, ADMIN, status()), 'approve');
  assert.equal(approve.enabled, false);
  assert.match(approve.reason ?? '', /different person/i);
});

test('someone who already approved cannot approve again', () => {
  const twoPerson = request({
    risk: 'D', approvals_required: 2,
    approvals: [{ approver_id: 'admin-1', approved_at: '2026-10-18T12:01:00Z' }],
  });
  assert.match(by(decisionAvailability(twoPerson, ADMIN, status()), 'approve').reason ?? '', /already approved/i);
});

test('an engineer can cancel their own request but not approve or run anything', () => {
  const list = decisionAvailability(request(), ENGINEER, status());
  assert.equal(by(list, 'cancel').enabled, true);
  for (const verb of ['approve', 'reject', 'execute']) {
    assert.equal(by(list, verb).enabled, false, verb);
    assert.match(by(list, verb).reason ?? '', /role does not permit/i);
  }
});

test('an approved request is run by the executor role, and the label is honest about a dry run', () => {
  const approved = request({
    state: 'approved', execute_by: '2026-10-18T13:00:00Z',
    approvals: [{ approver_id: 'admin-2', approved_at: '2026-10-18T12:01:00Z' }],
  });
  const execute = by(decisionAvailability(approved, ADMIN, status({ dry_run_only: true })), 'execute');
  assert.equal(execute.enabled, true);
  assert.equal(execute.needsStepUp, true);
  assert.match(execute.label, /dry run/i);
  assert.doesNotMatch(execute.label, /^execute$/i);
});

test('the requester cannot execute their own request unless the policy allows it, and is told why', () => {
  const approved = request({
    state: 'approved', execute_by: '2026-10-18T13:00:00Z',
    requester: { id: 'admin-1', kind: 'human' },
    approvals: [{ approver_id: 'admin-2', approved_at: '2026-10-18T12:01:00Z' }],
  });
  const refused = by(decisionAvailability(approved, ADMIN, status({ policy: { self_execute_allowed: false } })), 'execute');
  assert.equal(refused.enabled, false);
  assert.match(refused.reason ?? '', /The person who requested an action cannot execute it/);
  const allowed = by(decisionAvailability(approved, ADMIN, status({ policy: { self_execute_allowed: true } })), 'execute');
  assert.equal(allowed.enabled, true);
  // Someone else is unaffected by the policy, and a missing status fails closed for the requester.
  const other = { ...approved, requester: { id: 'someone-else', kind: 'human' } } as unknown as ActionRequest;
  assert.equal(by(decisionAvailability(other, ADMIN, status()), 'execute').enabled, true);
  assert.equal(by(decisionAvailability(approved, ADMIN, null), 'execute').enabled, false);
});

test('the kill switch disables approve and execute with a reason', () => {
  const engaged = status({ kill_switch: { engaged: true, source: 'runtime', since: '2026-10-18T12:00:00Z' } });
  const approve = by(decisionAvailability(request(), ADMIN, engaged), 'approve');
  assert.equal(approve.enabled, false);
  assert.match(approve.reason ?? '', /kill switch/i);
  const approved = request({ state: 'approved', execute_by: '2026-10-18T13:00:00Z', approvals: [{ approver_id: 'a', approved_at: '2026-10-18T12:01:00Z' }] });
  assert.match(by(decisionAvailability(approved, ADMIN, engaged), 'execute').reason ?? '', /kill switch/i);
});

test('a finished request offers nothing, and a signed-out viewer is told to sign in', () => {
  const done = request({ state: 'rejected' });
  assert.ok(decisionAvailability(done, ADMIN, status()).every((a) => !a.enabled));
  assert.match(by(decisionAvailability(request(), null, status()), 'approve').reason ?? '', /sign in/i);
});

// --- the server action planner ----------------------------------------------------------------------------------------

test('a decision is rebuilt field by field and aimed at one fixed path', () => {
  const plan = planDecision({ verb: 'approve', actionId: ID, digest: DIGEST, version: 3, extra: 'ignored', command: 'reload' });
  assert.deepEqual(plan, {
    ok: true,
    path: `/api/v1/actions/${ID}/approve`,
    body: { expected_digest: DIGEST, expected_version: 3 },
    idempotencyKey: null,
  });
  const reject = planDecision({ verb: 'reject', actionId: ID, digest: DIGEST, version: 3, reason: '  Not justified  ' });
  assert.ok(reject.ok && reject.body.reason === 'Not justified');
  const execute = planDecision({ verb: 'execute', actionId: ID, digest: DIGEST, version: 4, key: KEY });
  assert.ok(execute.ok && execute.idempotencyKey === KEY && execute.path.endsWith('/execute'));
});

test('a decision that does not fit the contract is refused before anything is sent', () => {
  const good = { verb: 'approve', actionId: ID, digest: DIGEST, version: 3 };
  const refused: unknown[] = [
    null, 'approve', [],
    { ...good, verb: 'delete' },
    { ...good, verb: '../kill-switch' },
    { ...good, actionId: 'status' },
    { ...good, actionId: `${ID}/execute` },
    { ...good, digest: 'md5:abc' },
    { ...good, version: 0 },
    { ...good, version: '3' },
    { ...good, version: 1.5 },
    { ...good, verb: 'reject' },
    { ...good, verb: 'reject', reason: 'ab' },
    { ...good, verb: 'cancel', reason: 'bad\u0007reason' },
    { ...good, verb: 'cancel', reason: 'evil‮text' },
    { ...good, verb: 'execute' },
    { ...good, verb: 'execute', key: 'short' },
    { ...good, verb: 'execute', key: 'has spaces in the key 123' },
  ];
  for (const input of refused) assert.equal(planDecision(input).ok, false, JSON.stringify(input));
});

test('a finding proposal and the kill switch are planned the same way', () => {
  const finding = 'unknown-device-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
  const plan = planFindingProposal({ findingId: finding, evidenceVersion: 3, reason: 'Seen on the finance VLAN', key: KEY });
  assert.deepEqual(plan, {
    ok: true,
    body: { finding_id: finding, expected_evidence_version: 3, reason: 'Seen on the finance VLAN' },
    idempotencyKey: KEY,
  });
  for (const bad of [
    { findingId: 'nope', evidenceVersion: 3, reason: 'Seen on the VLAN', key: KEY },
    { findingId: finding, evidenceVersion: 0, reason: 'Seen on the VLAN', key: KEY },
    { findingId: finding, evidenceVersion: 3, reason: 'x', key: KEY },
    { findingId: finding, evidenceVersion: 3, reason: 'Seen on the VLAN', key: 'k' },
  ]) {
    assert.equal(planFindingProposal(bad).ok, false);
  }
  assert.deepEqual(planKillSwitch({ engaged: true, reason: 'Suspected compromise' }), {
    ok: true,
    body: { engaged: true, reason: 'Suspected compromise' },
  });
  assert.equal(planKillSwitch({ engaged: 'true', reason: 'Suspected compromise' }).ok, false);
  assert.equal(planKillSwitch({ engaged: false, reason: '' }).ok, false);
});

// --- review fixes ---------------------------------------------------------------------------------------------------

test('a dry run is never labelled Completed: the badge says it was a dry run', () => {
  assert.equal(statePresentation('succeeded', 'dry-run').label, 'Dry run recorded');
  assert.match(statePresentation('succeeded', 'dry-run').explanation, /nothing was changed/i);
  assert.equal(statePresentation('succeeded', 'live').label, 'Completed');
  assert.equal(statePresentation('succeeded').label, 'Completed');
  assert.equal(statePresentation('failed', 'dry-run').label, 'Failed');
});

test('the notice after a decision reports what actually happened', () => {
  const approved = describeDecisionOutcome('approve', 'approved', true);
  assert.equal(approved.tone, 'success');
  assert.match(approved.text, /not been run/i);
  const partial = describeDecisionOutcome('approve', 'pending-approval', true);
  assert.match(partial.text, /another approver/i);
  const dry = describeDecisionOutcome('execute', 'succeeded', true);
  assert.equal(dry.tone, 'info');
  assert.match(dry.text, /dry run recorded/i);
  assert.match(dry.text, /nothing was changed/i);
  const live = describeDecisionOutcome('execute', 'succeeded', false);
  assert.match(live.text, /verified/i);
  const failed = describeDecisionOutcome('execute', 'failed', true);
  assert.equal(failed.tone, 'danger');
  assert.match(failed.text, /failed/i);
  assert.doesNotMatch(failed.text, /recorded\./i);
  assert.equal(describeDecisionOutcome('execute', 'rolled-back', false).tone, 'warning');
  assert.match(describeDecisionOutcome('reject', 'rejected', true).text, /rejected/i);
  assert.match(describeDecisionOutcome('cancel', 'cancelled', true).text, /cancelled/i);
  assert.match(describeDecisionOutcome('execute', undefined, true).text, /refresh/i);
});
