import assert from 'node:assert/strict';
import test from 'node:test';

import {
  availableRuleActions,
  availableWindowActions,
  buildRuleDefinition,
  buildWindowRequest,
  emptyRuleForm,
  emptyWindowForm,
  planAlertingRequest,
  ruleToForm,
  type RuleFormValues,
  type WindowFormValues,
} from './alerting-forms.ts';
import type { AlertRule, MaintenanceWindow } from './api-contracts-alert-rule.ts';
import type { Viewer } from './incident-actions.ts';

const NOW = Date.parse('2026-10-10T12:00:00Z');
const RULE_ID = 'alert-rule-3f2b8a40-1c2d-4e5f-8a9b-0c1d2e3f4a5b';
const WINDOW_ID = 'maintenance-3f2b8a40-1c2d-4e5f-8a9b-0c1d2e3f4a5b';

function validRule(overrides: Partial<RuleFormValues> = {}): RuleFormValues {
  return {
    ...emptyRuleForm(),
    name: 'Core uplink saturated',
    scopeKind: 'device',
    scopeRef: 'core-sw-01',
    metric: 'interface.utilisation_percent',
    operator: 'gt',
    operand: '90',
    ...overrides,
  };
}

function validWindow(overrides: Partial<WindowFormValues> = {}): WindowFormValues {
  return {
    ...emptyWindowForm(),
    name: 'Core switch firmware',
    scopeKind: 'device',
    scopeRef: 'core-sw-01',
    startsAt: '2026-10-11T01:00',
    endsAt: '2026-10-11T03:00',
    evaluation: 'retain',
    reason: 'Planned firmware upgrade',
    ...overrides,
  };
}

// --- rule form -> definition -----------------------------------------------------------

test('a valid form builds exactly the contract definition', () => {
  const result = buildRuleDefinition(validRule());
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.deepEqual(result.definition, {
    name: 'Core uplink saturated',
    scope: { kind: 'device', ref: 'core-sw-01' },
    condition: {
      metric: 'interface.utilisation_percent',
      operator: 'gt',
      threshold: 90,
      pattern: null,
    },
    baseline_mode: 'none',
    window_seconds: 300,
    for_seconds: 0,
    cooldown_seconds: 600,
    schedule: null,
    exceptions: { destinations: [], device_groups: [] },
    severity: 'medium',
    labels: {},
    actions: ['create_alert'],
    incident_policy: 'none',
  });
});

test('matches takes the operand as a pattern and no threshold', () => {
  const result = buildRuleDefinition(
    validRule({ operator: 'matches', operand: 'link * down', metric: 'syslog.message' }),
  );
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.deepEqual(result.definition.condition, {
      metric: 'syslog.message',
      operator: 'matches',
      threshold: null,
      pattern: 'link * down',
    });
  }
});

test('numeric operators reject a non-number operand', () => {
  for (const operand of ['', 'abc', 'NaN', 'Infinity', '1e999', '9'.repeat(30)]) {
    const result = buildRuleDefinition(validRule({ operand }));
    assert.equal(result.ok, false, operand);
    if (!result.ok) assert.ok(result.errors.operand, operand);
  }
  assert.equal(buildRuleDefinition(validRule({ operand: '-12.5' })).ok, true);
});

test('field errors are keyed by field so the form can mark the right control', () => {
  const result = buildRuleDefinition(
    validRule({
      name: '   ',
      scopeRef: '',
      metric: 'Not A Metric',
      windowSeconds: '59',
      forSeconds: '-1',
      cooldownSeconds: 'x',
      actions: [],
    }),
  );
  assert.equal(result.ok, false);
  if (result.ok) return;
  for (const field of [
    'name',
    'scopeRef',
    'metric',
    'windowSeconds',
    'forSeconds',
    'cooldownSeconds',
    'actions',
  ]) {
    assert.ok(result.errors[field], field);
  }
});

test('timing bounds mirror the contract', () => {
  assert.equal(buildRuleDefinition(validRule({ windowSeconds: '60' })).ok, true);
  assert.equal(buildRuleDefinition(validRule({ windowSeconds: '86400' })).ok, true);
  assert.equal(buildRuleDefinition(validRule({ windowSeconds: '86401' })).ok, false);
  assert.equal(buildRuleDefinition(validRule({ forSeconds: '86401' })).ok, false);
  assert.equal(buildRuleDefinition(validRule({ cooldownSeconds: '604800' })).ok, true);
  assert.equal(buildRuleDefinition(validRule({ cooldownSeconds: '604801' })).ok, false);
});

test('labels are key=value lines; bad keys, duplicates and too many are rejected', () => {
  const ok = buildRuleDefinition(validRule({ labels: 'team=network\n\n site = core \n' }));
  assert.equal(ok.ok, true);
  if (ok.ok) assert.deepEqual(ok.definition.labels, { team: 'network', site: 'core' });
  for (const labels of ['Team=x', 'novalue', '=x', 'a=1\na=2', 'a b=1']) {
    assert.equal(buildRuleDefinition(validRule({ labels })).ok, false, labels);
  }
  const many = Array.from({ length: 33 }, (_, i) => `k${i}=v`).join('\n');
  assert.equal(buildRuleDefinition(validRule({ labels: many })).ok, false);
});

test('exceptions are one entry per line, bounded and unique', () => {
  const ok = buildRuleDefinition(
    validRule({ exceptionDestinations: 'guest-wifi\nlab\n', exceptionDeviceGroups: 'printers' }),
  );
  assert.equal(ok.ok, true);
  if (ok.ok) {
    assert.deepEqual(ok.definition.exceptions, {
      destinations: ['guest-wifi', 'lab'],
      device_groups: ['printers'],
    });
  }
  assert.equal(buildRuleDefinition(validRule({ exceptionDestinations: 'a\na' })).ok, false);
  assert.equal(buildRuleDefinition(validRule({ exceptionDeviceGroups: 'x'.repeat(129) })).ok, false);
});

test('a schedule is a timezone plus weekday and time-range lines', () => {
  const result = buildRuleDefinition(
    validRule({ scheduleTimezone: 'Europe/London', scheduleLines: 'mon,tue,wed 08:00-18:00\nsat 22:00-06:00' }),
  );
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.deepEqual(result.definition.schedule, {
      timezone: 'Europe/London',
      active: [
        { weekdays: ['mon', 'tue', 'wed'], from: '08:00', to: '18:00' },
        { weekdays: ['sat'], from: '22:00', to: '06:00' },
      ],
    });
  }
});

test('an incomplete or malformed schedule is rejected rather than dropped', () => {
  const bad: Array<Partial<RuleFormValues>> = [
    { scheduleTimezone: 'Europe/London', scheduleLines: '' },
    { scheduleTimezone: '', scheduleLines: 'mon 08:00-18:00' },
    { scheduleTimezone: 'Europe/London', scheduleLines: 'mon 8:00-18:00' },
    { scheduleTimezone: 'Europe/London', scheduleLines: 'funday 08:00-18:00' },
    { scheduleTimezone: 'Europe/London', scheduleLines: 'mon,mon 08:00-18:00' },
    { scheduleTimezone: 'Europe/London', scheduleLines: 'mon 24:00-18:00' },
    { scheduleTimezone: 'not a zone!', scheduleLines: 'mon 08:00-18:00' },
    {
      scheduleTimezone: 'UTC',
      scheduleLines: Array.from({ length: 15 }, () => 'mon 01:00-02:00').join('\n'),
    },
  ];
  for (const overrides of bad) {
    assert.equal(buildRuleDefinition(validRule(overrides)).ok, false, JSON.stringify(overrides));
  }
});

test('actions must be a non-empty unique subset of the known actions', () => {
  assert.equal(buildRuleDefinition(validRule({ actions: ['email', 'push'] })).ok, true);
  assert.equal(buildRuleDefinition(validRule({ actions: ['email', 'email'] })).ok, false);
  assert.equal(buildRuleDefinition(validRule({ actions: ['sms' as never] })).ok, false);
});

test('untrusted text is carried verbatim as data', () => {
  const name = '<script>alert(1)</script> ‮';
  const result = buildRuleDefinition(validRule({ name }));
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.definition.name, name);
});

test('buildRuleDefinition fails closed on a non-object', () => {
  for (const input of [null, undefined, 'x', 1, []]) {
    assert.equal(buildRuleDefinition(input).ok, false);
  }
});

test('an existing rule round-trips through the form unchanged', () => {
  const rule: AlertRule = {
    id: RULE_ID,
    name: 'Existing',
    status: 'disabled',
    scope: { kind: 'site', ref: 'hq' },
    condition: { metric: 'device.status', operator: 'eq', threshold: 0, pattern: null },
    baseline_mode: 'below-baseline',
    window_seconds: 600,
    for_seconds: 120,
    cooldown_seconds: 3600,
    schedule: {
      timezone: 'UTC',
      active: [{ weekdays: ['mon', 'fri'], from: '09:00', to: '17:00' }],
    },
    exceptions: { destinations: ['lab'], device_groups: [] },
    severity: 'high',
    labels: { team: 'noc' },
    actions: ['email', 'create_alert'],
    incident_policy: 'group',
    created_by: 'microsoft:ana',
    created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-02T00:00:00Z',
    approved_by: null,
    approved_at: null,
    version: 4,
  };
  const built = buildRuleDefinition(ruleToForm(rule));
  assert.equal(built.ok, true);
  if (!built.ok) return;
  const { id, status, created_by, created_at, updated_at, approved_by, approved_at, version, ...definition } =
    rule;
  void [id, status, created_by, created_at, updated_at, approved_by, approved_at, version];
  assert.deepEqual(built.definition, definition);
});

// --- window form -> request ------------------------------------------------------------

test('a valid window form builds the contract request with UTC instants', () => {
  const result = buildWindowRequest(validWindow(), NOW);
  assert.deepEqual(result, {
    ok: true,
    request: {
      name: 'Core switch firmware',
      scope: { kind: 'device', ref: 'core-sw-01' },
      starts_at: '2026-10-11T01:00:00Z',
      ends_at: '2026-10-11T03:00:00Z',
      evaluation: 'retain',
      reason: 'Planned firmware upgrade',
    },
  });
});

test('window times must be real, ordered and at most 30 days long', () => {
  const bad: Array<Partial<WindowFormValues>> = [
    { startsAt: '' },
    { endsAt: 'soon' },
    { startsAt: '2026-02-31T01:00' },
    { endsAt: '2026-10-11T01:00' },
    { endsAt: '2026-10-11T00:59' },
    { endsAt: '2026-11-11T01:01' },
  ];
  for (const overrides of bad) {
    const result = buildWindowRequest(validWindow(overrides), NOW);
    assert.equal(result.ok, false, JSON.stringify(overrides));
  }
  assert.equal(buildWindowRequest(validWindow({ endsAt: '2026-11-10T01:00' }), NOW).ok, true);
});

test('a window that has already ended is refused before any request', () => {
  const result = buildWindowRequest(
    validWindow({ startsAt: '2026-10-09T01:00', endsAt: '2026-10-09T03:00' }),
    NOW,
  );
  assert.equal(result.ok, false);
});

test('window text fields are required and bounded', () => {
  assert.equal(buildWindowRequest(validWindow({ name: ' ' }), NOW).ok, false);
  assert.equal(buildWindowRequest(validWindow({ reason: '' }), NOW).ok, false);
  assert.equal(buildWindowRequest(validWindow({ reason: 'x'.repeat(1001) }), NOW).ok, false);
  assert.equal(buildWindowRequest(validWindow({ scopeRef: '' }), NOW).ok, false);
});

// --- availability ----------------------------------------------------------------------

const ENGINEER: Viewer = {
  identityId: 'microsoft:eng',
  permissions: ['alert-rules:read', 'alert-rules:write', 'alert-rules:disable', 'maintenance:write'],
};
const ADMIN: Viewer = {
  identityId: 'microsoft:admin',
  permissions: [
    'alert-rules:read',
    'alert-rules:write',
    'alert-rules:approve',
    'alert-rules:disable',
    'maintenance:write',
    'maintenance:write-organisation',
  ],
};
const AUDITOR: Viewer = { identityId: 'microsoft:aud', permissions: ['alert-rules:read'] };

function ruleActions(status: AlertRule['status'], viewer: Viewer | null) {
  return Object.fromEntries(
    availableRuleActions({ status }, viewer).map((item) => [item.action, item]),
  );
}

test('a rule can be edited or approved only while it is not active, and disabled only while active', () => {
  for (const status of ['draft', 'disabled'] as const) {
    const actions = ruleActions(status, ADMIN);
    assert.equal(actions.edit.enabled, true, status);
    assert.equal(actions.approve.enabled, true, status);
    assert.equal(actions.disable.enabled, false, status);
  }
  const active = ruleActions('active', ADMIN);
  assert.equal(active.edit.enabled, false);
  assert.match(active.edit.reason ?? '', /disable/i);
  assert.equal(active.approve.enabled, false);
  assert.equal(active.disable.enabled, true);
});

test('an engineer may author and disable but not approve', () => {
  const draft = ruleActions('draft', ENGINEER);
  assert.equal(draft.edit.enabled, true);
  assert.equal(draft.approve.enabled, false);
  assert.match(draft.approve.reason ?? '', /role/i);
  assert.equal(ruleActions('active', ENGINEER).disable.enabled, true);
});

test('a read-only viewer or no session gets every rule action disabled with a reason', () => {
  for (const viewer of [AUDITOR, null]) {
    for (const item of availableRuleActions({ status: 'draft' }, viewer)) {
      assert.equal(item.enabled, false, item.action);
      assert.ok(item.reason, item.action);
    }
  }
});

test('approval is described as bound to the version the viewer is looking at', () => {
  const approve = availableRuleActions({ status: 'draft' }, ADMIN).find((a) => a.action === 'approve');
  assert.ok(approve);
});

function windowActions(
  window: Pick<MaintenanceWindow, 'status' | 'scope'> & { ends_at?: string },
  viewer: Viewer | null,
) {
  return availableWindowActions({ ends_at: '2026-10-11T03:00:00Z', ...window }, viewer, NOW);
}

test('a scheduled window can be cancelled by a maintenance writer', () => {
  const result = windowActions({ status: 'scheduled', scope: { kind: 'device', ref: 'x' } }, ENGINEER);
  assert.equal(result.cancel.enabled, true);
});

test('an organisation-scope window needs the organisation permission to cancel', () => {
  const window = { status: 'scheduled', scope: { kind: 'organisation', ref: 'all' } } as const;
  assert.equal(windowActions(window, ENGINEER).cancel.enabled, false);
  assert.match(windowActions(window, ENGINEER).cancel.reason ?? '', /organisation/i);
  assert.equal(windowActions(window, ADMIN).cancel.enabled, true);
});

test('a cancelled window cannot be cancelled again', () => {
  const result = windowActions({ status: 'cancelled', scope: { kind: 'device', ref: 'x' } }, ADMIN);
  assert.equal(result.cancel.enabled, false);
  assert.match(result.cancel.reason ?? '', /already cancelled/i);
});

test('a window that has already ended is not offered for cancellation', () => {
  const result = windowActions(
    { status: 'scheduled', scope: { kind: 'device', ref: 'x' }, ends_at: '2026-10-10T11:00:00Z' },
    ADMIN,
  );
  assert.equal(result.cancel.enabled, false);
  assert.match(result.cancel.reason ?? '', /already ended/i);
});

test('creating a window needs the maintenance permission; organisation scope and disable need more', () => {
  assert.equal(windowActions({ status: 'scheduled', scope: { kind: 'device', ref: 'x' } }, AUDITOR).create.enabled, false);
  assert.equal(windowActions({ status: 'scheduled', scope: { kind: 'device', ref: 'x' } }, ENGINEER).create.enabled, true);
  assert.equal(windowActions({ status: 'scheduled', scope: { kind: 'device', ref: 'x' } }, ENGINEER).organisationScope, false);
  assert.equal(windowActions({ status: 'scheduled', scope: { kind: 'device', ref: 'x' } }, ADMIN).organisationScope, true);
});

// --- request planning --------------------------------------------------------------------

test('rule.create posts the rebuilt definition', () => {
  const plan = planAlertingRequest({ action: 'rule.create', values: validRule() }, NOW);
  assert.equal(plan.ok, true);
  if (plan.ok) {
    assert.equal(plan.method, 'POST');
    assert.equal(plan.path, '/api/v1/alert-rules');
    assert.equal(plan.result, 'rule');
    assert.equal((plan.body as { name: string }).name, 'Core uplink saturated');
  }
});

test('rule.update binds the edit to the version the operator loaded', () => {
  const plan = planAlertingRequest(
    { action: 'rule.update', ruleId: RULE_ID, expectedVersion: 7, values: validRule() },
    NOW,
  );
  assert.equal(plan.ok, true);
  if (plan.ok) {
    assert.equal(plan.method, 'PUT');
    assert.equal(plan.path, `/api/v1/alert-rules/${RULE_ID}`);
    assert.equal((plan.body as { expected_version: number }).expected_version, 7);
    assert.equal((plan.body as { definition: { name: string } }).definition.name, 'Core uplink saturated');
  }
});

test('rule.approve carries only the reviewed version', () => {
  assert.deepEqual(planAlertingRequest({ action: 'rule.approve', ruleId: RULE_ID, expectedVersion: 3 }, NOW), {
    ok: true,
    method: 'POST',
    path: `/api/v1/alert-rules/${RULE_ID}/approve`,
    body: { expected_version: 3 },
    result: 'rule',
  });
});

test('expected_version must be a contract-valid integer', () => {
  for (const expectedVersion of [0, -1, 1.5, 1_000_001, '3', null, undefined]) {
    for (const action of ['rule.approve', 'rule.update'] as const) {
      const plan = planAlertingRequest(
        { action, ruleId: RULE_ID, expectedVersion, values: validRule() },
        NOW,
      );
      assert.equal(plan.ok, false, `${action} ${String(expectedVersion)}`);
    }
  }
});

test('rule.disable and window.cancel are bodyless actions on a validated id', () => {
  assert.deepEqual(planAlertingRequest({ action: 'rule.disable', ruleId: RULE_ID }, NOW), {
    ok: true,
    method: 'POST',
    path: `/api/v1/alert-rules/${RULE_ID}/disable`,
    body: {},
    result: 'rule',
  });
  assert.deepEqual(planAlertingRequest({ action: 'window.cancel', windowId: WINDOW_ID }, NOW), {
    ok: true,
    method: 'POST',
    path: `/api/v1/maintenance-windows/${WINDOW_ID}/cancel`,
    body: {},
    result: 'window',
  });
});

test('window.create posts the rebuilt request', () => {
  const plan = planAlertingRequest({ action: 'window.create', values: validWindow() }, NOW);
  assert.equal(plan.ok, true);
  if (plan.ok) {
    assert.equal(plan.path, '/api/v1/maintenance-windows');
    assert.equal(plan.result, 'window');
  }
});

test('malformed ids, unknown actions and invalid values never become a request', () => {
  const bad: unknown[] = [
    null,
    'x',
    { action: 'rule.delete', ruleId: RULE_ID },
    { action: 'rule.disable', ruleId: `${RULE_ID}/../approve` },
    { action: 'rule.disable', ruleId: 'alert-rule-1' },
    { action: 'window.cancel', windowId: RULE_ID },
    { action: 'rule.create', values: validRule({ name: '' }) },
    { action: 'rule.create' },
    { action: 'window.create', values: validWindow({ reason: '' }) },
  ];
  for (const input of bad) {
    assert.equal(planAlertingRequest(input, NOW).ok, false, JSON.stringify(input));
  }
});
