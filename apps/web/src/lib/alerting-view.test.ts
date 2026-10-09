import assert from 'node:assert/strict';
import test from 'node:test';

import type { AlertRule, MaintenanceWindow } from './api-contracts-alert-rule.ts';
import {
  DEFAULT_ALERTING_PAGE_SIZE,
  alertingListPath,
  alertingPageHrefs,
  describeCondition,
  describeScope,
  formatSeconds,
  parseAlertingOffsets,
  ruleStatusView,
  windowCounts,
  windowPhase,
  windowPhaseLabel,
} from './alerting-view.ts';

function rule(overrides: Partial<AlertRule> = {}): AlertRule {
  return {
    id: 'alert-rule-0a1b2c3d-0000-4000-8000-0123456789ab',
    name: 'High CPU',
    status: 'draft',
    scope: { kind: 'device', ref: 'sw-1' },
    condition: { metric: 'cpu.load', operator: 'gt', threshold: 90, pattern: null },
    baseline_mode: 'none',
    window_seconds: 300,
    for_seconds: 120,
    cooldown_seconds: 3600,
    schedule: null,
    exceptions: { destinations: [], device_groups: [] },
    severity: 'high',
    labels: {},
    actions: ['create_alert'],
    incident_policy: 'none',
    created_by: 'alice',
    created_at: '2026-10-06T07:00:00Z',
    updated_at: '2026-10-06T07:00:00Z',
    approved_by: null,
    approved_at: null,
    version: 3,
    ...overrides,
  };
}

function win(overrides: Partial<MaintenanceWindow> = {}): MaintenanceWindow {
  return {
    id: 'maintenance-0a1b2c3d-0000-4000-8000-0123456789ab',
    name: 'Patching',
    scope: { kind: 'site', ref: 'hq' },
    starts_at: '2026-10-06T08:00:00Z',
    ends_at: '2026-10-06T10:00:00Z',
    evaluation: 'retain',
    status: 'scheduled',
    reason: 'planned',
    created_by: 'bob',
    created_at: '2026-10-05T08:00:00Z',
    cancelled_by: null,
    cancelled_at: null,
    ...overrides,
  };
}

const at = (iso: string) => Date.parse(iso);

test('a draft rule is awaiting approval and not evaluated', () => {
  const view = ruleStatusView(rule());
  assert.equal(view.label, 'Draft');
  assert.equal(view.approval, 'awaiting');
  assert.match(view.detail, /not evaluated/i);
});

test('an active rule with an approval record is approved', () => {
  const view = ruleStatusView(
    rule({ status: 'active', approved_by: 'carol', approved_at: '2026-10-06T07:30:00Z' }),
  );
  assert.equal(view.label, 'Active');
  assert.equal(view.approval, 'approved');
  assert.match(view.detail, /carol/);
});

test('an active rule with no approval record is flagged, never shown as approved', () => {
  const view = ruleStatusView(rule({ status: 'active' }));
  assert.equal(view.approval, 'inconsistent');
});

test('a disabled rule is disabled regardless of approval history', () => {
  const view = ruleStatusView(
    rule({ status: 'disabled', approved_by: 'carol', approved_at: '2026-10-06T07:30:00Z' }),
  );
  assert.equal(view.label, 'Disabled');
  assert.equal(view.approval, 'disabled');
});

test('describes threshold and pattern conditions as plain text', () => {
  assert.equal(describeCondition(rule().condition), 'cpu.load > 90');
  assert.equal(
    describeCondition({
      metric: 'log.message',
      operator: 'matches',
      threshold: null,
      pattern: '<b>x</b>',
    }),
    'log.message matches <b>x</b>',
  );
  assert.equal(
    describeCondition({ metric: 'a.b', operator: 'lte', threshold: 1.5, pattern: null }),
    'a.b <= 1.5',
  );
});

test('describes scopes as kind and reference', () => {
  assert.equal(describeScope({ kind: 'device_group', ref: 'core' }), 'device group: core');
  assert.equal(describeScope({ kind: 'vlan', ref: '10' }), 'vlan: 10');
});

test('formats durations without fabricating precision', () => {
  assert.equal(formatSeconds(0), '0 s');
  assert.equal(formatSeconds(45), '45 s');
  assert.equal(formatSeconds(300), '5 min');
  assert.equal(formatSeconds(3600), '1 h');
  assert.equal(formatSeconds(5400), '90 min');
  assert.equal(formatSeconds(90061), '90061 s');
});

test('window phase is derived from the evaluation clock', () => {
  const w = win();
  assert.equal(windowPhase(w, at('2026-10-06T07:59:59Z')), 'upcoming');
  assert.equal(windowPhase(w, at('2026-10-06T08:00:00Z')), 'active');
  assert.equal(windowPhase(w, at('2026-10-06T09:59:59Z')), 'active');
  assert.equal(windowPhase(w, at('2026-10-06T10:00:00Z')), 'ended');
});

test('a cancelled window is never active', () => {
  const w = win({ status: 'cancelled', cancelled_by: 'bob', cancelled_at: '2026-10-06T07:00:00Z' });
  assert.equal(windowPhase(w, at('2026-10-06T09:00:00Z')), 'cancelled');
});

test('an unusable clock yields unknown, not a guess', () => {
  assert.equal(windowPhase(win(), Number.NaN), 'unknown');
});

test('phase labels are explicit', () => {
  assert.equal(windowPhaseLabel('active'), 'Active now');
  assert.equal(windowPhaseLabel('unknown'), 'Unknown');
});

test('window counts cover only the listed windows', () => {
  const counts = windowCounts(
    [
      win(),
      win({ starts_at: '2026-10-07T08:00:00Z', ends_at: '2026-10-07T09:00:00Z' }),
      win({ status: 'cancelled', cancelled_by: 'b', cancelled_at: '2026-10-06T07:00:00Z' }),
    ],
    at('2026-10-06T09:00:00Z'),
  );
  assert.deepEqual(counts, {
    active: 1,
    upcoming: 1,
    ended: 0,
    cancelled: 1,
    unknown: 0,
    listed: 3,
  });
});

test('offsets are bounded and invalid ones fall back to zero', () => {
  assert.deepEqual(parseAlertingOffsets({ rules_offset: '50', windows_offset: '10000' }), {
    rules: 50,
    windows: 10000,
  });
  assert.deepEqual(parseAlertingOffsets({ rules_offset: '-1', windows_offset: '10001' }), {
    rules: 0,
    windows: 0,
  });
  assert.deepEqual(parseAlertingOffsets({}), { rules: 0, windows: 0 });
});

test('API list paths are fixed shapes with a bounded offset', () => {
  assert.equal(
    alertingListPath('rules', 50),
    `/api/v1/alert-rules?limit=${DEFAULT_ALERTING_PAGE_SIZE}&offset=50`,
  );
  assert.equal(
    alertingListPath('windows', 0),
    `/api/v1/maintenance-windows?limit=${DEFAULT_ALERTING_PAGE_SIZE}&offset=0&include_cancelled=true`,
  );
});

test('page links keep the other list position and the source alerts page', () => {
  const links = alertingPageHrefs('rules', { rules: 50, windows: 20 }, 50, 100, 3);
  assert.equal(links.next, '/alerts?page=3&rules_offset=100&windows_offset=20');
  assert.equal(links.previous, '/alerts?page=3&windows_offset=20');
  const none = alertingPageHrefs('windows', { rules: 0, windows: 0 }, 50, null, 1);
  assert.equal(none.next, null);
  assert.equal(none.previous, null);
});
