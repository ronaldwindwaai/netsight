import assert from 'node:assert/strict';
import test from 'node:test';

import type { Incident, IncidentTimelineEvent } from './api-contracts-incident.ts';
import { parseIncident } from './api-contracts-incident.ts';
import {
  DEFAULT_INCIDENT_PAGE_SIZE,
  DEFAULT_TIMELINE_PAGE_SIZE,
  incidentCounts,
  incidentDetailHref,
  incidentDetailPath,
  incidentHref,
  incidentListPath,
  incidentPageHrefs,
  isIncidentId,
  parseIncidentFilters,
  parseTimelineCursor,
  severityLabel,
  stateLabel,
  timelineEventSummary,
  timelinePath,
} from './incident-view.ts';

const ID = 'incident-0a1b2c3d-0000-4000-8000-0123456789ab';

function incident(overrides: Partial<Incident> = {}): Incident {
  return {
    id: ID,
    title: 'Core switch down',
    severity: 'high',
    state: 'open',
    created_at: '2026-10-06T07:00:00Z',
    updated_at: '2026-10-06T07:05:00Z',
    assignee_id: null,
    evidence_ids: [],
    resolution: null,
    ...overrides,
  };
}

test('labels every state and severity', () => {
  assert.equal(stateLabel('investigating'), 'Investigating');
  assert.equal(stateLabel('open'), 'Open');
  assert.equal(severityLabel('critical'), 'Critical');
  assert.equal(severityLabel('low'), 'Low');
});

test('accepts only contract-shaped incident ids', () => {
  assert.equal(isIncidentId(ID), true);
  assert.equal(isIncidentId(`${ID}x`), false);
  assert.equal(isIncidentId('incident-../../admin'), false);
  assert.equal(isIncidentId(ID.toUpperCase()), false);
  assert.equal(isIncidentId(''), false);
});

test('builds an encoded link only for valid ids', () => {
  assert.equal(incidentHref(ID), `/incidents/${encodeURIComponent(ID)}`);
  assert.equal(incidentHref('javascript:alert(1)'), null);
  assert.equal(incidentHref('incident-1/../../x'), null);
});

test('a hostile title survives parsing as literal text', () => {
  const hostile = '<script>alert(1)</script>"><img src=x onerror=alert(1)>';
  const parsed = parseIncident({ ...incident(), title: hostile });
  assert.equal(parsed?.title, hostile);
});

test('counts are per listed incident and cover every severity and state', () => {
  const counts = incidentCounts([
    incident({ severity: 'critical' }),
    incident({ severity: 'high', state: 'acknowledged' }),
    incident({ severity: 'high' }),
  ]);
  assert.deepEqual(counts.bySeverity, { critical: 1, high: 2, medium: 0, low: 0 });
  assert.equal(counts.byState.open, 2);
  assert.equal(counts.byState.acknowledged, 1);
  assert.equal(counts.byState.closed, 0);
  assert.equal(counts.listed, 3);
});

test('counts of an empty list report zero listed', () => {
  assert.equal(incidentCounts([]).listed, 0);
});

test('filters accept only contract values', () => {
  const filters = parseIncidentFilters({
    state: 'open',
    severity: 'critical',
    assignee_id: ' alice ',
    offset: '100',
  });
  assert.deepEqual(filters, {
    state: 'open',
    severity: 'critical',
    assigneeId: 'alice',
    offset: 100,
  });
});

test('invalid filter values are dropped, never forwarded', () => {
  const filters = parseIncidentFilters({
    state: 'bogus',
    severity: ['critical', 'low'],
    assignee_id: 'x'.repeat(256),
    offset: '-1',
  });
  assert.deepEqual(filters, { state: null, severity: 'critical', assigneeId: null, offset: 0 });
});

test('offset is bounded and numeric only', () => {
  assert.equal(parseIncidentFilters({ offset: '10001' }).offset, 0);
  assert.equal(parseIncidentFilters({ offset: '10000' }).offset, 10000);
  assert.equal(parseIncidentFilters({ offset: '1e3' }).offset, 0);
  assert.equal(parseIncidentFilters({ offset: '12abc' }).offset, 0);
  assert.equal(parseIncidentFilters({}).offset, 0);
});

test('a blank assignee filter is ignored', () => {
  assert.equal(parseIncidentFilters({ assignee_id: '   ' }).assigneeId, null);
});

test('API list path carries only validated filters and encodes the assignee', () => {
  const path = incidentListPath({
    state: 'open',
    severity: null,
    assigneeId: 'a&b=c/../',
    offset: 50,
  });
  assert.equal(
    path,
    `/api/v1/incidents?limit=${DEFAULT_INCIDENT_PAGE_SIZE}&offset=50&state=open&assignee_id=${encodeURIComponent('a&b=c/../')}`,
  );
});

test('page links preserve filters, use next_offset and step back safely', () => {
  const filters = { state: null, severity: 'high' as const, assigneeId: null, offset: 50 };
  const links = incidentPageHrefs(filters, 50, 100);
  assert.equal(links.next, '/incidents?severity=high&offset=100');
  assert.equal(links.previous, '/incidents?severity=high');
  const first = incidentPageHrefs({ ...filters, offset: 0 }, 50, null);
  assert.equal(first.previous, null);
  assert.equal(first.next, null);
  const second = incidentPageHrefs({ ...filters, offset: 20 }, 50, null);
  assert.equal(second.previous, '/incidents?severity=high');
});

test('detail API paths validate the id and cursor', () => {
  assert.equal(incidentDetailPath(ID), `/api/v1/incidents/${encodeURIComponent(ID)}`);
  assert.equal(incidentDetailPath('nope'), null);
  assert.equal(
    timelinePath(ID, 7),
    `/api/v1/incidents/${encodeURIComponent(ID)}/timeline?after_seq=7&limit=${DEFAULT_TIMELINE_PAGE_SIZE}`,
  );
  assert.equal(timelinePath('nope', 0), null);
});

test('timeline cursor accepts only bounded integers', () => {
  assert.equal(parseTimelineCursor('12'), 12);
  assert.equal(parseTimelineCursor(undefined), 0);
  assert.equal(parseTimelineCursor('-3'), 0);
  assert.equal(parseTimelineCursor('1000001'), 0);
  assert.equal(parseTimelineCursor('1.5'), 0);
  assert.equal(parseTimelineCursor(['5', '6']), 5);
});

test('detail href carries the timeline cursor only when past the start', () => {
  assert.equal(incidentDetailHref(ID, 0), `/incidents/${encodeURIComponent(ID)}`);
  assert.equal(incidentDetailHref(ID, 40), `/incidents/${encodeURIComponent(ID)}?after_seq=40`);
  assert.equal(incidentDetailHref('bad', 0), null);
});

function event(overrides: Partial<IncidentTimelineEvent>): IncidentTimelineEvent {
  return {
    id: 'incident-event-0a1b2c3d-0000-4000-8000-0123456789ab',
    incident_id: ID,
    seq: 1,
    occurred_at: '2026-10-06T07:00:00Z',
    actor_id: 'alice',
    kind: 'comment',
    state_from: null,
    state_to: null,
    reason: null,
    message: 'hello',
    subject_id: null,
    ...overrides,
  };
}

test('state-change summary names both states', () => {
  const text = timelineEventSummary(
    event({ kind: 'state-changed', state_from: 'open', state_to: 'acknowledged', message: null }),
  );
  assert.equal(text.label, 'State changed');
  assert.equal(text.detail, 'Open to Acknowledged');
});

test('other kinds are labelled and reference their subject as text', () => {
  const text = timelineEventSummary(
    event({ kind: 'evidence-added', message: null, subject_id: 'ev-1' }),
  );
  assert.equal(text.label, 'Evidence added');
  assert.equal(text.detail, 'ev-1');
  assert.equal(timelineEventSummary(event({ kind: 'comment' })).detail, null);
});
