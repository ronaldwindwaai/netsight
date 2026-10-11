import assert from 'node:assert/strict';
import test from 'node:test';

import type { FetchState } from './api-response.ts';
import type {
  UnknownDeviceCheck,
  UnknownDeviceLinkSlot,
  UnknownDeviceList,
} from './api-contracts-unknown-devices.ts';
import {
  DEFAULT_PAGE_SIZE,
  checkPresentation,
  findingHref,
  findingsPath,
  listSurface,
  pageHrefs,
  parseFindingsQuery,
  severityPresentation,
  slotLabel,
  slotStatement,
  statePresentation,
  timelinePath,
} from './unknown-device-view.ts';

const listOf = (over: Partial<UnknownDeviceList> = {}): FetchState<UnknownDeviceList> => ({
  kind: 'ok',
  correlationId: 'c',
  data: { state: 'ok', generated_at: '2026-10-11T12:00:00Z', page: 1, page_size: 25, total: 1, items: [], ...over },
});

function failure(kind: string, status: number): FetchState<UnknownDeviceList> {
  return { kind, code: 'X', message: 'm', correlationId: 'c', status } as FetchState<UnknownDeviceList>;
}

const unknownSlot = (reason: UnknownDeviceLinkSlot['reason']): UnknownDeviceLinkSlot => ({
  slot: 'port', basis: 'unknown', value: null, label: null, attachment_kind: null, confidence: null, reason, evidence: [],
});

test('an empty query is the first page of open findings', () => {
  assert.deepEqual(parseFindingsQuery({}), { page: 1, state: 'open', severity: null, assigned: null });
});

test('valid filters are read as typed and an unusable one is dropped', () => {
  assert.deepEqual(parseFindingsQuery({ page: '2', state: 'resolved', severity: 'high', assigned: 'true' }), {
    page: 2, state: 'resolved', severity: 'high', assigned: true,
  });
  assert.equal(parseFindingsQuery({ state: 'closed' }).state, 'open');
  assert.equal(parseFindingsQuery({ state: 'all' }).state, null);
  assert.equal(parseFindingsQuery({ severity: 'severe' }).severity, null);
  assert.equal(parseFindingsQuery({ assigned: 'maybe' }).assigned, null);
  assert.equal(parseFindingsQuery({ page: '0' }).page, 1);
  assert.equal(parseFindingsQuery({ page: ['3', '4'] }).page, 3);
});

test('the API path carries only validated values', () => {
  assert.equal(findingsPath(parseFindingsQuery({})), `/api/v1/unknown-devices?page=1&page_size=${DEFAULT_PAGE_SIZE}&state=open`);
  const all = findingsPath(parseFindingsQuery({ state: 'all', severity: 'low', assigned: 'false' }));
  assert.ok(all.includes('severity=low') && all.includes('assigned=false') && !all.includes('state='));
  const hostile = findingsPath(parseFindingsQuery({ state: 'new&page_size=9999', severity: 'low&x=1' }));
  assert.ok(!hostile.includes('9999') && !hostile.includes('x=1'));
});

test('paging keeps the filters, including an explicit all', () => {
  const query = parseFindingsQuery({ state: 'all', page: '2' });
  const hrefs = pageHrefs(query, 80);
  assert.equal(hrefs.previous, '/unknown-devices?state=all');
  assert.equal(hrefs.next, '/unknown-devices?state=all&page=3');
  assert.deepEqual(pageHrefs(parseFindingsQuery({}), 10), { previous: null, next: null });
});

test('links name a finding by its id, encoded', () => {
  const id = 'unknown-device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc';
  assert.equal(findingHref(id), `/unknown-devices/${id}`);
  assert.equal(timelinePath(id), `/api/v1/unknown-devices/${id}/timeline`);
});

test('every state and severity is a word and an icon, and unknown severity is not low', () => {
  for (const s of ['new', 'acknowledged', 'investigating', 'resolved', 'false-positive'] as const) {
    const view = statePresentation(s);
    assert.ok(view.label.length > 0 && view.icon.startsWith('bi-'));
  }
  for (const s of ['low', 'medium', 'high', 'critical', 'unknown'] as const) {
    const view = severityPresentation(s);
    assert.ok(view.label.length > 0 && view.icon.startsWith('bi-') && view.explanation.length > 10);
  }
  assert.match(severityPresentation('unknown').explanation, /policy/i);
  assert.notEqual(severityPresentation('unknown').label, severityPresentation('low').label);
  assert.equal(statePresentation('false-positive').label, 'False positive');
});

test('a hop that is not known says so and why, in words', () => {
  assert.equal(slotLabel('attachment'), 'Switch or access point');
  assert.match(slotStatement(unknownSlot('source-unavailable')), /No connected source can observe/);
  assert.match(slotStatement(unknownSlot('no-evidence')), /No evidence/);
  assert.match(slotStatement(unknownSlot('conflicting-evidence')), /disagree/i);
  assert.match(slotStatement(unknownSlot('expired')), /no longer hold/i);
  assert.doesNotMatch(slotStatement(unknownSlot('source-unavailable')), /not connected\s*$/i);
});

test('an observed hop shows its value or its label as plain text', () => {
  const slot: UnknownDeviceLinkSlot = {
    slot: 'attachment', basis: 'observed', value: 'device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc',
    label: '<img src=x onerror=alert(1)>', attachment_kind: 'switch', confidence: 0.9, reason: null,
    evidence: [{ id: 'snmp:fdb-1', source: 'snmp', kind: 'switch-mac-table', observed_at: '2026-10-11T12:00:00Z', confidence: 0.9 }],
  };
  assert.equal(slotStatement(slot), '<img src=x onerror=alert(1)>');
  assert.equal(slotStatement({ ...slot, label: null }), slot.value);
});

test('a comparison with NetBox reads as a sentence per field', () => {
  const noMatch: UnknownDeviceCheck = { field: 'mac', result: 'no-match', detail: null };
  assert.match(checkPresentation(noMatch).text, /NetBox has no interface with this MAC/);
  const unchecked: UnknownDeviceCheck = { field: 'ip', result: 'not-checked', detail: 'no address was observed' };
  assert.match(checkPresentation(unchecked).text, /no address was observed/);
  assert.equal(checkPresentation(unchecked).label, 'Not checked');
});

test('each outcome of the read has its own surface', () => {
  const none = parseFindingsQuery({});
  assert.equal(listSurface(failure('forbidden', 403), none), 'permission');
  assert.equal(listSurface(failure('unauthenticated', 401), none), 'unauthenticated');
  assert.equal(listSurface(failure('error', 500), none), 'error');
  assert.equal(listSurface(listOf({ state: 'not-connected', total: 0 }), none), 'not-connected');
  assert.equal(listSurface(listOf({ state: 'unknown', total: 0 }), none), 'unknown');
  assert.equal(listSurface(listOf({ total: 0 }), none), 'empty');
  assert.equal(listSurface(listOf({ total: 0 }), parseFindingsQuery({ severity: 'high' })), 'filtered-empty');
  assert.equal(listSurface(listOf(), none), 'data');
});
