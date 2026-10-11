import assert from 'node:assert/strict';
import test from 'node:test';

import type { FetchState } from './api-response.ts';
import type { InventoryList } from './api-contracts-inventory.ts';
import {
  DEFAULT_PAGE_SIZE,
  NOT_REPORTED,
  classBasisText,
  classLabel,
  degradedSources,
  inventoryPath,
  isInventoryId,
  itemHref,
  listSurface,
  pageHrefs,
  parseInventoryQuery,
  provenancePresentation,
  reconcilePresentation,
} from './inventory-view.ts';

const OK_LIST = (over: Partial<InventoryList> = {}): FetchState<InventoryList> => ({
  kind: 'ok',
  correlationId: 'c',
  data: {
    state: 'ok',
    generated_at: '2026-10-11T12:00:00Z',
    page: 1,
    page_size: 25,
    total: 1,
    sources: [{ source: 'netbox', state: 'ok', observed_at: '2026-10-11T12:00:00Z' }],
    summary: { total: 1, known: 1, unknown: 0, by_class: [], by_source: [] },
    items: [],
    ...over,
  },
});

function failure(kind: string, status: number): FetchState<InventoryList> {
  return { kind, code: 'X', message: 'm', correlationId: 'c', status } as FetchState<InventoryList>;
}

test('an empty query is page one with no filter', () => {
  const query = parseInventoryQuery({});
  assert.deepEqual(query, {
    page: 1,
    assetClass: null,
    site: null,
    status: null,
    source: null,
    known: null,
    q: null,
  });
});

test('each valid filter is read as typed', () => {
  const query = parseInventoryQuery({
    page: '3',
    asset_class: 'server',
    site: 'HQ',
    status: 'offline',
    source: 'both',
    known: 'false',
    q: 'core',
  });
  assert.deepEqual(query, {
    page: 3,
    assetClass: 'server',
    site: 'HQ',
    status: 'offline',
    source: 'both',
    known: false,
    q: 'core',
  });
});

test('an unusable value is dropped, never passed on to the API', () => {
  const query = parseInventoryQuery({
    page: '0',
    asset_class: 'toaster',
    status: 'great',
    source: 'snmp',
    known: 'maybe',
    site: '',
    q: 'x'.repeat(65),
  });
  assert.deepEqual(query, parseInventoryQuery({}));
  assert.equal(parseInventoryQuery({ page: '-1' }).page, 1);
  assert.equal(parseInventoryQuery({ page: '1.5' }).page, 1);
  assert.equal(parseInventoryQuery({ page: '100001' }).page, 1);
  assert.equal(parseInventoryQuery({ q: 'bad\u0000text' }).q, null);
});

test('a repeated parameter uses its first value', () => {
  assert.equal(parseInventoryQuery({ asset_class: ['server', 'printer'] }).assetClass, 'server');
});

test('the API path carries only the filters in use, encoded', () => {
  assert.equal(
    inventoryPath(parseInventoryQuery({})),
    `/api/v1/inventory?page=1&page_size=${DEFAULT_PAGE_SIZE}`,
  );
  const path = inventoryPath(parseInventoryQuery({ q: 'a&b=c d', asset_class: 'iot', known: 'true' }));
  assert.ok(path.startsWith('/api/v1/inventory?'));
  assert.ok(path.includes('q=a%26b%3Dc+d'));
  assert.ok(path.includes('asset_class=iot') && path.includes('known=true'));
  assert.ok(!path.includes('site=') && !path.includes('status='));
});

test('a hostile search can not add a parameter or break out of the path', () => {
  const path = inventoryPath(parseInventoryQuery({ q: '../../admin?x=1#frag&page_size=9999' }));
  const url = new URL(path, 'https://api.test');
  assert.equal(url.pathname, '/api/v1/inventory');
  assert.equal(url.searchParams.get('page_size'), String(DEFAULT_PAGE_SIZE));
  assert.equal(url.searchParams.get('q'), '../../admin?x=1#frag&page_size=9999');
});

test('paging links keep the filters and stop at the ends', () => {
  const query = parseInventoryQuery({ asset_class: 'server', page: '2' });
  const hrefs = pageHrefs(query, 80);
  assert.equal(hrefs.previous, '/inventory?asset_class=server');
  assert.equal(hrefs.next, '/inventory?asset_class=server&page=3');
  assert.deepEqual(pageHrefs(parseInventoryQuery({}), 10), { previous: null, next: null });
  assert.equal(pageHrefs(parseInventoryQuery({ page: '4' }), 80).next, null);
});

test('an asset links to its own page by id', () => {
  assert.equal(itemHref('device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc'), '/inventory/device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc');
});

test('every class has a plain label and unknown assets are not called a device type', () => {
  assert.equal(classLabel('network-device'), 'Network device');
  assert.equal(classLabel('access-point'), 'Access point');
  assert.equal(classLabel('cctv'), 'CCTV');
  assert.equal(classLabel('unknown-asset'), 'Unknown asset');
  assert.equal(classLabel('unclassified'), 'Unclassified');
});

test('the class basis says who decided, and unclassified is not a guess', () => {
  assert.match(classBasisText('role-map'), /NetBox role/);
  assert.match(classBasisText('type-map'), /device type/);
  assert.match(classBasisText('unmapped'), /map has no entry/i);
  assert.match(classBasisText('not-in-netbox'), /NetBox has no record/);
});

test('provenance is a word and an icon, never colour alone', () => {
  for (const p of ['netbox', 'discovered', 'both', 'conflict', 'unknown'] as const) {
    const view = provenancePresentation(p);
    assert.ok(view.label.length > 0 && view.icon.startsWith('bi-') && view.explanation.length > 20);
  }
  assert.equal(provenancePresentation('conflict').label, 'Conflict');
  assert.match(provenancePresentation('conflict').explanation, /NetBox/);
  assert.equal(provenancePresentation('unknown').label, 'Not reported');
});

test('the reconcile status explains itself and never reads as healthy when it could not be checked', () => {
  assert.equal(reconcilePresentation('reconciled').label, 'Reconciled');
  assert.equal(reconcilePresentation('not-checked').label, 'Not checked');
  assert.notEqual(reconcilePresentation('not-checked').theme, 'success');
  assert.match(reconcilePresentation('ambiguous').explanation, /name/i);
});

test('each outcome of the read has its own surface', () => {
  const none = parseInventoryQuery({});
  assert.equal(listSurface(failure('forbidden', 403), none), 'permission');
  assert.equal(listSurface(failure('unauthenticated', 401), none), 'unauthenticated');
  assert.equal(listSurface(failure('error', 500), none), 'error');
  assert.equal(listSurface(failure('rate_limited', 429), none), 'error');
  assert.equal(listSurface(OK_LIST({ state: 'not-connected', total: 0, summary: null }), none), 'not-connected');
  assert.equal(listSurface(OK_LIST({ state: 'unknown', total: 0, summary: null }), none), 'unknown');
  assert.equal(listSurface(OK_LIST({ total: 0 }), none), 'empty');
  assert.equal(listSurface(OK_LIST({ total: 0 }), parseInventoryQuery({ q: 'zzz' })), 'filtered-empty');
  assert.equal(listSurface(OK_LIST(), none), 'data');
});

test('only sources that were not read are reported as degraded', () => {
  const degraded = degradedSources([
    { source: 'netbox', state: 'ok', observed_at: '2026-10-11T12:00:00Z' },
    { source: 'librenms', state: 'unknown', observed_at: null },
    { source: 'wazuh', state: 'not-connected', observed_at: null },
  ]);
  assert.deepEqual(degraded.map((s) => [s.source, s.state]), [
    ['librenms', 'unknown'],
    ['wazuh', 'not-connected'],
  ]);
  assert.equal(NOT_REPORTED, 'Not reported');
});

test('only a canonical asset id may be placed in an API path', () => {
  assert.equal(isInventoryId('device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc'), true);
  for (const bad of ['', 'device-1', '../etc', 'DEVICE-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc', 'device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc/x', 'device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc?x=1']) {
    assert.equal(isInventoryId(bad), false, bad);
  }
});
