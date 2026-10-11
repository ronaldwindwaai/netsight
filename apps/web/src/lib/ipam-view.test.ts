import assert from 'node:assert/strict';
import test from 'node:test';

import type { IpamUtilisation } from './api-contracts-ipam.ts';
import {
  DEFAULT_PAGE_SIZE,
  activityPresentation,
  addressesPath,
  basisShort,
  basisText,
  ipamHref,
  parseIpamQuery,
  prefixesPath,
  telemetryNotice,
  utilisationBarPercent,
  utilisationText,
  vlansPath,
} from './ipam-view.ts';

const COMPUTED: IpamUtilisation = {
  state: 'ok',
  basis: 'netbox-and-discovered',
  capacity: 254,
  netbox_addresses: 100,
  discovered_only: 6,
  used: 106,
  reserved: 20,
  free: 128,
  percent: 41.7,
};

test('an empty query is page one of every section with no filter', () => {
  assert.deepEqual(parseIpamQuery({}), {
    prefixesPage: 1,
    vlansPage: 1,
    addressesPage: 1,
    family: null,
    activity: null,
  });
});

test('each section pages on its own and unusable values are dropped', () => {
  const query = parseIpamQuery({
    prefixes_page: '2',
    vlans_page: '0',
    addresses_page: 'x',
    family: '6',
    activity: 'stale',
  });
  assert.deepEqual(query, {
    prefixesPage: 2,
    vlansPage: 1,
    addressesPage: 1,
    family: '6',
    activity: 'stale',
  });
  assert.equal(parseIpamQuery({ family: '5' }).family, null);
  assert.equal(parseIpamQuery({ activity: 'idle' }).activity, null);
  assert.equal(parseIpamQuery({ prefixes_page: '100001' }).prefixesPage, 1);
});

test('the API paths carry only validated values', () => {
  const query = parseIpamQuery({ family: '4', activity: 'stale', addresses_page: '3' });
  assert.equal(prefixesPath(query), `/api/v1/ipam/prefixes?page=1&page_size=${DEFAULT_PAGE_SIZE}&family=4`);
  assert.equal(vlansPath(query), `/api/v1/ipam/vlans?page=1&page_size=${DEFAULT_PAGE_SIZE}`);
  assert.equal(
    addressesPath(query),
    `/api/v1/ipam/addresses?page=3&page_size=${DEFAULT_PAGE_SIZE}&activity=stale`,
  );
  const hostile = parseIpamQuery({ family: '4&x=1', activity: 'stale&page_size=9999' });
  assert.equal(prefixesPath(hostile).includes('x=1'), false);
  assert.equal(addressesPath(hostile).includes('9999'), false);
});

test('page links keep the other sections and filters', () => {
  const query = parseIpamQuery({ prefixes_page: '2', addresses_page: '3', activity: 'stale' });
  assert.equal(ipamHref(query, { addressesPage: 4 }), '/ipam?prefixes_page=2&addresses_page=4&activity=stale');
  assert.equal(ipamHref(query, { activity: null, addressesPage: 1 }), '/ipam?prefixes_page=2');
  assert.equal(ipamHref(parseIpamQuery({}), {}), '/ipam');
});

test('utilisation is always stated with its basis and its capacity', () => {
  const text = utilisationText(COMPUTED);
  assert.match(text, /41\.7%/);
  assert.match(text, /106 of 254/);
  assert.match(text, /usable/);
});

test('unknown utilisation never shows a figure', () => {
  const unknown: IpamUtilisation = {
    state: 'unknown', basis: 'capacity-not-meaningful', capacity: null, netbox_addresses: null,
    discovered_only: null, used: null, reserved: null, free: null, percent: null,
  };
  assert.equal(utilisationText(unknown), 'Not computed');
  assert.doesNotMatch(utilisationText({ ...unknown, basis: 'addresses-unavailable' }), /\d/);
  assert.equal(utilisationBarPercent(unknown), null);
});

test('a prefix marked utilized is said to be the operator declaring it full', () => {
  const marked: IpamUtilisation = { ...COMPUTED, basis: 'marked-utilized', percent: 100 };
  assert.match(utilisationText(marked), /marked as fully utilised in NetBox/i);
  assert.equal(utilisationBarPercent(marked), 100);
});

test('the bar is clamped and absent without a figure', () => {
  assert.equal(utilisationBarPercent(COMPUTED), 41.7);
  assert.equal(utilisationBarPercent({ ...COMPUTED, percent: 100 }), 100);
  assert.equal(utilisationBarPercent({ ...COMPUTED, percent: null, state: 'unknown' }), null);
});

test('every basis is explained in plain words', () => {
  for (const basis of ['netbox-addresses', 'netbox-and-discovered', 'marked-utilized', 'capacity-not-meaningful', 'addresses-unavailable'] as const) {
    assert.ok(basisText(basis).length > 20);
  }
  assert.match(basisText('netbox-addresses'), /telemetry/i);
  assert.match(basisText('capacity-not-meaningful'), /IPv6/);
});

test('activity is a word and an icon, and unknown is not stale', () => {
  for (const activity of ['active', 'stale', 'unknown', 'reserved'] as const) {
    const view = activityPresentation(activity);
    assert.ok(view.label.length > 0 && view.icon.startsWith('bi-') && view.explanation.length > 20);
  }
  assert.notEqual(activityPresentation('unknown').label, activityPresentation('stale').label);
  assert.match(activityPresentation('unknown').explanation, /could not be read/i);
});

test('the telemetry notice says what decides stale and when nothing can be judged', () => {
  const ok = telemetryNotice({ state: 'ok', window_seconds: 86400, sources: ['librenms', 'wazuh'] });
  assert.match(ok.text, /24 hours/);
  assert.match(ok.text, /LibreNMS/);
  assert.equal(ok.judged, true);
  const none = telemetryNotice({ state: 'not-connected', window_seconds: 86400, sources: [] });
  assert.equal(none.judged, false);
  assert.match(none.text, /not judged/i);
  const failing = telemetryNotice({ state: 'unknown', window_seconds: 3600, sources: [] });
  assert.equal(failing.judged, false);
  assert.match(failing.text, /1 hour/);
});

test('every basis has a short label that never claims a figure', () => {
  for (const basis of ['netbox-addresses', 'netbox-and-discovered', 'marked-utilized', 'capacity-not-meaningful', 'addresses-unavailable'] as const) {
    assert.ok(basisShort(basis).length > 5 && !/\d/.test(basisShort(basis)));
  }
});
