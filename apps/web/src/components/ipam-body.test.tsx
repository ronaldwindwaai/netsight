import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import type { ReactElement } from 'react';

import { cleanup, render, screen, within } from '@testing-library/react';

import { FindingsSummaryCard, InventorySummaryCard, IpamSummaryCard } from '@/components/counts-cards';
import { IpamAddressesCard, IpamPrefixesCard, IpamVlansCard } from '@/components/ipam-body';
import type { IpamAddressList, IpamPrefixList, IpamVlanList } from '@/lib/api-contracts-ipam';
import { parseIpamQuery } from '@/lib/ipam-view';
import {
  HOSTILE,
  failureState,
  findingSummary,
  inventorySummary,
  ipamAddress,
  ipamAddresses,
  ipamNotOk,
  ipamPrefix,
  ipamPrefixes,
  ipamRootPrefix,
  ipamSummary,
  ipamVlans,
  okState,
  staleAddress,
  telemetryNone,
} from '@/test/step8-fixtures';

afterEach(() => cleanup());

const NONE = parseIpamQuery({});

describe('prefixes', () => {
  const view = (state: Parameters<typeof IpamPrefixesCard>[0]['state'], query = NONE) => (
    <IpamPrefixesCard state={state} query={query} />
  );

  it('every outcome of the read has its own surface', () => {
    const outcomes: Array<[Parameters<typeof IpamPrefixesCard>[0]['state'], RegExp]> = [
      [failureState<IpamPrefixList>('forbidden', 403), /not available to your role/],
      [failureState<IpamPrefixList>('error', 500), /Unable to load data/],
      [okState(ipamNotOk('prefixes', 'not-connected')), /NetBox not connected/],
      [okState(ipamNotOk('prefixes', 'unknown')), /NetBox state unknown/],
      [okState(ipamPrefixes({ items: [], total: 0 })), /NetBox lists no prefixes/],
    ];
    for (const [state, expected] of outcomes) {
      const { unmount } = render(view(state));
      assert.match(document.body.textContent ?? '', expected);
      assert.equal(screen.queryAllByRole('table').length, 0);
      unmount();
    }
  });

  it('an empty filtered result is not the same as an empty NetBox', () => {
    render(view(okState(ipamPrefixes({ items: [], total: 0 })), parseIpamQuery({ family: '6' })));
    assert.match(document.body.textContent ?? '', /No prefixes match this filter/);
  });

  it('shows the tree: depth is indented and announced', () => {
    render(view(okState(ipamPrefixes())));
    const rows = within(screen.getByRole('table')).getAllByRole('row');
    assert.equal(rows.length, 3);
    assert.match(rows[1].textContent ?? '', /Level 1:.*10\.0\.0\.0\/8/);
    assert.match(rows[2].textContent ?? '', /Level 2:.*10\.0\.0\.0\/24/);
    const indent = (row: HTMLElement) => row.querySelector<HTMLElement>('td div[style]')?.style.paddingLeft;
    assert.equal(indent(rows[1]), '0rem');
    assert.equal(indent(rows[2]), '1.25rem');
  });

  it('shows utilisation as text, a bar and its basis', () => {
    render(view(okState(ipamPrefixes())));
    const row = within(screen.getByRole('table')).getAllByRole('row')[2];
    const text = row.textContent ?? '';
    assert.match(text, /41\.7% \(106 of 254 usable addresses\)/);
    assert.match(text, /Basis: NetBox addresses plus telemetry/);
    assert.match(text, /20 reserved, 128 free/);
    const bar = within(row).getByRole('progressbar');
    assert.equal(bar.getAttribute('aria-valuenow'), '41.7');
  });

  it('draws no bar and no figure when utilisation is not computed', () => {
    const unknown = ipamRootPrefix({
      utilisation: {
        state: 'unknown', basis: 'capacity-not-meaningful', capacity: null, netbox_addresses: null,
        discovered_only: null, used: null, reserved: null, free: null, percent: null,
      },
    });
    render(view(okState(ipamPrefixes({ items: [unknown], total: 1 }))));
    const row = within(screen.getByRole('table')).getAllByRole('row')[1];
    assert.match(row.textContent ?? '', /Not computed/);
    assert.match(row.textContent ?? '', /Capacity not meaningful/);
    assert.equal(within(row).queryAllByRole('progressbar').length, 0);
  });

  it('says a prefix marked utilised is the operator declaring it full', () => {
    const marked = ipamRootPrefix({
      utilisation: { state: 'ok', basis: 'marked-utilized', capacity: 254, netbox_addresses: 3, discovered_only: 0, used: 3, reserved: null, free: null, percent: 100 },
    });
    render(view(okState(ipamPrefixes({ items: [marked], total: 1 }))));
    assert.match(document.body.textContent ?? '', /marked as fully utilised in NetBox/);
  });

  it('lists reserved ranges under the prefix and notes the ones not listed', () => {
    const many = ipamPrefix({ reserved_ranges_total: 20 });
    render(view(okState(ipamPrefixes({ items: [many], total: 1 }))));
    const details = document.querySelector('details');
    assert.ok(details);
    assert.match(details?.textContent ?? '', /20 reserved ranges/);
    assert.match(details?.textContent ?? '', /10\.0\.0\.100 – 10\.0\.0\.119 \(20\)/);
    assert.match(details?.textContent ?? '', /and 19 more/);
  });

  it('names a missing VLAN honestly and keeps the family filter in the links', () => {
    render(view(okState(ipamPrefixes()), parseIpamQuery({ family: '4' })));
    assert.match(document.body.textContent ?? '', /None named/);
    assert.equal(screen.getByRole('link', { name: 'IPv6' }).getAttribute('href'), '/ipam?family=6');
    assert.equal(screen.getByRole('link', { name: 'All' }).getAttribute('href'), '/ipam');
  });

  it('renders hostile text as text', () => {
    const hostile = ipamPrefix({ description: HOSTILE, site: HOSTILE, role: HOSTILE });
    const { container } = render(view(okState(ipamPrefixes({ items: [hostile], total: 1 }))));
    assert.ok((container.textContent ?? '').includes(HOSTILE));
    assert.equal(container.querySelector('img'), null);
  });
});

describe('VLANs', () => {
  it('every outcome has its own surface and a missing count is Not reported', () => {
    const { unmount } = render(<IpamVlansCard state={failureState<IpamVlanList>('forbidden', 403)} query={NONE} />);
    assert.match(document.body.textContent ?? '', /not available to your role/);
    unmount();
    render(<IpamVlansCard state={okState(ipamNotOk('vlans', 'unknown'))} query={NONE} />);
    assert.match(document.body.textContent ?? '', /NetBox state unknown/);
    cleanup();
    const unread = ipamVlans({
      items: [{ id: 'ipam-vlan-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc', vid: 20, name: HOSTILE, status: null, site: null, group: null, description: null, prefix_count: null }],
    });
    const { container } = render(<IpamVlansCard state={okState(unread)} query={NONE} />);
    const row = within(screen.getByRole('table')).getAllByRole('row')[1].textContent ?? '';
    assert.match(row, /Not reported/);
    assert.ok((container.textContent ?? '').includes(HOSTILE));
    assert.equal(container.querySelector('img'), null);
  });
});

describe('IP usage', () => {
  const view = (state: Parameters<typeof IpamAddressesCard>[0]['state'], query = NONE) => (
    <IpamAddressesCard state={state} query={query} />
  );

  it('shows active and stale with the witness and says what decides it', () => {
    render(view(okState(ipamAddresses())));
    const rows = within(screen.getByRole('table')).getAllByRole('row');
    assert.match(rows[1].textContent ?? '', /10\.0\.0\.15.*Active.*LibreNMS.*2026-10-11 12:00:00 UTC/);
    assert.match(rows[2].textContent ?? '', /10\.0\.0\.16.*Stale.*Not seen/);
    assert.match(document.body.textContent ?? '', /Seen means reported by LibreNMS within the last 24 hours/);
  });

  it('offers the activity filters with their counts', () => {
    render(view(okState(ipamAddresses()), parseIpamQuery({ activity: 'stale' })));
    assert.equal(screen.getByRole('link', { name: 'Stale (1)' }).getAttribute('href'), '/ipam?activity=stale');
    assert.equal(screen.getByRole('link', { name: 'Active (1)' }).getAttribute('href'), '/ipam?activity=active');
    assert.equal(screen.getByRole('link', { name: 'All' }).getAttribute('href'), '/ipam');
  });

  it('with no telemetry nothing is judged: the notice says so and no address is called stale', () => {
    const unjudged = ipamAddresses({
      telemetry: telemetryNone,
      items: [staleAddress({ activity: 'unknown' })],
      activity_counts: { active: 0, stale: 0, unknown: 1, reserved: 0 },
    });
    render(view(okState(unjudged)));
    assert.match(document.body.textContent ?? '', /activity is not judged/);
    assert.match(document.body.textContent ?? '', /never as stale/);
    const row = within(screen.getByRole('table')).getAllByRole('row')[1].textContent ?? '';
    assert.match(row, /Unknown/);
    assert.doesNotMatch(row, /Stale/);
  });

  it('every outcome of the read has its own surface', () => {
    const outcomes: Array<[Parameters<typeof IpamAddressesCard>[0]['state'], RegExp]> = [
      [failureState<IpamAddressList>('forbidden', 403), /not available to your role/],
      [failureState<IpamAddressList>('rate_limited', 429), /Too many requests/],
      [okState(ipamNotOk('addresses', 'not-connected')), /NetBox not connected/],
      [okState(ipamNotOk('addresses', 'unknown')), /NetBox state unknown/],
    ];
    for (const [state, expected] of outcomes) {
      const { unmount } = render(view(state));
      assert.match(document.body.textContent ?? '', expected);
      unmount();
    }
  });

  it('an empty page for a filter is explained, not hidden', () => {
    render(view(okState(ipamAddresses({ items: [], total: 0 })), parseIpamQuery({ activity: 'stale' })));
    assert.match(document.body.textContent ?? '', /No addresses match this filter/);
  });

  it('names a source that was not read', () => {
    render(view(okState(ipamAddresses())));
    assert.match(document.body.textContent ?? '', /Wazuh is not connected/);
  });

  it('renders hostile DNS names as text', () => {
    const { container } = render(view(okState(ipamAddresses({ items: [ipamAddress({ dns_name: HOSTILE })], total: 1 }))));
    assert.ok((container.textContent ?? '').includes(HOSTILE));
    assert.equal(container.querySelector('img'), null);
  });
});

describe('counts-only cards', () => {
  it('the inventory card shows numbers and no asset', () => {
    render(<InventorySummaryCard state={okState(inventorySummary())} />);
    const text = document.body.textContent ?? '';
    assert.match(text, /Assets\s*3/);
    assert.match(text, /Server: 2/);
    assert.match(text, /Your role does not see individual assets/);
    assert.equal(screen.queryAllByRole('link').length, 0);
    assert.equal(screen.queryAllByRole('table').length, 0);
  });

  it('the IPAM card reports what could not be read as Not reported and never as zero', () => {
    const summary = ipamSummary();
    const counts = { ...summary.counts!, active_addresses: null, stale_addresses: null, discovered_only_addresses: null, unknown_activity_addresses: 120 };
    render(<IpamSummaryCard state={okState({ ...summary, counts, telemetry: telemetryNone })} />);
    const text = document.body.textContent ?? '';
    assert.match(text, /Active addresses\s*Not reported/);
    assert.match(text, /Stale addresses\s*Not reported/);
    assert.match(text, /active and stale are not judged/);
  });

  it('the findings card shows state and severity counts only', () => {
    render(<FindingsSummaryCard state={okState(findingSummary())} />);
    const text = document.body.textContent ?? '';
    assert.match(text, /Open findings\s*3/);
    assert.match(text, /New: 2/);
    assert.match(text, /Unknown severity: 3/);
    assert.equal(screen.queryAllByRole('link').length, 0);
  });

  it('each card has a surface for every non-ok outcome', () => {
    const cases: Array<[ReactElement, RegExp]> = [
      [<InventorySummaryCard key="a" state={failureState('forbidden', 403)} />, /inventory:read-summary/],
      [<IpamSummaryCard key="b" state={okState(ipamSummary('not-connected'))} />, /NetBox not connected/],
      [<FindingsSummaryCard key="c" state={okState(findingSummary('unknown'))} />, /state unknown/],
      [<InventorySummaryCard key="d" state={failureState('error', 500)} />, /Unable to load data/],
    ];
    for (const [element, expected] of cases) {
      const { unmount } = render(element);
      assert.match(document.body.textContent ?? '', expected);
      unmount();
    }
  });
});
