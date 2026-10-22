import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { UnknownDeviceDetailBody } from '@/components/unknown-device-detail-body';
import { FindingsFilters, UnknownDevicesBody } from '@/components/unknown-devices-body';
import type {
  UnknownDeviceDetail,
  UnknownDeviceList,
  UnknownDeviceTimeline,
} from '@/lib/api-contracts-unknown-devices';
import { parseFindingsQuery } from '@/lib/unknown-device-view';
import {
  FINDING_ID,
  HOSTILE,
  failureState,
  finding,
  findingDetail,
  findingList,
  okState,
  proposedAction,
  timeline,
} from '@/test/step8-fixtures';

afterEach(() => cleanup());

const NONE = parseFindingsQuery({});
const list = (state: Parameters<typeof UnknownDevicesBody>[0]['state'], query = NONE) => (
  <UnknownDevicesBody state={state} query={query} />
);
const text = () => document.body.textContent ?? '';

describe('findings list', () => {
  it('every outcome of the read has its own surface and no table', () => {
    const empty = findingList({ items: [], total: 0 });
    const outcomes: Array<[Parameters<typeof UnknownDevicesBody>[0]['state'], RegExp]> = [
      [failureState<UnknownDeviceList>('forbidden', 403), /not available to your role/],
      [failureState<UnknownDeviceList>('error', 500), /Unable to load data/],
      [okState({ ...empty, state: 'not-connected' }), /Finding store not connected/],
      [okState({ ...empty, state: 'unknown' }), /Finding store state unknown/],
      [okState(empty), /No unknown devices are open/],
    ];
    for (const [state, expected] of outcomes) {
      const { unmount } = render(list(state));
      assert.match(text(), expected);
      assert.equal(screen.queryAllByRole('table').length, 0);
      unmount();
    }
  });

  it('an empty filtered result is not the same as an empty store', () => {
    render(list(okState(findingList({ items: [], total: 0 })), parseFindingsQuery({ severity: 'high' })));
    assert.match(text(), /No findings match these filters/);
    assert.doesNotMatch(text(), /No unknown devices are open/);
  });

  it('shows state, severity, assignment and the proposal as words', () => {
    render(list(okState(findingList())));
    const rows = within(screen.getByRole('table')).getAllByRole('row');
    assert.equal(rows.length, 3);
    assert.match(rows[1].textContent ?? '', /aa:bb:cc:00:11:22.*10\.0\.5\.9.*printer-x.*New.*Medium.*Unassigned/);
    assert.doesNotMatch(rows[1].textContent ?? '', /Quarantine proposed/);
    assert.match(rows[2].textContent ?? '', /Investigating.*High.*oidc:tech-9/);
    assert.match(rows[2].textContent ?? '', /Quarantine proposed, not executed/);
    assert.match(rows[2].textContent ?? '', /Not reported/);
  });

  it('links to the finding detail by its identifier', () => {
    render(list(okState(findingList())));
    const link = screen.getByRole('link', { name: 'aa:bb:cc:00:11:22' });
    assert.equal(link.getAttribute('href'), `/unknown-devices/${FINDING_ID}`);
  });

  it('shows unknown severity as unknown, not as low', () => {
    const unknown = finding({ severity: 'unknown', severity_basis: 'no-policy' });
    render(list(okState(findingList({ items: [unknown], total: 1 }))));
    assert.match(text(), /Unknown severity/);
    assert.doesNotMatch(text(), /\bLow\b/);
  });

  it('renders hostile endpoint text as text', () => {
    const hostile = finding({ endpoint: { ip: '10.0.5.9', mac: 'aa:bb:cc:00:11:22', hostname: HOSTILE } });
    const { container } = render(list(okState(findingList({ items: [hostile], total: 1 }))));
    assert.ok((container.textContent ?? '').includes(HOSTILE));
    assert.equal(container.querySelector('img'), null);
  });

  it('pages with the filters kept in the links', () => {
    const many = findingList({ total: 60 });
    render(list(okState(many), parseFindingsQuery({ severity: 'high', page: '2' })));
    const nav = screen.getByRole('navigation', { name: 'Finding pages' });
    assert.equal(within(nav).getByRole('link', { name: /Previous/ }).getAttribute('href'), '/unknown-devices?severity=high');
    assert.equal(
      within(nav).getByRole('link', { name: /Next/ }).getAttribute('href'),
      '/unknown-devices?severity=high&page=3',
    );
  });
});

describe('findings filters', () => {
  it('marks the current choices and offers a way back', () => {
    render(<FindingsFilters query={parseFindingsQuery({ state: 'resolved', assigned: 'false' })} />);
    const nav = screen.getByRole('navigation', { name: 'Finding filters' });
    assert.equal(within(nav).getByRole('link', { name: 'Resolved' }).getAttribute('aria-current'), 'true');
    assert.equal(within(nav).getByRole('link', { name: 'Unassigned' }).getAttribute('aria-current'), 'true');
    assert.equal(within(nav).getByRole('link', { name: 'Open' }).getAttribute('aria-current'), null);
    assert.equal(within(nav).getByRole('link', { name: 'Clear filters' }).getAttribute('href'), '/unknown-devices');
  });

  it('builds links that change one filter and keep the others', () => {
    render(<FindingsFilters query={parseFindingsQuery({ severity: 'high' })} />);
    assert.equal(screen.getByRole('link', { name: 'All states' }).getAttribute('href'), '/unknown-devices?state=all&severity=high');
    assert.equal(screen.getByRole('link', { name: 'Any severity' }).getAttribute('href'), '/unknown-devices');
    assert.equal(screen.getByRole('link', { name: 'Assigned' }).getAttribute('href'), '/unknown-devices?severity=high&assigned=true');
  });

  it('shows no clear link when nothing is filtered', () => {
    render(<FindingsFilters query={NONE} />);
    assert.equal(screen.queryAllByRole('link', { name: 'Clear filters' }).length, 0);
  });
});

describe('finding detail', () => {
  const detail = (
    state: Parameters<typeof UnknownDeviceDetailBody>[0]['state'],
    timelineState: Parameters<typeof UnknownDeviceDetailBody>[0]['timeline'] = okState(timeline()),
  ) => <UnknownDeviceDetailBody state={state} actions={<p>ACTIONS-SLOT</p>} timeline={timelineState} permissions={[]} />;

  it('every outcome of the read has its own surface and no actions', () => {
    const outcomes: Array<[Parameters<typeof UnknownDeviceDetailBody>[0]['state'], RegExp]> = [
      [failureState<UnknownDeviceDetail>('forbidden', 403), /not available to your role/],
      [failureState<UnknownDeviceDetail>('not_found', 404), /Finding not found/],
      [failureState<UnknownDeviceDetail>('error', 500), /Unable to load data/],
      [okState(findingDetail(null, 'not-connected')), /Finding store not connected/],
      [okState(findingDetail(null, 'unknown')), /Finding store state unknown/],
    ];
    for (const [state, expected] of outcomes) {
      const { unmount } = render(detail(state));
      assert.match(text(), expected);
      assert.doesNotMatch(text(), /ACTIONS-SLOT/);
      unmount();
    }
  });

  it('shows the endpoint, the chain with observed values and unknown hops with their reasons', () => {
    render(detail(okState(findingDetail())));
    const chain = screen.getByRole('list', { name: /Evidence chain/ });
    const hops = within(chain).getAllByRole('listitem').filter((li) => li.matches('li.list-group-item'));
    assert.equal(hops.length, 5);
    assert.match(hops[0].textContent ?? '', /IP address.*Observed.*10\.0\.5\.9.*librenms.*device-poll/);
    assert.match(hops[1].textContent ?? '', /MAC address.*Observed.*aa:bb:cc:00:11:22/);
    for (const hop of hops.slice(2)) {
      assert.match(hop.textContent ?? '', /Unknown/);
      assert.match(hop.textContent ?? '', /No connected source can observe this/);
    }
    assert.match(text(), /Set by the default of the operator severity policy/);
  });

  it('lists every NetBox comparison check in words', () => {
    render(detail(okState(findingDetail())));
    assert.match(text(), /NetBox assigns this address to no device/);
    assert.match(text(), /NetBox has no interface with this MAC address/);
    assert.match(text(), /NetBox has no device of this name/);
    assert.match(text(), /NetBox is read, never written/);
  });

  it('explains a name-matches-mac-does-not comparison and keeps the plain one quiet', () => {
    const spoof = finding({
      comparison: {
        checked_at: '2026-10-11T12:00:00Z',
        reason: 'name-matches-mac-does-not',
        checks: [
          { field: 'ip', result: 'no-match', detail: null },
          { field: 'mac', result: 'no-match', detail: null },
          { field: 'hostname', result: 'match', detail: null },
        ],
      },
    });
    const { unmount } = render(detail(okState(findingDetail(spoof))));
    assert.match(text(), /name matched a NetBox device but the MAC address did not/);
    unmount();
    render(detail(okState(findingDetail())));
    assert.doesNotMatch(text(), /name matched a NetBox device/);
  });

  it('labels a suppressed sighting on the timeline', () => {
    const base = timeline().events[0];
    const sighting = { ...base, id: 'unknown-device-event-6f1c2a9e-0b1d-5c3e-8f4a-123456789009', seq: 9, kind: 'suppressed-sighting' as const };
    render(detail(okState(findingDetail()), okState(timeline({ events: [sighting] }))));
    assert.match(text(), /Seen again while dismissed/);
  });

  it('shows a proposed quarantine as a recommendation with no control to execute it', () => {
    render(detail(okState(findingDetail(finding({ proposed_action: proposedAction })))));
    assert.match(text(), /Isolate this endpoint \(quarantine\)/);
    assert.match(text(), /recommendation only/);
    assert.match(text(), /Nothing has been isolated/);
    assert.equal(screen.queryAllByRole('button').length, 0);
    assert.equal(screen.queryAllByRole('link', { name: /isolate|quarantine/i }).length, 0);
  });

  it('shows no proposal card when none was made', () => {
    render(detail(okState(findingDetail())));
    assert.doesNotMatch(text(), /Proposed action/);
  });

  it('puts the workflow slot in place for an acting viewer', () => {
    render(detail(okState(findingDetail())));
    assert.match(text(), /ACTIONS-SLOT/);
  });

  it('renders the timeline in order with state changes spelled out and comments as text', () => {
    const { container } = render(detail(okState(findingDetail())));
    const card = screen.getByText('Timeline').closest('.card') as HTMLElement;
    const events = within(card).getAllByRole('listitem');
    assert.equal(events.length, 3);
    assert.match(events[0].textContent ?? '', /Detected.*system:unknown-device-scan/);
    assert.match(events[1].textContent ?? '', /State changed from New to Acknowledged.*oidc:analyst-1/);
    assert.ok((events[2].textContent ?? '').includes(HOSTILE));
    assert.equal(container.querySelector('img'), null);
  });

  it('says so when the timeline is empty, forbidden, unread or has more pages', () => {
    const cases: Array<[Parameters<typeof UnknownDeviceDetailBody>[0]['timeline'], RegExp]> = [
      [okState(timeline({ events: [] })), /No events yet/],
      [failureState<UnknownDeviceTimeline>('forbidden', 403), /timeline is not available to your role/],
      [null, /Your role does not read the timeline/],
      [okState({ ...timeline(), state: 'unknown' }), /Finding store state unknown/],
      [failureState<UnknownDeviceTimeline>('error', 500), /Unable to load data/],
      [okState(timeline({ next_after_seq: 3 })), /more exist than fit/],
    ];
    for (const [state, expected] of cases) {
      const { unmount } = render(detail(okState(findingDetail()), state));
      assert.match(text(), expected);
      unmount();
    }
  });

  it('renders hostile endpoint text as text', () => {
    const hostile = finding({ endpoint: { ip: '10.0.5.9', mac: 'aa:bb:cc:00:11:22', hostname: HOSTILE } });
    const { container } = render(detail(okState(findingDetail(hostile))));
    assert.ok((container.textContent ?? '').includes(HOSTILE));
    assert.equal(container.querySelector('img'), null);
  });
});
