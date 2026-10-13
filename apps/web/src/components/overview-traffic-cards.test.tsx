import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { OverviewApplicationMix, OverviewTopDestinations } from '@/components/overview-traffic-cards';
import type {
  TrafficApplicationsResponse,
  TrafficDestinationsResponse,
} from '@/lib/api-contracts-traffic-explorer';
import {
  COHORT_SUFFICIENT,
  COHORT_TOO_FEW,
  HOSTILE,
  applicationFixture,
  applicationsFixture,
  destinationFixture,
  destinationsFixture,
  emptyApplications,
  emptyDestinations,
  failureState,
  okState,
} from '@/test/traffic-fixtures';

afterEach(() => cleanup());

const text = () => document.body.textContent ?? '';

const WITHHELD = {
  visibility: 'withheld',
  bytes: null,
  packets: null,
  share: null,
  endpoints: null,
  users: null,
  domain: null,
  asn: null,
  country: null,
  first_seen: null,
  last_seen: null,
} as const;

function destinations(over: Partial<TrafficDestinationsResponse> = {}): TrafficDestinationsResponse {
  return destinationsFixture({
    items: [
      destinationFixture({ rank: 1, address: '203.0.113.9', bytes: 600_000_000, share: 0.6 }),
      destinationFixture({ rank: 2, address: '198.51.100.7', bytes: 400_000_000, share: 0.4 }),
    ],
    ...over,
  });
}

describe('Top destinations', () => {
  it('is Restricted, not empty, for a role without traffic access', () => {
    render(<OverviewTopDestinations state={null} />);
    const card = screen.getByRole('region', { name: /Top destinations/i });
    assert.match(card.textContent ?? '', /Restricted/);
    assert.match(card.textContent ?? '', /traffic:read/);
    assert.equal(within(card).queryAllByRole('listitem').length, 0);
  });

  it('a refusal from the API is also Restricted', () => {
    render(<OverviewTopDestinations state={failureState<TrafficDestinationsResponse>('forbidden', 403)} />);
    assert.match(text(), /Restricted/);
  });

  it('not connected keeps the explicit not-connected surface', () => {
    render(<OverviewTopDestinations state={okState(emptyDestinations('not-connected'))} />);
    assert.match(text(), /Flow telemetry not connected/);
    assert.equal(screen.queryAllByRole('listitem').length, 0);
  });

  it('unknown is unknown and nothing is ranked', () => {
    render(<OverviewTopDestinations state={okState(emptyDestinations('unknown'))} />);
    assert.match(text(), /Traffic state unknown/);
    assert.equal(screen.queryAllByRole('listitem').length, 0);
  });

  it('an API error is an error', () => {
    render(<OverviewTopDestinations state={failureState<TrafficDestinationsResponse>('error', 500)} />);
    assert.match(text(), /Unable to load data/);
  });

  it('a valid empty window is empty, not a failure', () => {
    render(<OverviewTopDestinations state={okState(destinations({ items: [] }))} />);
    assert.match(text(), /No traffic in this window/);
  });

  it('ranks destination addresses with their volume and links to the destinations page', () => {
    render(<OverviewTopDestinations state={okState(destinations())} />);
    const card = screen.getByRole('region', { name: /Top destinations/i });
    assert.match(card.textContent ?? '', /203\.0\.113\.9/);
    assert.match(card.textContent ?? '', /600 MB/);
    assert.equal(within(card).getAllByRole('listitem').length, 2);
    assert.equal(
      within(card).getByRole('link', { name: /All destinations/ }).getAttribute('href'),
      '/traffic/destinations?preset=24h',
    );
  });

  it('a destination a small group reached shows its address and no figure at all', () => {
    const state = okState(
      destinations({
        cohort: COHORT_TOO_FEW,
        items: [
          destinationFixture({ rank: 1, address: '203.0.113.9', bytes: 600_000_000, share: 0.6 }),
          destinationFixture({ rank: 2, address: '198.51.100.7', ...WITHHELD }),
        ],
      }),
    );
    render(<OverviewTopDestinations state={state} />);
    const card = screen.getByRole('region', { name: /Top destinations/i });
    const rows = within(card).getAllByRole('listitem');
    assert.match(rows[1].textContent ?? '', /198\.51\.100\.7/);
    assert.match(rows[1].textContent ?? '', /Withheld \(fewer than 5 endpoints\)/);
    assert.doesNotMatch(rows[1].textContent ?? '', /\d+(\.\d+)? ?(B|KB|MB|GB)|%/);
    assert.equal(rows[1].querySelectorAll('.progress').length, 0);
    assert.match(card.textContent ?? '', /withheld because fewer than 5 internal endpoints/);
  });

  it('a sufficient cohort says nothing is withheld', () => {
    render(<OverviewTopDestinations state={okState(destinations({ cohort: COHORT_SUFFICIENT }))} />);
    assert.match(text(), /at least 5 internal endpoints/);
    assert.doesNotMatch(text(), /Withheld/);
  });

  it('hostile addresses are only text', () => {
    const hostile = destinations({ items: [destinationFixture({ address: HOSTILE.slice(0, 40) })] });
    render(<OverviewTopDestinations state={okState(hostile)} />);
    assert.equal(document.querySelectorAll('img, script, iframe').length, 0);
  });
});

describe('Application mix', () => {
  function show(state: ReturnType<typeof okState<TrafficApplicationsResponse>> | ReturnType<typeof failureState<TrafficApplicationsResponse>> | null) {
    return render(<OverviewApplicationMix state={state} />);
  }

  it('is Restricted for a role without traffic access', () => {
    show(null);
    const card = screen.getByRole('region', { name: /Application mix/i });
    assert.match(card.textContent ?? '', /Restricted/);
    assert.match(card.textContent ?? '', /traffic:read/);
  });

  it('not connected and unknown are explicit and show no applications', () => {
    show(okState(emptyApplications('not-connected')));
    assert.match(text(), /Application telemetry not connected/);
    cleanup();
    show(okState(emptyApplications('unknown')));
    assert.match(text(), /Traffic state unknown/);
    assert.equal(screen.queryAllByRole('listitem').length, 0);
  });

  it('a source that reports no applications says so instead of showing an empty mix', () => {
    show(okState(emptyApplications('unknown', { unsupported: ['application'] })));
    assert.match(text(), /does not report applications/);
  });

  it('an API error is an error', () => {
    show(failureState<TrafficApplicationsResponse>('error', 500));
    assert.match(text(), /Unable to load data/);
  });

  it('a valid empty window is empty', () => {
    show(okState(applicationsFixture({ items: [], total_bytes: 0 })));
    assert.match(text(), /No applications in this window/);
  });

  it('shows source-reported applications with their share of all bytes, never an estimate', () => {
    show(
      okState(
        applicationsFixture({
          items: [
            applicationFixture(),
            applicationFixture({ rank: 2, application: 'Zoom', bytes: 100_000_000, share: 0.25 }),
          ],
        }),
      ),
    );
    const card = screen.getByRole('region', { name: /Application mix/i });
    assert.match(card.textContent ?? '', /Microsoft 365/);
    assert.match(card.textContent ?? '', /40%/);
    assert.match(card.textContent ?? '', /Zoom/);
    assert.match(card.textContent ?? '', /share of all bytes/i);
    assert.equal(
      within(card).getByRole('link', { name: /All applications/ }).getAttribute('href'),
      '/traffic/applications?preset=24h',
    );
  });

  it('hostile application names are only text', () => {
    show(okState(applicationsFixture({ items: [applicationFixture({ application: HOSTILE })] })));
    assert.equal(document.querySelectorAll('img, script, iframe').length, 0);
    assert.ok(text().includes(HOSTILE));
  });

  it('an application a small group used is named without a bar or a figure', () => {
    show(
      okState(
        applicationsFixture({
          cohort: COHORT_TOO_FEW,
          items: [
            applicationFixture(),
            applicationFixture({
              rank: 2,
              application: 'BitTorrent',
              visibility: 'withheld',
              bytes: null,
              packets: null,
              share: null,
              endpoints: null,
              trend: { state: 'unknown', previous_bytes: null, change_ratio: null },
            }),
          ],
        }),
      ),
    );
    const card = screen.getByRole('region', { name: /Application mix/i });
    const rows = within(card).getAllByRole('listitem');
    assert.match(rows[1].textContent ?? '', /BitTorrent/);
    assert.match(rows[1].textContent ?? '', /Withheld/);
    assert.equal(rows[1].querySelectorAll('.progress').length, 0);
  });
});

