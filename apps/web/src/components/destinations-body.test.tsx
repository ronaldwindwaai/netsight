import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { DestinationsBody } from '@/components/destinations-body';
import type { TrafficDestinationsResponse } from '@/lib/api-contracts-traffic-explorer';
import {
  HOSTILE,
  STALE,
  destinationFixture,
  destinationsFixture,
  emptyDestinations,
  failureState,
  okState,
} from '@/test/traffic-fixtures';

afterEach(() => cleanup());

function show(state: ReturnType<typeof okState<TrafficDestinationsResponse>> | ReturnType<typeof failureState<TrafficDestinationsResponse>>) {
  return render(<DestinationsBody state={state} />);
}
const text = () => document.body.textContent ?? '';
const rows = () => within(screen.getByRole('table', { name: /destinations/i })).getAllByRole('row');

describe('every outcome of the read has its own surface', () => {
  it('permission denied names the permission', () => {
    show(failureState<TrafficDestinationsResponse>('forbidden', 403));
    assert.match(screen.getByRole('status').textContent ?? '', /traffic:read/);
  });

  it('sign-in, error and rate limit are distinct', () => {
    show(failureState<TrafficDestinationsResponse>('unauthenticated', 401));
    assert.ok(screen.getByRole('link', { name: /Sign in/ }));
    cleanup();
    show(failureState<TrafficDestinationsResponse>('error', 500));
    assert.match(text(), /Unable to load data/);
    cleanup();
    show(failureState<TrafficDestinationsResponse>('rate_limited', 429));
    assert.match(text(), /Too many requests/);
  });

  it('not connected and unknown carry no rows', () => {
    show(okState(emptyDestinations('not-connected')));
    assert.match(screen.getByRole('status').textContent ?? '', /Flow source not connected/);
    cleanup();
    show(okState(emptyDestinations('unknown')));
    assert.match(screen.getByRole('status').textContent ?? '', /state unknown/i);
    assert.equal(screen.queryAllByRole('table').length, 0);
  });

  it('a valid empty window is empty', () => {
    show(okState(destinationsFixture({ items: [], total_bytes: 0 })));
    assert.match(screen.getByRole('status').textContent ?? '', /No destinations in this window/);
  });

  it('stale data is labelled', () => {
    show(okState(destinationsFixture({ freshness: { ...STALE } })));
    assert.match(text(), /Stale monitoring data/);
  });
});

describe('the table', () => {
  it('names every column, including what first seen means', () => {
    show(okState(destinationsFixture()));
    const headers = within(screen.getByRole('table', { name: /destinations/i }))
      .getAllByRole('columnheader')
      .map((cell) => cell.textContent);
    assert.deepEqual(headers, [
      'Destination',
      'ASN',
      'Location',
      'First seen',
      'Last seen',
      'Endpoints',
      'Users',
      'Volume',
      'Reputation',
    ]);
    assert.match(text(), /since 2026-09-10 12:00:00 UTC/);
  });

  it('shows the source-reported values', () => {
    show(okState(destinationsFixture()));
    const row = rows()[1].textContent ?? '';
    assert.match(row, /203\.0\.113\.9/);
    assert.match(row, /cdn\.example\.net/);
    assert.match(row, /AS64500/);
    assert.match(row, /ZA/);
    assert.match(row, /2026-10-01 00:00:00 UTC/);
    assert.match(row, /2026-10-11 11:59:00 UTC/);
    assert.match(row, /150 MB/);
    assert.match(row, /12/);
  });

  it('fields the source did not report are Not reported, never invented', () => {
    show(
      okState(
        destinationsFixture({
          items: [destinationFixture({ domain: null, asn: null, country: null, first_seen: null, endpoints: null, share: null })],
        }),
      ),
    );
    const row = rows()[1].textContent ?? '';
    assert.match(row, /Not reported/);
    assert.doesNotMatch(row, /AS\d/);
  });

  it('users are Unknown, not zero', () => {
    show(okState(destinationsFixture()));
    const cells = within(rows()[1]).getAllByRole('cell');
    assert.equal(cells[6].textContent?.trim(), 'Unknown');
  });

  it('reputation is Unknown without an operator list and the page says so', () => {
    show(okState(destinationsFixture()));
    assert.match(text(), /No operator traffic policy is configured/);
    const cells = within(rows()[1]).getAllByRole('cell');
    assert.equal(cells[8].textContent?.trim(), 'Unknown');
  });

  it('shows list-derived reputation as a word and an icon', () => {
    show(
      okState(
        destinationsFixture({
          policy: { state: 'configured' },
          items: [
            destinationFixture({ reputation: 'deny-listed' }),
            destinationFixture({ rank: 2, address: '198.51.100.7', domain: null, reputation: 'allow-listed' }),
          ],
        }),
      ),
    );
    assert.match(rows()[1].textContent ?? '', /Deny-listed/);
    assert.match(rows()[2].textContent ?? '', /Allow-listed/);
    assert.ok(rows()[1].querySelector('i.bi'));
  });

  it('an invalid policy is stated', () => {
    show(okState(destinationsFixture({ policy: { state: 'invalid' } })));
    assert.match(text(), /policy file is invalid/);
  });

  it('says that reputation comes only from operator lists, never from a source guess', () => {
    show(okState(destinationsFixture()));
    assert.match(text(), /only from the operator allow and deny lists/);
  });

  it('hostile domains are only text', () => {
    show(okState(destinationsFixture({ items: [destinationFixture({ domain: HOSTILE })] })));
    assert.equal(document.querySelectorAll('img, script, iframe').length, 0);
    assert.ok(text().includes(HOSTILE));
  });

  it('a first-seen the look-back could not establish is not shown as a fact', () => {
    show(okState(destinationsFixture({ first_seen_since: null })));
    assert.match(text(), /First seen was not determined/);
  });
});
