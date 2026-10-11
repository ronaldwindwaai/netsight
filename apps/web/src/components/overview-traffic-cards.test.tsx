import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { OverviewApplicationMix, OverviewTopTalkers } from '@/components/overview-traffic-cards';
import type { TrafficTopResponse } from '@/lib/api-contracts';
import type { TrafficApplicationsResponse } from '@/lib/api-contracts-traffic-explorer';
import {
  FRESH,
  HOSTILE,
  NO_FRESHNESS,
  TIME_RANGE,
  applicationFixture,
  applicationsFixture,
  emptyApplications,
  failureState,
  okState,
} from '@/test/traffic-fixtures';

afterEach(() => cleanup());

const text = () => document.body.textContent ?? '';

function talkers(over: Partial<TrafficTopResponse> = {}): TrafficTopResponse {
  return {
    state: 'ok',
    dimension: 'talkers',
    time_range: { ...TIME_RANGE },
    items: [
      { rank: 1, subject_kind: 'ip', subject_id: null, label: '10.0.0.10', bytes: 600_000_000, packets: null, share: 0.6 },
      { rank: 2, subject_kind: 'ip', subject_id: null, label: '10.0.0.11', bytes: 400_000_000, packets: null, share: 0.4 },
    ],
    freshness: { ...FRESH },
    ...over,
  };
}

describe('Top bandwidth users', () => {
  it('is Restricted, not empty, for a role without endpoint-level traffic', () => {
    render(<OverviewTopTalkers state={null} />);
    const card = screen.getByRole('region', { name: /Top bandwidth users/i });
    assert.match(card.textContent ?? '', /Restricted/);
    assert.match(card.textContent ?? '', /traffic:read-detail/);
    assert.equal(within(card).queryAllByRole('listitem').length, 0);
  });

  it('a refusal from the API is also Restricted', () => {
    render(<OverviewTopTalkers state={failureState<TrafficTopResponse>('forbidden', 403)} />);
    assert.match(text(), /Restricted/);
  });

  it('not connected keeps the explicit not-connected surface', () => {
    render(
      <OverviewTopTalkers
        state={okState(talkers({ state: 'not-connected', items: [], freshness: { ...NO_FRESHNESS } }))}
      />,
    );
    assert.match(text(), /Flow telemetry not connected/);
    assert.equal(screen.queryAllByRole('listitem').length, 0);
  });

  it('unknown is unknown and nothing is ranked', () => {
    render(<OverviewTopTalkers state={okState(talkers({ state: 'unknown', items: [] }))} />);
    assert.match(text(), /Traffic state unknown/);
    assert.equal(screen.queryAllByRole('listitem').length, 0);
  });

  it('an API error is an error', () => {
    render(<OverviewTopTalkers state={failureState<TrafficTopResponse>('error', 500)} />);
    assert.match(text(), /Unable to load data/);
  });

  it('a valid empty window is empty, not a failure', () => {
    render(<OverviewTopTalkers state={okState(talkers({ items: [] }))} />);
    assert.match(text(), /No traffic in this window/);
  });

  it('ranks real source addresses and says they are addresses, not people', () => {
    render(<OverviewTopTalkers state={okState(talkers())} />);
    const card = screen.getByRole('region', { name: /Top bandwidth users/i });
    assert.match(card.textContent ?? '', /10\.0\.0\.10/);
    assert.match(card.textContent ?? '', /600 MB/);
    assert.match(card.textContent ?? '', /Addresses, not people/);
    assert.equal(within(card).getAllByRole('listitem').length, 2);
    assert.equal(
      within(card).getByRole('link', { name: /Flow Explorer/ }).getAttribute('href'),
      '/traffic/flows?preset=24h',
    );
  });

  it('hostile labels are only text', () => {
    const hostile = talkers({
      items: [{ rank: 1, subject_kind: 'ip', subject_id: null, label: HOSTILE, bytes: 5, packets: null, share: null }],
    });
    render(<OverviewTopTalkers state={okState(hostile)} />);
    assert.equal(document.querySelectorAll('img, script, iframe').length, 0);
    assert.ok(text().includes(HOSTILE));
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
});
