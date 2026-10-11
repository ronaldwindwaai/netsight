import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { ApplicationsBody } from '@/components/applications-body';
import type { TrafficApplicationsResponse } from '@/lib/api-contracts-traffic-explorer';
import {
  HOSTILE,
  STALE,
  applicationFixture,
  applicationsFixture,
  emptyApplications,
  failureState,
  okState,
} from '@/test/traffic-fixtures';

afterEach(() => cleanup());

function show(state: ReturnType<typeof okState<TrafficApplicationsResponse>> | ReturnType<typeof failureState<TrafficApplicationsResponse>>) {
  return render(<ApplicationsBody state={state} />);
}
const text = () => document.body.textContent ?? '';
const firstRow = () => within(screen.getByRole('table', { name: /applications/i })).getAllByRole('row')[1];

describe('every outcome of the read has its own surface', () => {
  it('permission denied names the permission', () => {
    show(failureState<TrafficApplicationsResponse>('forbidden', 403));
    assert.match(screen.getByRole('status').textContent ?? '', /not available to your role/);
    assert.match(screen.getByRole('status').textContent ?? '', /traffic:read/);
  });

  it('sign-in, error and rate limit are distinct', () => {
    show(failureState<TrafficApplicationsResponse>('unauthenticated', 401));
    assert.ok(screen.getByRole('link', { name: /Sign in/ }));
    cleanup();
    show(failureState<TrafficApplicationsResponse>('error', 500));
    assert.match(text(), /Unable to load data/);
    cleanup();
    show(failureState<TrafficApplicationsResponse>('rate_limited', 429));
    assert.match(text(), /Too many requests/);
  });

  it('not connected and unknown are not empty and carry no rows', () => {
    show(okState(emptyApplications('not-connected')));
    assert.match(screen.getByRole('status').textContent ?? '', /Flow source not connected/);
    assert.equal(screen.queryAllByRole('table').length, 0);
    cleanup();
    show(okState(emptyApplications('unknown')));
    assert.match(screen.getByRole('status').textContent ?? '', /state unknown/i);
  });

  it('a source without application data says what is missing and shows nothing', () => {
    show(okState(emptyApplications('unknown', { unsupported: ['application'] })));
    const status = screen.getByRole('status').textContent ?? '';
    assert.match(status, /does not report applications/i);
    assert.equal(screen.queryAllByRole('table').length, 0);
  });

  it('a valid empty window is empty and says it is not proof of no use', () => {
    show(okState(applicationsFixture({ items: [], total_bytes: 0 })));
    assert.match(screen.getByRole('status').textContent ?? '', /No applications in this window/);
  });

  it('stale data is labelled', () => {
    show(okState(applicationsFixture({ freshness: { ...STALE } })));
    assert.match(text(), /Stale monitoring data/);
  });
});

describe('the table', () => {
  it('has a caption and column headers naming what each count is', () => {
    show(okState(applicationsFixture()));
    const headers = within(screen.getByRole('table', { name: /applications/i }))
      .getAllByRole('columnheader')
      .map((cell) => cell.textContent);
    assert.deepEqual(headers, [
      'Application',
      'Volume',
      'Endpoints (source addresses)',
      'Users',
      'Trend',
      'Risk',
      'Approval',
    ]);
  });

  it('shows the source-reported values and the share of the window total', () => {
    show(okState(applicationsFixture()));
    const row = firstRow().textContent ?? '';
    assert.match(row, /Microsoft 365/);
    assert.match(row, /Productivity/);
    assert.match(row, /150 MB/);
    assert.match(row, /40%/);
    assert.match(row, /25/);
    assert.match(row, /Up 50%/);
  });

  it('users are Unknown, never zero, and the page says why', () => {
    show(okState(applicationsFixture()));
    assert.match(firstRow().textContent ?? '', /Unknown/);
    assert.match(text(), /counting people needs per-flow identity attribution/i);
  });

  it('endpoints are labelled as addresses, not people or inventory devices', () => {
    show(okState(applicationsFixture()));
    assert.match(text(), /distinct source addresses/i);
  });

  it('risk and approval are Unknown without an operator policy, and the page says so', () => {
    show(okState(applicationsFixture()));
    assert.match(text(), /No operator traffic policy is configured/);
    const cells = within(firstRow()).getAllByRole('cell');
    assert.equal(cells[5].textContent?.trim(), 'Unknown');
    assert.equal(cells[6].textContent?.trim(), 'Unknown');
  });

  it('shows policy-derived approval and risk with a word and an icon', () => {
    show(
      okState(
        applicationsFixture({
          policy: { state: 'configured' },
          items: [
            applicationFixture({ risk: 'high', approval: 'unapproved' }),
            applicationFixture({ rank: 2, application: 'Zoom', risk: 'low', approval: 'approved' }),
          ],
          total_bytes: 400_000_000,
        }),
      ),
    );
    const rows = within(screen.getByRole('table', { name: /applications/i })).getAllByRole('row');
    assert.match(rows[1].textContent ?? '', /High risk/);
    assert.match(rows[1].textContent ?? '', /Not approved/);
    assert.match(rows[2].textContent ?? '', /Low risk/);
    assert.match(rows[2].textContent ?? '', /Approved/);
    assert.ok(rows[1].querySelector('i.bi'), 'a status carries an icon as well as a word');
    assert.doesNotMatch(text(), /No operator traffic policy/);
  });

  it('an invalid policy is stated and classifies nothing', () => {
    show(okState(applicationsFixture({ policy: { state: 'invalid' } })));
    assert.match(text(), /policy file is invalid/);
  });

  it('a new application and an unknown trend are worded as such', () => {
    show(
      okState(
        applicationsFixture({
          items: [
            applicationFixture({ trend: { state: 'new', previous_bytes: 0, change_ratio: null } }),
            applicationFixture({ rank: 2, application: 'B', trend: { state: 'unknown', previous_bytes: null, change_ratio: null } }),
          ],
        }),
      ),
    );
    const rows = within(screen.getByRole('table', { name: /applications/i })).getAllByRole('row');
    assert.match(rows[1].textContent ?? '', /New in this window/);
    assert.match(rows[2].textContent ?? '', /Unknown \(no earlier window/);
  });

  it('a missing category and endpoint count are Not reported', () => {
    show(okState(applicationsFixture({ items: [applicationFixture({ category: null, endpoints: null, share: null })] })));
    const row = firstRow().textContent ?? '';
    assert.match(row, /Not reported/);
    assert.match(row, /share not reported/);
  });

  it('hostile application names and categories are only text', () => {
    show(okState(applicationsFixture({ items: [applicationFixture({ application: HOSTILE, category: HOSTILE })] })));
    assert.equal(document.querySelectorAll('img, script, iframe').length, 0);
    assert.ok(text().includes(HOSTILE));
  });

  it('names the comparison window used for the trend', () => {
    show(okState(applicationsFixture()));
    assert.match(text(), /compared with the previous 24 hours|compared with the preceding window/i);
  });

  it('says there is no trend when no previous window was compared', () => {
    show(okState(applicationsFixture({ previous_range: null })));
    assert.match(text(), /No previous window was compared/);
  });
});
