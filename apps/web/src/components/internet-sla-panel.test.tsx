import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { InternetSlaPanel } from '@/components/internet-sla-panel';
import type { SlaResponse } from '@/lib/api-contracts-internet';
import { monthOptions } from '@/lib/internet-view';
import { failureState, okState, slaFixture, slaLinkFixture } from '@/test/internet-fixtures';

afterEach(() => cleanup());

const MONTHS = monthOptions(new Date('2026-10-11T12:00:00Z'));

function panel(
  state = okState(slaFixture()),
  overrides: { month?: string; adjusted?: boolean; canExport?: boolean } = {},
) {
  return render(
    <InternetSlaPanel
      state={state}
      month={overrides.month ?? '2026-09'}
      months={MONTHS}
      adjusted={overrides.adjusted ?? false}
      canExport={overrides.canExport ?? true}
    />,
  );
}

describe('the month picker is server-bounded and read-only', () => {
  it('offers exactly the supported months in a plain GET form', () => {
    const { container } = panel();
    const select = screen.getByLabelText('SLA month (UTC)') as HTMLSelectElement;
    const options = Array.from(select.options).map((option) => option.value);
    assert.deepEqual(options, MONTHS);
    assert.equal(options.length, 25);
    assert.equal(select.value, '2026-09');
    const form = container.querySelector('form');
    assert.equal(form?.getAttribute('method'), 'get');
    assert.equal(form?.getAttribute('action'), '/internet');
    assert.ok(screen.getByRole('button', { name: 'Show month' }));
  });

  it('says so when the requested month had to be replaced', () => {
    panel(okState(slaFixture()), { adjusted: true });
    assert.match(screen.getByRole('status').textContent ?? '', /outside the supported range/);
  });
});

describe('the evidence export is a read-only download', () => {
  it('links to the CSV and JSON export for exactly the shown month', () => {
    panel();
    assert.equal(
      screen.getByRole('link', { name: /Download CSV/ }).getAttribute('href'),
      '/internet/export?month=2026-09&format=csv',
    );
    assert.equal(
      screen.getByRole('link', { name: /Download JSON/ }).getAttribute('href'),
      '/internet/export?month=2026-09&format=json',
    );
  });

  it('is withheld, with the reason, from a viewer without internet:export', () => {
    panel(okState(slaFixture()), { canExport: false });
    assert.equal(screen.queryAllByRole('link').length, 0);
    assert.match(document.body.textContent ?? '', /internet:export permission, which your role does not hold/);
  });

  it('is not offered when there is nothing to export', () => {
    panel(okState(slaFixture({ state: 'not-connected', period_start: null, period_end: null, links: [] })));
    assert.equal(screen.queryAllByRole('link').length, 0);
    panel(failureState<SlaResponse>('error', 500));
    assert.equal(screen.queryAllByRole('link').length, 0);
  });

  it('refuses to build a link from a month that is not YYYY-MM', () => {
    assert.throws(() => panel(okState(slaFixture()), { month: '../../etc' }));
  });
});

describe('the figures', () => {
  it('shows uptime, down, degraded, unknown, outages and coverage per link', () => {
    panel();
    const row = screen.getByRole('row', { name: /Primary fibre/ });
    const text = row.textContent ?? '';
    assert.match(text, /99\.925%/);
    assert.match(text, /10 min/); // 600 s of downtime
    assert.match(text, /16 min 40 s/); // 1000 s degraded
    assert.match(text, /17 h 20 min/); // 62 400 s with no samples, shown as unknown
    assert.match(text, /2 \(longest 6 min 40 s\)/);
    assert.match(text, /92\.778%/);
    assert.match(screen.getByRole('columnheader', { name: /Unknown \(no samples\)/ }).textContent ?? '', /no samples/);
    assert.match(document.body.textContent ?? '', /Period 2026-09-01 00:00:00 UTC to 2026-10-01 00:00:00 UTC/);
    assert.match(document.body.textContent ?? '', /Time without a probe round is unknown, not up and not down/);
  });

  it('names a violation in words, not only an icon', () => {
    const link = slaLinkFixture({
      uptime_pct: 85,
      violations: [{ kind: 'uptime-below-target', target_pct: 99.5, actual_pct: 85 }],
    });
    panel(okState(slaFixture({ links: [link] })));
    assert.match(screen.getByRole('row', { name: /Primary fibre/ }).textContent ?? '', /Below target 99\.5% \(actual 85%\)/);
  });

  it('says plainly when no target is configured or nothing was known', () => {
    panel(
      okState(
        slaFixture({
          links: [
            slaLinkFixture({ uptime_target_pct: null }),
            slaLinkFixture({ link_id: 'lte-1', name: 'LTE', uptime_pct: null, up_seconds: 0, degraded_seconds: 0, down_seconds: 0, unknown_seconds: 864_000, outage_count: 0, longest_outage_seconds: 0, coverage_pct: 0, cycle_count: 0 }),
          ],
        }),
      ),
    );
    assert.match(screen.getByRole('row', { name: /Primary fibre/ }).textContent ?? '', /No uptime target configured/);
    const lte = screen.getByRole('row', { name: /LTE/ }).textContent ?? '';
    assert.match(lte, /Not reported/); // uptime of a month with no known time is never 0% or 100%
    assert.match(lte, /no known time/);
  });

  it('a link the store could not read is unknown, and the others still show', () => {
    panel(
      okState(
        slaFixture({
          links: [
            slaLinkFixture(),
            slaLinkFixture({ link_id: 'lte-1', name: 'LTE', state: 'unknown', uptime_target_pct: null, total_seconds: null, up_seconds: null, degraded_seconds: null, down_seconds: null, unknown_seconds: null, uptime_pct: null, coverage_pct: null, outage_count: null, longest_outage_seconds: null, cycle_count: null }),
          ],
        }),
      ),
    );
    assert.match(screen.getByRole('row', { name: /LTE/ }).textContent ?? '', /Unknown: the sample store could not be read/);
    assert.match(screen.getByRole('row', { name: /Primary fibre/ }).textContent ?? '', /99\.925%/);
  });

  it('renders a hostile link name as data', () => {
    const hostile = '<img src=x onerror=alert(1)>';
    const { container } = panel(okState(slaFixture({ links: [slaLinkFixture({ name: hostile })] })));
    assert.equal(container.querySelector('img'), null);
    assert.ok((container.textContent ?? '').includes(hostile));
  });
});

describe('every outcome of the read has its own surface', () => {
  it('not-connected is not a perfect month', () => {
    panel(okState(slaFixture({ state: 'not-connected', period_start: null, period_end: null, links: [] })));
    assert.match(screen.getByRole('status').textContent ?? '', /not the same as a perfect month/);
    assert.equal(screen.queryAllByRole('table').length, 0);
  });

  it('unknown estimates nothing', () => {
    panel(okState(slaFixture({ state: 'unknown', period_start: null, period_end: null, links: [] })));
    assert.match(screen.getByRole('status').textContent ?? '', /Nothing is estimated/);
  });

  it('ok without links is empty', () => {
    panel(okState(slaFixture({ links: [] })));
    assert.match(screen.getByRole('status').textContent ?? '', /No WAN links in this month/);
  });

  it('permission denied shows no figures', () => {
    panel(failureState<SlaResponse>('forbidden', 403));
    const text = within(document.body).getByRole('status').textContent ?? '';
    assert.match(text, /not available to your role/);
    assert.equal(screen.queryAllByRole('table').length, 0);
  });

  it('an API error is shown as an error', () => {
    panel(failureState<SlaResponse>('error', 500));
    assert.match(document.body.textContent ?? '', /Unable to load data/);
    assert.equal(screen.queryAllByRole('table').length, 0);
  });

  it('a rejected month (422) is an error, not an empty month', () => {
    panel(failureState<SlaResponse>('error', 422));
    assert.match(document.body.textContent ?? '', /Unable to load data/);
  });
});

describe('truncation and missing figures are never hidden', () => {
  it('says when the evidence export lists only part of the month', () => {
    panel(okState(slaFixture({ links: [slaLinkFixture({ windows_truncated: true })] })));
    const note = screen.getByRole('alert');
    assert.match(note.textContent ?? '', /Primary fibre/);
    assert.match(note.textContent ?? '', /export lists only the first windows/);
    assert.match(note.textContent ?? '', /figures above are complete/);
  });

  it('shows no truncation warning for a complete month', () => {
    panel(okState(slaFixture()));
    assert.equal(screen.queryAllByRole('alert').length, 0);
  });

  it('renders a missing outage count as Not reported, not as an empty cell', () => {
    panel(
      okState(slaFixture({ links: [slaLinkFixture({ outage_count: null, longest_outage_seconds: null })] })),
    );
    const row = screen.getByRole('row', { name: /Primary fibre/ });
    const cells = within(row).getAllByRole('cell');
    assert.equal(cells[4].textContent, 'Not reported');
  });

  it('still shows a real zero outage count', () => {
    panel(okState(slaFixture({ links: [slaLinkFixture({ outage_count: 0 })] })));
    const cells = within(screen.getByRole('row', { name: /Primary fibre/ })).getAllByRole('cell');
    assert.equal(cells[4].textContent, '0');
  });

  it('notes an empty period instead of showing a misleading blank', () => {
    panel(
      okState(
        slaFixture({
          period_end: '2026-09-01T00:00:00Z',
          links: [
            slaLinkFixture({
              total_seconds: 0,
              up_seconds: 0,
              degraded_seconds: 0,
              down_seconds: 0,
              unknown_seconds: 0,
              uptime_pct: null,
              coverage_pct: 0,
              outage_count: 0,
              longest_outage_seconds: 0,
              cycle_count: 0,
            }),
          ],
        }),
      ),
    );
    assert.match(document.body.textContent ?? '', /The month has only just started/);
  });
});
