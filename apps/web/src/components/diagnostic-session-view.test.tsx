import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { DiagnosticSessionBody } from '@/components/diagnostic-session-body';
import { DiagnosticSessionPage } from '@/components/diagnostic-session-page';
import type { FetchState } from '@/lib/api-response';
import type { DiagnosticSession, DiagnosticSessionResponse } from '@/lib/api-contracts-diagnostic-session';
import {
  COMPLETED_MS,
  SESSION_ID,
  changesState,
  sessionFixture,
  unnarrowedSession,
} from '@/test/diagnostic-fixtures';

afterEach(() => cleanup());

const FRESH = COMPLETED_MS + 2 * 60_000;
const STALE = COMPLETED_MS + 3 * 60 * 60_000;

function renderBody(session: DiagnosticSession = sessionFixture(), nowMs = FRESH) {
  return render(<DiagnosticSessionBody session={session} nowMs={nowMs} />);
}

function failure(kind: string, status: number | null = null): FetchState<DiagnosticSessionResponse> {
  return {
    kind,
    code: kind.toUpperCase(),
    message: 'Something went wrong.',
    correlationId: 'corr-1',
    status,
  } as FetchState<DiagnosticSessionResponse>;
}

describe('probable cause panel', () => {
  it('shows the domain, the confidence and a labelled evidence list', () => {
    renderBody();
    const panel = screen.getByRole('region', { name: 'Probable cause' });
    assert.ok(within(panel).getByText('Firewall / path'));
    assert.ok(within(panel).getByText('Low confidence'));
    const evidence = within(panel).getByRole('list', { name: 'Evidence' });
    const lines = within(evidence).getAllByRole('listitem');
    assert.equal(lines.length, 4);
    assert.deepEqual(
      lines.map((line) => within(line).getByTestId('evidence-basis').textContent),
      ['Observed', 'Observed', 'Inferred', 'Unknown'],
    );
    assert.match(lines[2].textContent ?? '', /does not prove/);
    assert.match(lines[0].textContent ?? '', /1 check/);
  });

  it('names the external-only pattern as an inference, not a proven fault', () => {
    renderBody();
    const panel = screen.getByRole('region', { name: 'Probable cause' });
    assert.match(panel.textContent ?? '', /internal ok, external failing/i);
    assert.match(panel.textContent ?? '', /inferred/i);
  });

  it('says nothing was narrowed instead of naming a cause or calling the target healthy', () => {
    renderBody(unnarrowedSession());
    const panel = screen.getByRole('region', { name: 'Probable cause' });
    assert.match(panel.textContent ?? '', /No probable cause was identified/);
    assert.match(panel.textContent ?? '', /Unknown confidence/);
    assert.doesNotMatch(panel.textContent ?? '', /healthy/i);
  });

  it('renders the alternatives, unknowns and next checks as read-only text', () => {
    renderBody();
    assert.ok(screen.getByText('Upstream routing change'));
    assert.ok(screen.getByText('No flow telemetry for the perimeter link'));
    assert.ok(screen.getByText('Compare the firewall rule set against the last change'));
  });
});

describe('per-location results', () => {
  it('lists all six locations and never shows an unconfigured one as passing', () => {
    renderBody();
    const region = screen.getByRole('region', { name: 'Probe locations' });
    const rows = within(region).getAllByRole('row').slice(1);
    assert.equal(rows.length, 6);
    const text = (name: string) => rows.find((row) => row.textContent?.includes(name))?.textContent ?? '';
    assert.match(text('Cloud / external'), /Checks failed/);
    assert.match(text('Server VLAN'), /Checks passed/);
    for (const name of ['User LAN', 'Branch', 'Wi-Fi', 'Remote site']) {
      assert.match(text(name), /Not connected/, name);
      assert.doesNotMatch(text(name), /passed|healthy/i, name);
    }
  });

  it('shows a configured location with no answers as no answer, not healthy', () => {
    const session = sessionFixture();
    session.locations = session.locations.map((row) =>
      row.location === 'branch'
        ? { ...row, state: 'unknown', unknown_checks: 1, check_ids: ['c-x'] }
        : row,
    );
    session.probable_cause = { ...session.probable_cause };
    // the branch check must exist in the run for the session to be coherent
    session.run = {
      ...session.run,
      checks: [
        ...session.run.checks,
        { ...session.run.checks[0], id: 'c-x', status: 'unknown', location: 'branch' },
      ],
    };
    renderBody(session);
    const region = screen.getByRole('region', { name: 'Probe locations' });
    const branch = within(region)
      .getAllByRole('row')
      .find((row) => row.textContent?.includes('Branch'));
    assert.match(branch?.textContent ?? '', /No answer/);
    assert.match(branch?.textContent ?? '', /not assumed healthy/);
  });
});

describe('path view', () => {
  it('draws the six tiers in order, marks the suspected hop and keeps unknown hops unknown', () => {
    renderBody();
    const path = screen.getByRole('list', { name: 'Network path' });
    const hops = within(path).getAllByRole('listitem');
    assert.deepEqual(
      hops.map((hop) => within(hop).getByTestId('hop-tier').textContent),
      ['User', 'Access point', 'Access switch', 'Core', 'Firewall', 'Server'],
    );
    assert.match(hops[0].textContent ?? '', /Unknown/);
    assert.match(hops[1].textContent ?? '', /Unknown/);
    assert.match(hops[4].textContent ?? '', /fw-01/);
    assert.match(hops[4].textContent ?? '', /suspected/i);
    assert.equal(hops.filter((hop) => /suspected/i.test(hop.textContent ?? '')).length, 1);
    assert.equal(hops[4].getAttribute('data-suspected'), 'true');
  });

  it('states which links are explicit cables and which are unknown, and fabricates none', () => {
    renderBody();
    const links = screen.getAllByTestId('path-link');
    assert.equal(links.length, 5);
    assert.deepEqual(
      links.map((link) => link.getAttribute('data-state')),
      ['unknown', 'unknown', 'known', 'known', 'known'],
    );
    assert.match(links[0].textContent ?? '', /No explicit link/);
    assert.match(links[2].textContent ?? '', /Explicit cable/);
  });

  it('shows not-connected and unknown paths as such, with nothing drawn', () => {
    for (const state of ['not-connected', 'unknown'] as const) {
      cleanup();
      const session = sessionFixture();
      session.path = { state, observed_at: null, hops: [], links: [] };
      renderBody(session);
      assert.equal(screen.queryByRole('list', { name: 'Network path' }), null, state);
      const region = screen.getByRole('region', { name: 'Network path' });
      assert.match(region.textContent ?? '', state === 'unknown' ? /could not be established/ : /not connected/i);
    }
  });
});

describe('recent changes', () => {
  it('lists changes as things that may correlate, never as a cause', () => {
    renderBody();
    const region = screen.getByRole('region', { name: 'Recent changes' });
    assert.ok(within(region).getByText('Incident title withheld'));
    assert.match(region.textContent ?? '', /May correlate/);
    assert.match(region.textContent ?? '', /not matched to the target/);
    assert.doesNotMatch(region.textContent ?? '', /caused|root cause|because of/i);
  });

  it('shows an incident as a reference with its severity and says its title is withheld', () => {
    renderBody();
    const region = screen.getByRole('region', { name: 'Recent changes' });
    assert.ok(within(region).getByText('High'));
    assert.match(region.textContent ?? '', /title is withheld/i);
    assert.match(region.textContent ?? '', /incidents:read/);
  });

  it('shows a revealed incident title without the withheld note', () => {
    const session = sessionFixture();
    session.recent_changes = {
      ...session.recent_changes,
      items: [
        { ...session.recent_changes.items[0], title: 'Firewall policy push', title_redacted: false },
      ],
    };
    renderBody(session);
    const region = screen.getByRole('region', { name: 'Recent changes' });
    assert.ok(within(region).getByText('Firewall policy push'));
    assert.doesNotMatch(region.textContent ?? '', /title is withheld/i);
  });

  it('shows an alert with its stored title and no severity', () => {
    const session = sessionFixture();
    session.recent_changes = {
      ...session.recent_changes,
      items: [
        {
          ...session.recent_changes.items[0],
          kind: 'alert',
          ref_id: 'alert-7',
          severity: null,
          title: 'Link down on core-01',
          title_redacted: false,
        },
      ],
    };
    renderBody(session);
    const region = screen.getByRole('region', { name: 'Recent changes' });
    assert.ok(within(region).getByText('Link down on core-01'));
    assert.equal(within(region).queryByText('High'), null);
  });

  it('says plainly that configuration changes are not connected, even when others are', () => {
    renderBody();
    const region = screen.getByRole('region', { name: 'Recent changes' });
    assert.match(region.textContent ?? '', /Configuration changes[^.]*not connected/i);
  });

  it('shows no connected source as not connected, never as no changes', () => {
    const session = sessionFixture();
    session.recent_changes = changesState('not-connected');
    renderBody(session);
    const region = screen.getByRole('region', { name: 'Recent changes' });
    assert.match(region.textContent ?? '', /Change source not connected/);
    assert.match(region.textContent ?? '', /not the same as there being no changes/);
  });

  it('shows an unreadable source as unknown', () => {
    const session = sessionFixture();
    session.recent_changes = changesState('unknown');
    renderBody(session);
    const region = screen.getByRole('region', { name: 'Recent changes' });
    assert.match(region.textContent ?? '', /could not be read/);
  });

  it('shows a read source with nothing in the window as a valid empty result', () => {
    const session = sessionFixture();
    session.recent_changes = { ...session.recent_changes, items: [] };
    renderBody(session);
    const region = screen.getByRole('region', { name: 'Recent changes' });
    assert.match(region.textContent ?? '', /No changes were recorded by the connected sources/);
  });
});

describe('unlocated checks', () => {
  it('notes that checks from a prober with no location are listed under checks', () => {
    const session = sessionFixture();
    const [first, ...rest] = session.run.checks;
    session.run = { ...session.run, checks: [...rest, { ...first, location: null }] };
    renderBody(session);
    const region = screen.getByRole('region', { name: 'Probe locations' });
    assert.match(region.textContent ?? '', /1 check .*no configured location/i);
    assert.match(region.textContent ?? '', /listed under (the )?checks/i);
  });

  it('shows no such note when every check has a location', () => {
    renderBody();
    const region = screen.getByRole('region', { name: 'Probe locations' });
    assert.doesNotMatch(region.textContent ?? '', /no configured location/i);
  });
});

describe('untrusted text', () => {
  it('renders operator and telemetry text as data only', () => {
    const hostile = '<img src=x onerror="alert(1)"> <script>alert(2)</script>';
    const session = sessionFixture();
    session.run = { ...session.run, target: hostile, symptom: hostile };
    session.recent_changes = {
      ...session.recent_changes,
      items: [{ ...session.recent_changes.items[0], title: hostile }],
    };
    session.path = {
      ...session.path,
      hops: session.path.hops.map((hop) => (hop.tier === 'core' ? { ...hop, name: hostile } : hop)),
    };
    const { container } = renderBody(session);
    assert.equal(container.querySelector('img'), null);
    assert.equal(container.querySelector('script'), null);
    assert.ok(container.textContent?.includes(hostile));
  });
});

describe('state banners', () => {
  it('marks an old session as a stored snapshot, not current state', () => {
    renderBody(sessionFixture(), STALE);
    assert.match(screen.getByRole('status', { name: 'Snapshot age' }).textContent ?? '', /stored snapshot/i);
  });

  it('does not call a fresh session stale', () => {
    renderBody();
    assert.equal(screen.queryByRole('status', { name: 'Snapshot age' }), null);
    assert.ok(screen.getByText(/Completed 2026-10-10 08:00:05 UTC/));
  });

  it('lists exactly the sections that are only partly available', () => {
    renderBody();
    const banner = screen.getByRole('status', { name: 'Partial session' });
    assert.match(banner.textContent ?? '', /Probe locations without a source/);
    assert.doesNotMatch(banner.textContent ?? '', /Path|Recent changes/);
  });

  it('shows an empty session for a run with no checks', () => {
    const session = sessionFixture();
    session.run = { ...session.run, checks: [] };
    session.locations = session.locations.map((row) => ({
      ...row,
      state: 'not-connected',
      status: null,
      passed: 0,
      failed: 0,
      unknown_checks: 0,
      check_ids: [],
    }));
    session.probable_cause = { ...session.probable_cause, evidence: [] };
    renderBody(session);
    assert.match(screen.getByRole('region', { name: 'Checks' }).textContent ?? '', /No checks were recorded/);
  });
});

describe('read-only', () => {
  it('offers no remediation, form or button, only navigation', () => {
    const { container } = renderBody();
    assert.equal(container.querySelectorAll('button').length, 0);
    assert.equal(container.querySelectorAll('form').length, 0);
    assert.equal(container.querySelectorAll('input, textarea, select').length, 0);
    assert.doesNotMatch(container.textContent ?? '', /restart|disable|quarantine|remediat|apply fix/i);
  });
});

describe('page states', () => {
  it('renders a stored session', () => {
    render(
      <DiagnosticSessionPage
        state={{ kind: 'ok', data: { state: 'ok', session: sessionFixture() }, correlationId: 'c' }}
        nowMs={FRESH}
      />,
    );
    assert.ok(screen.getByRole('region', { name: 'Probable cause' }));
  });

  for (const [state, title] of [
    ['not-connected', /Diagnostic session store not connected/],
    ['unknown', /Diagnostic session store state unknown/],
  ] as const) {
    it(`shows a ${state} store as such`, () => {
      render(
        <DiagnosticSessionPage
          state={{ kind: 'ok', data: { state, session: null }, correlationId: 'c' }}
          nowMs={FRESH}
        />,
      );
      assert.match(screen.getByRole('status').textContent ?? '', title);
      assert.equal(screen.queryByRole('region', { name: 'Probable cause' }), null);
    });
  }

  for (const [kind, status, text] of [
    ['forbidden', 403, /Permission denied/],
    ['unauthenticated', 401, /sign-in required/i],
    ['not_found', 404, /not found/i],
    ['rate_limited', 429, /Too many requests/],
    ['source_unavailable', 503, /unavailable/i],
    ['invalid_response', 200, /Invalid Netsight API response/],
    ['error', 500, /Unable to load data/],
  ] as const) {
    it(`shows ${kind} explicitly and no session`, () => {
      render(<DiagnosticSessionPage state={failure(kind, status)} nowMs={FRESH} />);
      assert.match(document.body.textContent ?? '', text);
      assert.equal(screen.queryByRole('region', { name: 'Probable cause' }), null);
    });
  }

  it('does not fetch or render for a malformed identifier', () => {
    render(<DiagnosticSessionPage state={null} nowMs={FRESH} />);
    assert.match(screen.getByRole('status').textContent ?? '', /Invalid session identifier/);
  });

  it('links back to the diagnostics page', () => {
    render(
      <DiagnosticSessionPage
        state={{ kind: 'ok', data: { state: 'ok', session: sessionFixture() }, correlationId: 'c' }}
        nowMs={FRESH}
      />,
    );
    const link = screen.getByRole('link', { name: /All diagnostics/ });
    assert.equal(link.getAttribute('href'), '/diagnostics');
    assert.ok(SESSION_ID);
  });
});
