import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { UserDetailBody } from '@/components/user-detail-body';
import type { UserDetailResponse } from '@/lib/api-contracts-identity';
import {
  HOSTILE,
  detailFixture,
  failureState,
  inferredLink,
  okState,
  profile,
  securityAbsent,
  securityOk,
  session,
  source,
  sourceNotConnected,
  sourceUnknown,
  trafficAbsent,
  trafficOk,
} from '@/test/identity-fixtures';

afterEach(() => cleanup());

function body(state: ReturnType<typeof okState<UserDetailResponse>> | ReturnType<typeof failureState<UserDetailResponse>>) {
  return <UserDetailBody state={state} />;
}

function section(name: string): HTMLElement {
  return screen.getByRole('region', { name });
}

describe('every outcome of the read has its own surface', () => {
  it('permission denied explains the missing permission and shows no profile', () => {
    render(body(failureState<UserDetailResponse>('forbidden', 403)));
    const text = screen.getByRole('status').textContent ?? '';
    assert.match(text, /not available to your role/);
    assert.match(text, /users:read/);
    assert.equal(screen.queryAllByRole('region').length, 0);
  });

  it('an unauthenticated session is asked to sign in', () => {
    render(body(failureState<UserDetailResponse>('unauthenticated', 401)));
    assert.ok(screen.getByRole('link', { name: /Sign in/ }));
  });

  it('a missing person is not found, not an empty profile', () => {
    render(body(failureState<UserDetailResponse>('not_found', 404)));
    assert.match(document.body.textContent ?? '', /not found/i);
    assert.equal(screen.queryAllByRole('region').length, 0);
  });

  it('errors and rate limits are reported as such', () => {
    render(body(failureState<UserDetailResponse>('error', 500)));
    assert.match(document.body.textContent ?? '', /Unable to load data/);
    cleanup();
    render(body(failureState<UserDetailResponse>('rate_limited', 429)));
    assert.match(document.body.textContent ?? '', /Too many requests/);
  });

  it('nothing configured is not-connected and no profile is shown', () => {
    render(body(okState(detailFixture({ state: 'not-connected', user: null, traffic: null, security: null, sources: [sourceNotConnected('wazuh')] }))));
    const text = screen.getByRole('status').textContent ?? '';
    assert.match(text, /not connected/i);
    assert.equal(screen.queryAllByRole('region').length, 0);
  });

  it('a failing source is unknown and nothing is estimated', () => {
    render(body(okState(detailFixture({ state: 'unknown', user: null, traffic: null, security: null, sources: [sourceUnknown('wazuh')] }))));
    const text = screen.getByRole('status').textContent ?? '';
    assert.match(text, /state unknown/i);
    assert.match(text, /Nothing is estimated/);
  });
});

describe('the profile', () => {
  it('names the person, the accounts and what the evidence was read from', () => {
    render(body(okState(detailFixture())));
    assert.ok(screen.getByRole('heading', { name: 'Alice Example', level: 1 }));
    const accounts = section('Accounts');
    assert.match(accounts.textContent ?? '', /Person to account/);
    assert.match(accounts.textContent ?? '', /alice/);
    assert.match(document.body.textContent ?? '', /as of 2026-10-11 12:00:00 UTC/i);
  });

  it('never shows fields no source provides', () => {
    render(body(okState(detailFixture())));
    assert.doesNotMatch(document.body.textContent ?? '', /e-?mail|department|manager|MFA|last login|at risk|behaviou?r/i);
  });

  it('renders a hostile name as text', () => {
    const state = okState(detailFixture({ user: profile({ display_name: HOSTILE }) }));
    const { container } = render(body(state));
    assert.ok((container.textContent ?? '').includes(HOSTILE));
    assert.equal(container.querySelector('img'), null);
  });

  it('labels an unnamed person', () => {
    render(body(okState(detailFixture({ user: profile({ display_name: null }) }))));
    assert.ok(screen.getByRole('heading', { name: 'Unnamed person', level: 1 }));
  });

  it('shows a partial-evidence notice when a source could not be read', () => {
    render(body(okState(detailFixture({ sources: [source(), sourceUnknown('netbox')] }))));
    assert.match(document.body.textContent ?? '', /netbox: could not be read/);
  });
});

describe('current sessions', () => {
  it('shows each session with its kind, basis, confidence, window and ordered links', () => {
    render(body(okState(detailFixture())));
    const sessions = section('Current sessions');
    const text = sessions.textContent ?? '';
    assert.match(text, /Wired \(802\.1X\)/);
    assert.match(text, /Observed/);
    assert.match(text, /95%/);
    assert.match(text, /Valid from 2026-10-11 10:00:00 UTC until 2026-10-11 12:09:00 UTC/);
    const items = within(sessions).getAllByRole('listitem');
    assert.equal(items.length, 4);
    assert.match(items[0].textContent ?? '', /Person to account/);
    assert.match(items[1].textContent ?? '', /Account to MAC address/);
    assert.match(items[3].textContent ?? '', /MAC address to port/);
  });

  it('shows an inferred session as inferred', () => {
    const inferred = session({ basis: 'inferred', confidence: 0.7, links: [session().links[0], inferredLink({ relation: 'account-mac', source: session().links[1].source, target: session().links[1].target })] });
    render(body(okState(detailFixture({ user: profile({ sessions: [inferred] }) }))));
    assert.match(section('Current sessions').textContent ?? '', /Inferred/);
  });

  it('says no session is evidenced and that this is not the same as offline', () => {
    render(body(okState(detailFixture({ user: profile({ sessions: [] }) }))));
    const text = section('Current sessions').textContent ?? '';
    assert.match(text, /No current session is evidenced/);
    assert.match(text, /not .*offline/i);
  });
});

describe('assigned devices', () => {
  it('are declarations, shown as inferred, never as use', () => {
    render(body(okState(detailFixture())));
    const text = section('Assigned devices').textContent ?? '';
    assert.match(text, /declaration/i);
    assert.match(text, /not proof/i);
    assert.match(text, /PC-001/);
    assert.match(text, /Inferred/);
  });

  it('is absent rather than empty when none is declared', () => {
    render(body(okState(detailFixture({ user: profile({ assigned_devices: [] }) }))));
    assert.equal(screen.queryAllByRole('region', { name: 'Assigned devices' }).length, 0);
  });
});

describe('traffic', () => {
  it('is attributed by address, labelled inferred, and shows a volume per address', () => {
    render(body(okState(detailFixture())));
    const text = section('Traffic').textContent ?? '';
    assert.match(text, /Inferred/);
    assert.match(text, /by IP address/i);
    assert.match(text, /10\.0\.0\.10/);
    assert.match(text, /1 MB/);
    assert.match(text, /2026-10-11 11:00:00 UTC/);
  });

  it('never turns an unlisted address into zero', () => {
    const traffic = trafficOk({ items: [{ address: '10.0.0.10', bytes: null, covers_window: true }] });
    render(body(okState(detailFixture({ traffic }))));
    const text = section('Traffic').textContent ?? '';
    assert.match(text, /Not among the top 100 talkers/);
    assert.doesNotMatch(text, /\b0 B\b/);
  });

  it('says when the address link does not cover the whole window', () => {
    const traffic = trafficOk({ items: [{ address: '10.0.0.10', bytes: null, covers_window: false }] });
    render(body(okState(detailFixture({ traffic }))));
    assert.match(section('Traffic').textContent ?? '', /does not cover the whole window/);
  });

  it('is not-connected without a traffic source', () => {
    render(body(okState(detailFixture({ traffic: trafficAbsent('not-connected') }))));
    const text = section('Traffic').textContent ?? '';
    assert.match(text, /Traffic source not connected/);
    assert.equal(within(section('Traffic')).queryAllByRole('table').length, 0);
  });

  it('is unknown when the traffic source failed', () => {
    render(body(okState(detailFixture({ traffic: trafficAbsent('unknown') }))));
    assert.match(section('Traffic').textContent ?? '', /Traffic state unknown/);
  });

  it('says there is nothing to look up when no address is attributed', () => {
    render(body(okState(detailFixture({ traffic: trafficOk({ items: [], top_n: 0 }) }))));
    assert.match(section('Traffic').textContent ?? '', /No address is currently attributed/);
  });
});

describe('security events', () => {
  it('lists events at attributed addresses with the basis of the attribution and its evidence', () => {
    render(body(okState(detailFixture())));
    const region = section('Security events');
    const text = region.textContent ?? '';
    assert.match(text, /ET SCAN Suspicious inbound to MSSQL port 1433/);
    assert.match(text, /High/);
    assert.match(text, /10\.0\.0\.10/);
    assert.match(text, /2026-10-11 11:00:00 UTC/);
    assert.match(text, /Inferred/);
    assert.match(text, /events involving an address attributed to this person/i);
    assert.match(text, /at the time of the event/i);
    assert.match(text, /not a record of what the person did/i);
    assert.ok(within(region).getByText(/Evidence \(3\)/));
  });

  it('renders a hostile signature as text', () => {
    const item = { ...securityOk().items[0], signature: HOSTILE };
    const { container } = render(body(okState(detailFixture({ security: securityOk({ items: [item] }) }))));
    assert.ok((container.textContent ?? '').includes(HOSTILE));
    assert.equal(container.querySelector('img'), null);
  });

  it('says none were found without implying the person did nothing', () => {
    render(body(okState(detailFixture({ security: securityOk({ items: [] }) }))));
    const text = section('Security events').textContent ?? '';
    assert.match(text, /No security events involve an address attributed to this person/);
    assert.match(text, /not evidence that nothing happened/i);
  });

  it('notes a cut-short list', () => {
    render(body(okState(detailFixture({ security: securityOk({ truncated: true }) }))));
    assert.match(section('Security events').textContent ?? '', /more events matched than are shown/i);
  });

  it('is not-connected or unknown without a security source', () => {
    render(body(okState(detailFixture({ security: securityAbsent('not-connected') }))));
    assert.match(section('Security events').textContent ?? '', /Security source not connected/);
    cleanup();
    render(body(okState(detailFixture({ security: securityAbsent('unknown') }))));
    assert.match(section('Security events').textContent ?? '', /Security state unknown/);
  });
});

describe('accessibility', () => {
  it('uses one level-one heading and named regions for every section', () => {
    render(body(okState(detailFixture())));
    assert.equal(screen.getAllByRole('heading', { level: 1 }).length, 1);
    for (const name of ['Accounts', 'Current sessions', 'Assigned devices', 'Traffic', 'Security events']) {
      assert.ok(section(name), name);
    }
  });

  it('never carries a link relation in colour alone: every link has a basis word', () => {
    render(body(okState(detailFixture())));
    for (const item of screen.getAllByRole('listitem')) {
      assert.match(item.textContent ?? '', /Observed|Inferred|Unknown/);
    }
  });
});
