import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';

import { UsersAccessDenied } from '@/components/users-access-denied';
import { UsersSummaryCard } from '@/components/users-summary-card';
import type { UsersAggregateResponse } from '@/lib/api-contracts-identity';
import {
  aggregateFixture,
  failureState,
  okState,
  sourceNotConnected,
  sourceUnknown,
} from '@/test/identity-fixtures';

afterEach(() => cleanup());

describe('the aggregate', () => {
  it('shows counts only and says no names or identifiers are shown to this role', () => {
    render(<UsersSummaryCard state={okState(aggregateFixture())} />);
    const text = document.body.textContent ?? '';
    assert.match(text, /People known/);
    assert.ok(screen.getByText('5'));
    assert.match(text, /Observed session/);
    assert.match(text, /Inferred session only/);
    assert.match(text, /No session evidence/);
    assert.match(text, /VPN sessions/);
    assert.match(text, /Counts only/);
    assert.match(text, /as of 2026-10-11 12:00:00 UTC/i);
    assert.equal(screen.queryAllByRole('link').length, 0);
  });

  it('presents no per-person row, name or profile link', () => {
    render(<UsersSummaryCard state={okState(aggregateFixture())} />);
    assert.equal(screen.queryAllByRole('table').length, 0);
    assert.doesNotMatch(document.body.textContent ?? '', /person-|Alice|Bob/);
  });

  it('is not-connected without a count of zero', () => {
    const state = okState(aggregateFixture({ state: 'not-connected', people_total: null, with_observed_session: null, with_inferred_session: null, without_session_evidence: null, vpn_sessions: null, sources: [sourceNotConnected('wazuh')] }));
    render(<UsersSummaryCard state={state} />);
    const text = screen.getByRole('status').textContent ?? '';
    assert.match(text, /not connected/i);
    assert.doesNotMatch(document.body.textContent ?? '', /People known/);
  });

  it('is unknown when a source failed, with nothing estimated', () => {
    const state = okState(aggregateFixture({ state: 'unknown', people_total: null, with_observed_session: null, with_inferred_session: null, without_session_evidence: null, vpn_sessions: null, sources: [sourceUnknown('wazuh')] }));
    render(<UsersSummaryCard state={state} />);
    assert.match(screen.getByRole('status').textContent ?? '', /Nothing is estimated/);
  });

  it('says what a partial read missed', () => {
    render(<UsersSummaryCard state={okState(aggregateFixture({ sources: [aggregateFixture().sources[0], sourceUnknown('netbox')] }))} />);
    assert.match(document.body.textContent ?? '', /netbox: could not be read/);
  });

  it('reports permission, sign-in, error and rate-limit failures distinctly', () => {
    render(<UsersSummaryCard state={failureState<UsersAggregateResponse>('forbidden', 403)} />);
    assert.match(screen.getByRole('status').textContent ?? '', /users:read-summary/);
    cleanup();
    render(<UsersSummaryCard state={failureState<UsersAggregateResponse>('unauthenticated', 401)} />);
    assert.ok(screen.getByRole('link', { name: /Sign in/ }));
    cleanup();
    render(<UsersSummaryCard state={failureState<UsersAggregateResponse>('error', 500)} />);
    assert.match(document.body.textContent ?? '', /Unable to load data/);
    cleanup();
    render(<UsersSummaryCard state={failureState<UsersAggregateResponse>('rate_limited', 429)} />);
    assert.match(document.body.textContent ?? '', /Too many requests/);
  });
});

describe('access denied', () => {
  it('explains the permission and renders no control or data', () => {
    const { container } = render(<UsersAccessDenied />);
    const text = screen.getByRole('status').textContent ?? '';
    assert.match(text, /not available to your role/);
    assert.match(text, /users:read-summary/);
    assert.equal(container.querySelectorAll('input, select, button, a').length, 0);
  });
});
