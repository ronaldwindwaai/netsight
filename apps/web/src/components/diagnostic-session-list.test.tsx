import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { DiagnosticSessionList } from '@/components/diagnostic-session-list';
import SessionLoading from '@/app/(dashboard)/diagnostics/[diagnosticId]/loading';
import type { FetchState } from '@/lib/api-response';
import type { DiagnosticSessionListResponse } from '@/lib/api-contracts-diagnostic-session';
import { SESSION_ID, summaryFixture } from '@/test/diagnostic-fixtures';

afterEach(() => cleanup());

const OTHER_ID = 'diagnostic-2a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d';

function ok(
  overrides: Partial<DiagnosticSessionListResponse> = {},
): FetchState<DiagnosticSessionListResponse> {
  return {
    kind: 'ok',
    correlationId: 'c',
    data: {
      state: 'ok',
      sessions: [summaryFixture(SESSION_ID), summaryFixture(OTHER_ID, { probable_fault_domain: null, confidence: 'unknown', target: 'host-b' })],
      limit: 20,
      offset: 0,
      next_offset: null,
      ...overrides,
    },
  };
}

function failure(kind: string, status: number): FetchState<DiagnosticSessionListResponse> {
  return {
    kind,
    code: kind.toUpperCase(),
    message: 'Something went wrong.',
    correlationId: 'corr-1',
    status,
  } as FetchState<DiagnosticSessionListResponse>;
}

describe('recent sessions', () => {
  it('lists stored sessions newest first with a link to each', () => {
    render(<DiagnosticSessionList state={ok()} offset={0} />);
    const links = screen.getAllByRole('link', { name: /Open session/ });
    assert.deepEqual(
      links.map((link) => link.getAttribute('href')),
      [`/diagnostics/${SESSION_ID}`, `/diagnostics/${OTHER_ID}`],
    );
    const rows = screen.getAllByRole('row').slice(1);
    assert.match(rows[0].textContent ?? '', /Firewall \/ path/);
    assert.match(rows[1].textContent ?? '', /No probable cause/);
    assert.doesNotMatch(rows[1].textContent ?? '', /healthy/i);
  });

  it('never links a session whose id is not exactly a session id', () => {
    const state = ok({ sessions: [summaryFixture(SESSION_ID), { ...summaryFixture(), id: 'diagnostic-../../x' }] });
    render(<DiagnosticSessionList state={state} offset={0} />);
    assert.equal(screen.getAllByRole('link', { name: /Open session/ }).length, 1);
  });

  it('shows a valid empty page as empty, not as an error', () => {
    render(<DiagnosticSessionList state={ok({ sessions: [] })} offset={0} />);
    assert.match(screen.getByRole('status').textContent ?? '', /No diagnostic sessions stored/);
  });

  for (const [state, text] of [
    ['not-connected', /Diagnostic session store not connected/],
    ['unknown', /Diagnostic session store state unknown/],
  ] as const) {
    it(`shows a ${state} store without rows`, () => {
      const data: FetchState<DiagnosticSessionListResponse> = {
        kind: 'ok',
        correlationId: 'c',
        data: { state, sessions: [], limit: 20, offset: 0, next_offset: null },
      };
      render(<DiagnosticSessionList state={data} offset={0} />);
      assert.match(screen.getByRole('status').textContent ?? '', text);
      assert.equal(screen.queryAllByRole('row').length, 0);
    });
  }

  for (const [kind, status, text] of [
    ['forbidden', 403, /Permission denied/],
    ['unauthenticated', 401, /sign-in required/i],
    ['rate_limited', 429, /Too many requests/],
    ['error', 500, /Unable to load data/],
  ] as const) {
    it(`shows ${kind} explicitly`, () => {
      render(<DiagnosticSessionList state={failure(kind, status)} offset={0} />);
      assert.match(document.body.textContent ?? '', text);
      assert.equal(screen.queryAllByRole('link', { name: /Open session/ }).length, 0);
    });
  }

  it('pages with bounded offsets only', () => {
    render(<DiagnosticSessionList state={ok({ offset: 20, next_offset: 40 })} offset={20} />);
    const nav = screen.getByRole('navigation', { name: 'Session pages' });
    assert.equal(within(nav).getByRole('link', { name: /Next/ }).getAttribute('href'), '/diagnostics?offset=40');
    assert.equal(within(nav).getByRole('link', { name: /Previous/ }).getAttribute('href'), '/diagnostics');
  });

  it('says a stored list is read from the store, with the retrieval time', () => {
    render(<DiagnosticSessionList state={ok()} offset={0} />);
    assert.match(document.body.textContent ?? '', /Retrieved \d{4}-\d{2}-\d{2}/);
  });
});

describe('loading state', () => {
  it('announces that the session is loading', () => {
    render(<SessionLoading />);
    assert.ok(screen.getAllByRole('status').length > 0);
    assert.match(document.body.textContent ?? '', /Loading diagnostic session/);
  });
});
