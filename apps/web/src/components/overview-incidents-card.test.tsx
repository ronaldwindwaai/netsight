import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';

import { OverviewIncidentsCard } from '@/components/overview-incidents-card';
import type { IncidentSummaryListResponse } from '@/lib/api-contracts-incident-api';
import { failureState, okState } from '@/test/traffic-fixtures';

afterEach(() => cleanup());

const row = (severity: 'critical' | 'high' | 'low', state: 'open' | 'investigating' | 'resolved' | 'closed', n: number) => ({
  id: `incident-00000000-0000-0000-0000-00000000000${n}`,
  title: `t${n}`,
  severity,
  state,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
  assigned: false,
  resolved_at: state === 'resolved' || state === 'closed' ? '2026-01-02T00:00:00Z' : null,
});

function list(over: Partial<IncidentSummaryListResponse>): IncidentSummaryListResponse {
  return { state: 'ok', incidents: [], limit: 50, offset: 0, next_offset: null, ...over };
}

const card = () => screen.getByRole('region', { name: /Active incidents/i });

describe('the overview incidents card', () => {
  it('is Restricted, not empty, without incident access', () => {
    render(<OverviewIncidentsCard state={null} />);
    assert.match(card().textContent ?? '', /Restricted/);
  });

  it('counts active incidents among the listed ones and labels it so', () => {
    const incidents = [row('critical', 'open', 1), row('high', 'investigating', 2), row('low', 'resolved', 3), row('low', 'closed', 4)];
    render(<OverviewIncidentsCard state={okState(list({ incidents }))} />);
    assert.match(card().textContent ?? '', /2 active/);
    assert.match(card().textContent ?? '', /of the 4 listed/);
    assert.match(card().textContent ?? '', /1 critical/);
    assert.ok(screen.getByRole('link', { name: /open incidents/i }));
  });

  it('says more exist beyond the listed page instead of presenting a total', () => {
    render(<OverviewIncidentsCard state={okState(list({ incidents: [row('low', 'open', 1)], next_offset: 50 }))} />);
    assert.match(card().textContent ?? '', /more incidents exist beyond/i);
  });

  it('shows a valid empty list as none listed, not as proof of safety', () => {
    render(<OverviewIncidentsCard state={okState(list({}))} />);
    assert.match(card().textContent ?? '', /No incidents listed/);
    assert.doesNotMatch(card().textContent ?? '', /all clear|healthy/i);
  });

  it('shows not-connected and unknown store states explicitly, with no count', () => {
    render(<OverviewIncidentsCard state={okState(list({ state: 'not-connected' }))} />);
    assert.match(card().textContent ?? '', /not connected/i);
    assert.doesNotMatch(card().textContent ?? '', /\d+ active/);
    cleanup();
    render(<OverviewIncidentsCard state={okState(list({ state: 'unknown' }))} />);
    assert.match(card().textContent ?? '', /unknown/i);
  });

  it('shows a failed read as unavailable with a link to the full page', () => {
    render(<OverviewIncidentsCard state={failureState('error', 500)} />);
    assert.match(card().textContent ?? '', /could not be read/i);
    assert.ok(screen.getByRole('link', { name: /open incidents/i }));
  });
});
