import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';

import { IncidentTimeline } from '@/components/incident-timeline';
import type { IncidentTimelineEvent } from '@/lib/api-contracts-incident';

afterEach(() => cleanup());

const UUID = '11111111-2222-4333-8444-555555555555';
function event(changes: Partial<IncidentTimelineEvent>): IncidentTimelineEvent {
  return {
    id: `incident-event-${UUID}`,
    incident_id: `incident-${UUID}`,
    seq: 1,
    occurred_at: '2026-10-18T12:00:00Z',
    actor_id: 'oidc:eng',
    kind: 'comment',
    state_from: null,
    state_to: null,
    reason: null,
    message: null,
    subject_id: null,
    ...changes,
  };
}

describe('incident timeline', () => {
  it('shows a state change as two state badges with words, not a bare sentence', () => {
    render(<IncidentTimeline events={[event({ kind: 'state-changed', state_from: 'open', state_to: 'acknowledged' })]} />);
    const item = screen.getByRole('listitem');
    assert.match(item.textContent ?? '', /Open/);
    assert.match(item.textContent ?? '', /Acknowledged/);
    assert.ok(item.querySelectorAll('.badge i.bi[aria-hidden="true"]').length >= 3);
    assert.match(item.querySelector('.visually-hidden')?.textContent ?? '', /changed to/);
  });

  it('links an action event to its request and a diagnostic event to its session', () => {
    render(
      <IncidentTimeline
        events={[
          event({ id: `incident-event-${UUID}`, seq: 1, kind: 'action-proposed', subject_id: `action-${UUID}` }),
          event({ id: `incident-event-aaaaaaaa-2222-4333-8444-555555555555`, seq: 2, kind: 'diagnostic', subject_id: `diagnostic-${UUID}` }),
        ]}
      />,
    );
    assert.equal(screen.getByRole('link', { name: /Open action request/ }).getAttribute('href'), `/actions/action-${UUID}`);
    assert.equal(screen.getByRole('link', { name: /Open diagnostic session/ }).getAttribute('href'), `/diagnostics/diagnostic-${UUID}`);
  });

  it('does not link ids of the wrong shape or the wrong kind', () => {
    const wrong = [
      event({ kind: 'action-proposed', subject_id: `diagnostic-${UUID}` }),
      event({ kind: 'diagnostic', subject_id: `action-${UUID}`, seq: 2 }),
      event({ kind: 'action-approved', subject_id: 'action-123', seq: 3 }),
      event({ kind: 'diagnostic', subject_id: `diagnostic-${UUID}/../x`, seq: 4 }),
      event({ kind: 'comment', subject_id: `action-${UUID}`, seq: 5 }),
    ];
    render(<IncidentTimeline events={wrong.map((e, i) => ({ ...e, id: `incident-event-0000000${i}-2222-4333-8444-555555555555` }))} />);
    assert.equal(screen.queryByRole('link'), null);
  });

  it('never turns hostile subject text into a link or markup', () => {
    const { container } = render(
      <IncidentTimeline events={[event({ kind: 'action-proposed', subject_id: '../../x"><img src=x>', message: '<img src=x onerror=alert(1)>' })]} />,
    );
    assert.equal(screen.queryByRole('link'), null);
    assert.equal(container.querySelector('img'), null);
  });
});
