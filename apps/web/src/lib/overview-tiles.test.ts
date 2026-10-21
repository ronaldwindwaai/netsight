import assert from 'node:assert/strict';
import test from 'node:test';

import type { SecurityEvent, SecurityEventsResponse } from './api-contracts-security.ts';
import type { UsersAggregateResponse } from './api-contracts-users.ts';
import type { FetchState } from './api-response.ts';
import {
  OVERVIEW_SECURITY_LIMIT,
  overviewSecurityRequest,
  overviewUsersRequest,
  securityTile,
  usersTile,
} from './overview-tiles.ts';

const FRESH = { state: 'fresh', observed_at: '2026-01-01T00:00:00Z', source: 'wazuh' } as const;

function event(severity: SecurityEvent['severity'], index: number): SecurityEvent {
  return {
    id: `e${index}`,
    observed_at: '2026-01-01T00:00:00Z',
    source: 'wazuh',
    severity,
    category: null,
    signature: 'sig',
    source_ip: null,
    destination_ip: null,
    device_id: null,
  };
}

function security(
  state: SecurityEventsResponse['state'],
  events: SecurityEvent[],
  freshness: { state: string; observed_at: string; source: string } = FRESH,
): FetchState<SecurityEventsResponse> {
  const data = { state, events, freshness, time_range: { from: 'a', to: 'b', preset: '24h' } };
  return { kind: 'ok', data: data as unknown as SecurityEventsResponse, correlationId: 'c' };
}

function users(over: Record<string, unknown>): FetchState<UsersAggregateResponse> {
  const data = {
    state: 'ok',
    as_of: 'x',
    window: { from: 'a', to: 'b' },
    sources: [],
    people_total: 12,
    with_observed_session: 3,
    with_inferred_session: 1,
    without_session_evidence: 8,
    vpn_sessions: 0,
    ...over,
  };
  return { kind: 'ok', data: data as unknown as UsersAggregateResponse, correlationId: 'c' };
}

function failure(kind: string): FetchState<never> {
  return { kind, code: 'x', message: 'm', correlationId: 'c', status: 500 } as FetchState<never>;
}

test('requests are made only for a role that holds the permission, and for an unread session', () => {
  assert.equal(overviewSecurityRequest(['incidents:read']), null);
  assert.match(overviewSecurityRequest(['security:read']) ?? '', /security\/events\?preset=24h&limit=100$/);
  assert.notEqual(overviewSecurityRequest(null), null);
  assert.equal(overviewUsersRequest(['security:read']), null);
  assert.equal(overviewUsersRequest(['users:read-summary']), '/api/v1/users/summary');
});

test('security: restricted, failed, not-connected, unknown and empty are all distinct', () => {
  assert.equal(securityTile(null).value, 'Restricted');
  assert.equal(securityTile(failure('forbidden')).value, 'Restricted');
  assert.equal(securityTile(failure('source_unavailable')).value, 'Unknown');
  assert.equal(securityTile(security('not-connected', [])).value, 'Not connected');
  assert.equal(securityTile(security('unknown', [])).value, 'Unknown');
  const empty = securityTile(security('ok', []));
  assert.equal(empty.value, '0 listed');
  assert.match(empty.detail, /not proof/);
});

test('security: counts are of the listed events and name the read cap when reached', () => {
  const few = securityTile(security('ok', [event('critical', 1), event('high', 2), event('low', 3)]));
  assert.equal(few.value, '3 events listed');
  assert.match(few.detail, /1 critical · 1 high · of the 3 listed/);
  assert.equal(few.theme, 'danger');
  const capped = securityTile(
    security('ok', Array.from({ length: OVERVIEW_SECURITY_LIMIT }, (_, i) => event('low', i))),
  );
  assert.equal(capped.value, `${OVERVIEW_SECURITY_LIMIT}+ events listed`);
  assert.match(capped.detail, /more may exist/);
  assert.equal(capped.theme, 'info');
});

test('security: stale freshness is stated', () => {
  const stale = securityTile(security('ok', [event('low', 1)], { ...FRESH, state: 'stale' }));
  assert.match(stale.detail, /data stale/);
});

test('users: restricted, failed, not-connected, unknown and not-reported are distinct', () => {
  assert.equal(usersTile(null).value, 'Restricted');
  assert.equal(usersTile(failure('forbidden')).value, 'Restricted');
  assert.equal(usersTile(failure('error')).value, 'Unknown');
  assert.equal(usersTile(users({ state: 'not-connected' })).value, 'Not connected');
  assert.equal(usersTile(users({ state: 'unknown' })).value, 'Unknown');
  assert.equal(usersTile(users({ people_total: null })).value, 'Not reported');
});

test('users: shows the aggregate count and flags a truncated source', () => {
  assert.equal(usersTile(users({})).value, '12 people known');
  assert.match(usersTile(users({})).detail, /3 with an observed session/);
  assert.equal(usersTile(users({ people_total: 1 })).value, '1 person known');
  const source = { source: 's', state: 'ok', record_count: 1, truncated: true, freshness: FRESH };
  assert.match(usersTile(users({ sources: [source] })).detail, /truncated/);
});
