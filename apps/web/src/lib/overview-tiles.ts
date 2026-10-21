import type { SecurityEventsResponse } from './api-contracts-security.ts';
import type { UsersAggregateResponse } from './api-contracts-users.ts';
import type { FetchState } from './api-response.ts';
import { severityCounts } from './security-summary.ts';

/** Listed security events the overview reads; the tile says "of the N listed", never a total. */
export const OVERVIEW_SECURITY_LIMIT = 100;
export const OVERVIEW_SECURITY_PATH = `/api/v1/security/events?preset=24h&limit=${OVERVIEW_SECURITY_LIMIT}`;
export const OVERVIEW_USERS_PATH = '/api/v1/users/summary';

export interface OverviewTile {
  value: string;
  detail: string;
  theme: 'danger' | 'warning' | 'info' | 'secondary';
}

type Failed = Exclude<FetchState<unknown>, { kind: 'ok' }>;

const RESTRICTED_FETCH_KINDS = new Set(['forbidden', 'unauthenticated']);

function holds(permissions: readonly string[] | null, permission: string): boolean {
  // An unread session (null) attempts the request so the API's own refusal is what renders.
  return permissions === null || permissions.includes(permission);
}

/** The security events request for a session, or null when it lacks security:read (no request is made). */
export function overviewSecurityRequest(permissions: readonly string[] | null): string | null {
  return holds(permissions, 'security:read') ? OVERVIEW_SECURITY_PATH : null;
}

/** The users aggregate request, or null without users:read-summary. Counts only, no per-person data. */
export function overviewUsersRequest(permissions: readonly string[] | null): string | null {
  return holds(permissions, 'users:read-summary') ? OVERVIEW_USERS_PATH : null;
}

export type OverviewUsersAccess = 'summary' | 'per-person' | 'none';

/**
 * How the viewer reaches users: the aggregate (users:read-summary, or an unread session so the API
 * decides), per-person pages only (users:read or users:read-limited: link, no aggregate fetch), or not at all.
 */
export function overviewUsersAccess(permissions: readonly string[] | null): OverviewUsersAccess {
  if (holds(permissions, 'users:read-summary')) return 'summary';
  const perPerson = permissions?.some((p) => p === 'users:read' || p === 'users:read-limited') ?? false;
  return perPerson ? 'per-person' : 'none';
}

function restricted(permission: string, what: string): OverviewTile {
  return {
    value: 'Restricted',
    detail: `${what} need ${permission}, which your role does not hold`,
    theme: 'secondary',
  };
}

function failed(state: Failed, permission: string, what: string): OverviewTile {
  if (RESTRICTED_FETCH_KINDS.has(state.kind)) return restricted(permission, what);
  return { value: 'Unknown', detail: `${what} could not be read; nothing is estimated`, theme: 'secondary' };
}

/** Security tile: counts of the events listed for the last 24 hours, with the read cap stated. */
export function securityTile(state: FetchState<SecurityEventsResponse> | null): OverviewTile {
  const what = 'Security events';
  if (state === null) return restricted('security:read', what);
  if (state.kind !== 'ok') return failed(state, 'security:read', what);
  const { data } = state;
  if (data.state === 'not-connected') {
    return { value: 'Not connected', detail: 'No security source is configured', theme: 'secondary' };
  }
  if (data.state === 'unknown') {
    return { value: 'Unknown', detail: 'The security source could not be read', theme: 'secondary' };
  }
  const listed = data.events.length;
  if (listed === 0) {
    return {
      value: '0 listed',
      detail: 'No events in the last 24 h; not proof nothing happened',
      theme: 'secondary',
    };
  }
  const capped = listed >= OVERVIEW_SECURITY_LIMIT;
  const counts = severityCounts(data.events);
  const severe = [
    ...(counts.critical > 0 ? [`${counts.critical} critical`] : []),
    ...(counts.high > 0 ? [`${counts.high} high`] : []),
  ];
  const parts = [
    ...(severe.length > 0 ? severe : ['none critical or high']),
    capped ? `of the ${listed} listed in 24 h; more may exist` : `of the ${listed} listed in the last 24 h`,
  ];
  const stale = data.freshness.state === 'fresh' ? '' : ` · data ${data.freshness.state}`;
  let theme: OverviewTile['theme'] = 'info';
  if (counts.critical > 0) theme = 'danger';
  else if (counts.high > 0) theme = 'warning';
  return { value: `${listed}${capped ? '+' : ''} events listed`, detail: `${parts.join(' · ')}${stale}`, theme };
}

/** Users tile: the aggregate people count (counts only; the API is the source of the total). */
export function usersTile(state: FetchState<UsersAggregateResponse> | 'per-person' | null): OverviewTile {
  const what = 'User counts';
  if (state === 'per-person') {
    return {
      value: 'Not summarised',
      detail: 'Your role reads people individually, not as counts; open Users',
      theme: 'secondary',
    };
  }
  if (state === null) return restricted('users:read-summary', what);
  if (state.kind !== 'ok') return failed(state, 'users:read-summary', what);
  const { data } = state;
  if (data.state === 'not-connected') {
    return { value: 'Not connected', detail: 'No identity evidence source is configured', theme: 'secondary' };
  }
  if (data.state === 'unknown') {
    return { value: 'Unknown', detail: 'The identity sources could not be read', theme: 'secondary' };
  }
  if (data.people_total === null) {
    return { value: 'Not reported', detail: 'The identity sources reported no people count', theme: 'secondary' };
  }
  const observed = data.with_observed_session === null ? 'not reported' : String(data.with_observed_session);
  const truncated = data.sources.some((source) => source.truncated);
  const caveat = truncated ? ' · a source was truncated, so this may undercount' : '';
  return {
    value: `${data.people_total} ${data.people_total === 1 ? 'person' : 'people'} known`,
    detail: `${observed} with an observed session${caveat}`,
    theme: 'info',
  };
}
