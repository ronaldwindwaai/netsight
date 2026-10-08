import {
  hasExactKeys,
  isIntegerInRange,
  isPlainRecord,
  isOneOf,
  parseArray,
} from './contract-guards.ts';
import {
  parseIncident,
  parseIncidentTimelineEvent,
  type Incident,
  type IncidentTimelineEvent,
} from './api-contracts-incident.ts';

/** not-connected: no incident store configured; unknown: the store failed; ok: stored rows. */
export const INCIDENT_API_STATES = ['not-connected', 'ok', 'unknown'] as const;
export type IncidentApiState = (typeof INCIDENT_API_STATES)[number];

/** Server-side caps; the API rejects anything beyond them with 422. */
export const MAX_INCIDENT_PAGE_SIZE = 100;
export const MAX_INCIDENT_LIST_OFFSET = 10_000;
export const MAX_TIMELINE_PAGE_SIZE = 500;
export const MAX_TIMELINE_SEQ = 1_000_000;

export interface IncidentListResponse {
  state: IncidentApiState;
  incidents: Incident[];
  limit: number;
  offset: number;
  next_offset: number | null;
}

export interface IncidentDetailResponse {
  state: IncidentApiState;
  incident: Incident | null;
}

export interface IncidentTimelineResponse {
  state: IncidentApiState;
  incident_id: string;
  events: IncidentTimelineEvent[];
  after_seq: number;
  next_after_seq: number | null;
}

const LIST_KEYS = ['state', 'incidents', 'limit', 'offset', 'next_offset'] as const;
const DETAIL_KEYS = ['state', 'incident'] as const;
const TIMELINE_KEYS = ['state', 'incident_id', 'events', 'after_seq', 'next_after_seq'] as const;
const INCIDENT_ID =
  /^incident-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function isNullableCursor(value: unknown, maximum: number): value is number | null {
  return value === null || isIntegerInRange(value, 1, maximum);
}

/** Fail closed: a non-ok state never carries rows or a cursor, whatever the payload says. */
export function parseIncidentListResponse(value: unknown): IncidentListResponse | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, LIST_KEYS)) return null;
  if (
    !isOneOf(value.state, INCIDENT_API_STATES) ||
    !isIntegerInRange(value.limit, 1, MAX_INCIDENT_PAGE_SIZE) ||
    !isIntegerInRange(value.offset, 0, MAX_INCIDENT_LIST_OFFSET) ||
    !isNullableCursor(value.next_offset, MAX_INCIDENT_LIST_OFFSET)
  ) {
    return null;
  }
  const incidents = parseArray(value.incidents, 0, MAX_INCIDENT_PAGE_SIZE, parseIncident);
  if (incidents === null) return null;
  if (value.state !== 'ok' && (incidents.length > 0 || value.next_offset !== null)) return null;
  return {
    state: value.state,
    incidents,
    limit: value.limit,
    offset: value.offset,
    next_offset: value.next_offset,
  };
}

export function parseIncidentDetailResponse(value: unknown): IncidentDetailResponse | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, DETAIL_KEYS)) return null;
  if (!isOneOf(value.state, INCIDENT_API_STATES)) return null;
  const incident = value.incident === null ? null : parseIncident(value.incident);
  if (value.incident !== null && incident === null) return null;
  // The incident is present exactly when the state is ok.
  if ((value.state === 'ok') !== (incident !== null)) return null;
  return { state: value.state, incident };
}

export function parseIncidentTimelineResponse(value: unknown): IncidentTimelineResponse | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, TIMELINE_KEYS)) return null;
  if (
    !isOneOf(value.state, INCIDENT_API_STATES) ||
    typeof value.incident_id !== 'string' ||
    !INCIDENT_ID.test(value.incident_id) ||
    !isIntegerInRange(value.after_seq, 0, MAX_TIMELINE_SEQ) ||
    !isNullableCursor(value.next_after_seq, MAX_TIMELINE_SEQ)
  ) {
    return null;
  }
  const events = parseArray(value.events, 0, MAX_TIMELINE_PAGE_SIZE, parseIncidentTimelineEvent);
  if (events === null) return null;
  if (value.state !== 'ok' && (events.length > 0 || value.next_after_seq !== null)) return null;
  return {
    state: value.state,
    incident_id: value.incident_id,
    events,
    after_seq: value.after_seq,
    next_after_seq: value.next_after_seq,
  };
}
