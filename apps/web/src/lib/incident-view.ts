import {
  INCIDENT_SEVERITIES,
  INCIDENT_STATES,
  type Incident,
  type IncidentSeverity,
  type IncidentState,
  type IncidentTimelineEvent,
  type TimelineEventKind,
} from './api-contracts-incident.ts';
import { MAX_INCIDENT_LIST_OFFSET, MAX_TIMELINE_SEQ } from './api-contracts-incident-api.ts';
import { codePointLength, isOneOf } from './contract-guards.ts';

export const DEFAULT_INCIDENT_PAGE_SIZE = 50;
export const DEFAULT_TIMELINE_PAGE_SIZE = 50;
const MAX_ASSIGNEE_LENGTH = 255;
const INCIDENT_ID =
  /^incident-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const NON_NEGATIVE_INTEGER = /^\d{1,7}$/;

/** Most severe first, for summary strips. */
export const SEVERITY_DISPLAY_ORDER: readonly IncidentSeverity[] = [
  'critical',
  'high',
  'medium',
  'low',
];

const STATE_LABELS: Record<IncidentState, string> = {
  open: 'Open',
  acknowledged: 'Acknowledged',
  investigating: 'Investigating',
  mitigated: 'Mitigated',
  resolved: 'Resolved',
  closed: 'Closed',
};

const SEVERITY_LABELS: Record<IncidentSeverity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

const TIMELINE_KIND_LABELS: Record<TimelineEventKind, string> = {
  'alert-linked': 'Alert linked',
  'alert-unlinked': 'Alert unlinked',
  'assignee-changed': 'Assignee changed',
  comment: 'Comment',
  diagnostic: 'Diagnostic',
  'action-proposed': 'Action proposed',
  'action-approved': 'Action approved',
  'action-executed': 'Action executed',
  'evidence-added': 'Evidence added',
  'state-changed': 'State changed',
  resolution: 'Resolution',
};

export function stateLabel(state: IncidentState): string {
  return STATE_LABELS[state];
}

export function severityLabel(severity: IncidentSeverity): string {
  return SEVERITY_LABELS[severity];
}

export function isIncidentId(value: string): boolean {
  return INCIDENT_ID.test(value);
}

/** Encoded detail link, or null when the id does not match the contract pattern. */
export function incidentHref(id: string): string | null {
  return isIncidentId(id) ? `/incidents/${encodeURIComponent(id)}` : null;
}

export interface IncidentCounts {
  /** Number of incidents in the list these counts were taken from. */
  listed: number;
  bySeverity: Record<IncidentSeverity, number>;
  byState: Record<IncidentState, number>;
}

/**
 * Counts over the listed page only, never a total reported by the store.
 * Callers must label them "of the listed incidents".
 */
export function incidentCounts(incidents: readonly Incident[]): IncidentCounts {
  const bySeverity = Object.fromEntries(
    INCIDENT_SEVERITIES.map((severity) => [severity, 0]),
  ) as Record<IncidentSeverity, number>;
  const byState = Object.fromEntries(INCIDENT_STATES.map((state) => [state, 0])) as Record<
    IncidentState,
    number
  >;
  for (const incident of incidents) {
    bySeverity[incident.severity] += 1;
    byState[incident.state] += 1;
  }
  return { listed: incidents.length, bySeverity, byState };
}

export type RawQuery = Record<string, string | string[] | undefined>;

export interface IncidentFilters {
  state: IncidentState | null;
  severity: IncidentSeverity | null;
  assigneeId: string | null;
  offset: number;
}

function firstValue(raw: string | string[] | undefined): string | undefined {
  return Array.isArray(raw) ? raw[0] : raw;
}

function boundedInteger(raw: string | string[] | undefined, maximum: number): number {
  const value = firstValue(raw);
  if (value === undefined || !NON_NEGATIVE_INTEGER.test(value)) return 0;
  const parsed = Number(value);
  return parsed <= maximum ? parsed : 0;
}

/** Only contract-valid values survive; anything else is dropped rather than forwarded. */
export function parseIncidentFilters(raw: RawQuery): IncidentFilters {
  const state = firstValue(raw.state);
  const severity = firstValue(raw.severity);
  const assignee = firstValue(raw.assignee_id)?.trim();
  const assigneeValid =
    assignee !== undefined &&
    assignee.length > 0 &&
    codePointLength(assignee) <= MAX_ASSIGNEE_LENGTH;
  return {
    state: isOneOf(state, INCIDENT_STATES) ? state : null,
    severity: isOneOf(severity, INCIDENT_SEVERITIES) ? severity : null,
    assigneeId: assigneeValid ? assignee : null,
    offset: boundedInteger(raw.offset, MAX_INCIDENT_LIST_OFFSET),
  };
}

function encodePairs(pairs: ReadonlyArray<readonly [string, string]>): string {
  return pairs.map(([key, value]) => `${key}=${encodeURIComponent(value)}`).join('&');
}

function filterPairs(filters: IncidentFilters): Array<readonly [string, string]> {
  const pairs: Array<readonly [string, string]> = [];
  if (filters.state) pairs.push(['state', filters.state]);
  if (filters.severity) pairs.push(['severity', filters.severity]);
  if (filters.assigneeId) pairs.push(['assignee_id', filters.assigneeId]);
  return pairs;
}

export function incidentListPath(filters: IncidentFilters): string {
  const pairs: Array<readonly [string, string]> = [
    ['limit', String(DEFAULT_INCIDENT_PAGE_SIZE)],
    ['offset', String(filters.offset)],
    ...filterPairs(filters),
  ];
  return `/api/v1/incidents?${encodePairs(pairs)}`;
}

function listHref(filters: IncidentFilters, offset: number): string {
  const pairs = filterPairs(filters);
  if (offset > 0) pairs.push(['offset', String(offset)]);
  return pairs.length === 0 ? '/incidents' : `/incidents?${encodePairs(pairs)}`;
}

export interface PageHrefs {
  previous: string | null;
  next: string | null;
}

/** Next uses the server-issued cursor; previous steps back by one page, clamped at zero. */
export function incidentPageHrefs(
  filters: IncidentFilters,
  limit: number,
  nextOffset: number | null,
): PageHrefs {
  return {
    previous: filters.offset > 0 ? listHref(filters, Math.max(0, filters.offset - limit)) : null,
    next: nextOffset === null ? null : listHref(filters, nextOffset),
  };
}

export function incidentDetailPath(id: string): string | null {
  return isIncidentId(id) ? `/api/v1/incidents/${encodeURIComponent(id)}` : null;
}

export function timelinePath(id: string, afterSeq: number): string | null {
  if (!isIncidentId(id)) return null;
  return `/api/v1/incidents/${encodeURIComponent(id)}/timeline?after_seq=${afterSeq}&limit=${DEFAULT_TIMELINE_PAGE_SIZE}`;
}

export function parseTimelineCursor(raw: string | string[] | undefined): number {
  return boundedInteger(raw, MAX_TIMELINE_SEQ);
}

/** Detail link at a timeline cursor; the cursor is omitted at the start. */
export function incidentDetailHref(id: string, afterSeq: number): string | null {
  const base = incidentHref(id);
  if (base === null) return null;
  return afterSeq > 0 ? `${base}?after_seq=${afterSeq}` : base;
}

export interface TimelineEventSummary {
  label: string;
  /** Short plain-text qualifier; the free-text message is rendered separately. */
  detail: string | null;
}

export function timelineEventSummary(event: IncidentTimelineEvent): TimelineEventSummary {
  const label = TIMELINE_KIND_LABELS[event.kind];
  if (event.kind === 'state-changed' && event.state_from && event.state_to) {
    return { label, detail: `${stateLabel(event.state_from)} to ${stateLabel(event.state_to)}` };
  }
  return { label, detail: event.subject_id };
}
