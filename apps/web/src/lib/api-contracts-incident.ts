import { isRfc3339 } from './api-contracts.ts';
import {
  hasExactKeys,
  isIntegerInRange,
  isNonBlankText,
  isNullableNonBlankText,
  isNullableText,
  isOneOf,
  isPlainRecord,
  isText,
  parseArray,
  textItem,
} from './contract-guards.ts';

export const INCIDENT_SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;
export const INCIDENT_STATES = [
  'open',
  'acknowledged',
  'investigating',
  'mitigated',
  'resolved',
  'closed',
] as const;
export const ROOT_CAUSE_STATUSES = ['determined', 'not-determined'] as const;
export const TIMELINE_EVENT_KINDS = [
  'alert-linked',
  'alert-unlinked',
  'assignee-changed',
  'comment',
  'diagnostic',
  'action-proposed',
  'action-approved',
  'action-executed',
  'evidence-added',
  'state-changed',
  'resolution',
] as const;

export type IncidentSeverity = (typeof INCIDENT_SEVERITIES)[number];
export type IncidentState = (typeof INCIDENT_STATES)[number];
export type RootCauseStatus = (typeof ROOT_CAUSE_STATUSES)[number];
export type TimelineEventKind = (typeof TIMELINE_EVENT_KINDS)[number];

export interface IncidentResolution {
  summary: string;
  root_cause_status: RootCauseStatus;
  root_cause: string | null;
  impact: string;
  restored_at: string;
  resolved_at: string;
  resolved_by: string;
  follow_up_actions: string[];
}

export interface Incident {
  id: string;
  title: string;
  severity: IncidentSeverity;
  state: IncidentState;
  created_at: string;
  updated_at: string;
  assignee_id: string | null;
  evidence_ids: string[];
  resolution: IncidentResolution | null;
}

export interface IncidentTimelineEvent {
  id: string;
  incident_id: string;
  seq: number;
  occurred_at: string;
  actor_id: string;
  kind: TimelineEventKind;
  state_from: IncidentState | null;
  state_to: IncidentState | null;
  reason: string | null;
  message: string | null;
  subject_id: string | null;
}

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const INCIDENT_ID = new RegExp(`^incident-${UUID}$`);
const TIMELINE_EVENT_ID = new RegExp(`^incident-event-${UUID}$`);

const RESOLUTION_KEYS = [
  'summary',
  'root_cause_status',
  'root_cause',
  'impact',
  'restored_at',
  'resolved_at',
  'resolved_by',
  'follow_up_actions',
] as const;
const INCIDENT_KEYS = [
  'id',
  'title',
  'severity',
  'state',
  'created_at',
  'updated_at',
  'assignee_id',
  'evidence_ids',
  'resolution',
] as const;
const EVENT_KEYS = [
  'id',
  'incident_id',
  'seq',
  'occurred_at',
  'actor_id',
  'kind',
  'state_from',
  'state_to',
  'reason',
  'message',
  'subject_id',
] as const;
const SUBJECT_REQUIRED_KINDS: readonly TimelineEventKind[] = [
  'alert-linked',
  'alert-unlinked',
  'diagnostic',
  'action-proposed',
  'action-approved',
  'action-executed',
  'evidence-added',
];

function isTimestamp(value: unknown): value is string {
  return typeof value === 'string' && isRfc3339(value);
}

function isNullableState(value: unknown): value is IncidentState | null {
  return value === null || isOneOf(value, INCIDENT_STATES);
}

/** Fail-closed parse; returns a detached copy or null. */
export function parseIncidentResolution(value: unknown): IncidentResolution | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, RESOLUTION_KEYS)) return null;
  const followUps = parseArray(value.follow_up_actions, 0, 32, textItem(1, 500, true));
  if (
    !isNonBlankText(value.summary, 2000) ||
    !isOneOf(value.root_cause_status, ROOT_CAUSE_STATUSES) ||
    !isNullableNonBlankText(value.root_cause, 2000) ||
    !isNonBlankText(value.impact, 2000) ||
    !isTimestamp(value.restored_at) ||
    !isTimestamp(value.resolved_at) ||
    !isText(value.resolved_by, 1, 255) ||
    followUps === null
  ) {
    return null;
  }
  // determined <=> an accepted root cause text is present.
  if ((value.root_cause_status === 'determined') !== (value.root_cause !== null)) return null;
  // Cross-field rule JSON Schema cannot express.
  if (Date.parse(value.restored_at) > Date.parse(value.resolved_at)) return null;
  return {
    summary: value.summary,
    root_cause_status: value.root_cause_status,
    root_cause: value.root_cause,
    impact: value.impact,
    restored_at: value.restored_at,
    resolved_at: value.resolved_at,
    resolved_by: value.resolved_by,
    follow_up_actions: followUps,
  };
}

export function parseIncident(value: unknown): Incident | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, INCIDENT_KEYS)) return null;
  const evidence = parseArray(value.evidence_ids, 0, 256, textItem(1, 128), true);
  if (
    typeof value.id !== 'string' ||
    !INCIDENT_ID.test(value.id) ||
    !isNonBlankText(value.title, 255) ||
    !isOneOf(value.severity, INCIDENT_SEVERITIES) ||
    !isOneOf(value.state, INCIDENT_STATES) ||
    !isTimestamp(value.created_at) ||
    !isTimestamp(value.updated_at) ||
    !isNullableText(value.assignee_id, 1, 255) ||
    evidence === null
  ) {
    return null;
  }
  const resolution = value.resolution === null ? null : parseIncidentResolution(value.resolution);
  if (value.resolution !== null && resolution === null) return null;
  // resolution present <=> state is resolved or closed.
  const needsResolution = value.state === 'resolved' || value.state === 'closed';
  if (needsResolution !== (resolution !== null)) return null;
  return {
    id: value.id,
    title: value.title,
    severity: value.severity,
    state: value.state,
    created_at: value.created_at,
    updated_at: value.updated_at,
    assignee_id: value.assignee_id,
    evidence_ids: evidence,
    resolution,
  };
}

export function parseIncidentTimelineEvent(value: unknown): IncidentTimelineEvent | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, EVENT_KEYS)) return null;
  if (
    typeof value.id !== 'string' ||
    !TIMELINE_EVENT_ID.test(value.id) ||
    typeof value.incident_id !== 'string' ||
    !INCIDENT_ID.test(value.incident_id) ||
    !isIntegerInRange(value.seq, 1, 1_000_000) ||
    !isTimestamp(value.occurred_at) ||
    !isText(value.actor_id, 1, 255) ||
    !isOneOf(value.kind, TIMELINE_EVENT_KINDS) ||
    !isNullableState(value.state_from) ||
    !isNullableState(value.state_to) ||
    !isNullableNonBlankText(value.reason, 1000) ||
    !isNullableNonBlankText(value.message, 4000) ||
    !isNullableText(value.subject_id, 1, 128)
  ) {
    return null;
  }
  const isStateChange = value.kind === 'state-changed';
  if (isStateChange !== (value.state_from !== null && value.state_to !== null)) return null;
  if (!isStateChange && (value.state_from !== null || value.state_to !== null)) return null;
  if (isStateChange && value.state_to === 'open' && value.reason === null) return null;
  if ((value.kind === 'comment' || value.kind === 'resolution') && value.message === null) {
    return null;
  }
  if (SUBJECT_REQUIRED_KINDS.includes(value.kind) && value.subject_id === null) return null;
  return {
    id: value.id,
    incident_id: value.incident_id,
    seq: value.seq,
    occurred_at: value.occurred_at,
    actor_id: value.actor_id,
    kind: value.kind,
    state_from: value.state_from,
    state_to: value.state_to,
    reason: value.reason,
    message: value.message,
    subject_id: value.subject_id,
  };
}
