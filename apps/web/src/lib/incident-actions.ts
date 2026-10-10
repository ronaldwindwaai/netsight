/**
 * Incident write actions as the UI understands them: which are available to the viewer in the
 * incident's current state, and how a form submission becomes an API request.
 *
 * Both halves are advisory/defensive only. The API re-checks authorisation, state, scope and
 * step-up on every request; availability here exists to explain, not to enforce. Pure, so the
 * rules (and the contract bounds the planner mirrors) are unit-tested.
 */
import type { IncidentState } from './api-contracts-incident.ts';
import { ROOT_CAUSE_STATUSES } from './api-contracts-incident.ts';
import { codePointLength, isOneOf } from './contract-guards.ts';
import { isIncidentId } from './incident-view.ts';

export type IncidentActionName =
  | 'acknowledge'
  | 'progress'
  | 'assign'
  | 'comment'
  | 'resolve'
  | 'reopen';

export interface Viewer {
  identityId: string;
  permissions: readonly string[];
}

export interface ActionAvailability {
  action: IncidentActionName;
  label: string;
  enabled: boolean;
  /** Why the action is disabled; null when enabled. Plain text. */
  reason: string | null;
  /** Resolve and reopen need a recent multi-factor sign-in (the API refuses otherwise). */
  needsStepUp: boolean;
}

interface IncidentFacts {
  state: IncidentState;
  assignee_id: string | null;
}

const ROLE_REASON = 'Your role does not permit this action.';
const ASSIGNED_REASON = 'Technicians can only act on incidents assigned to you.';
const SIGN_IN_REASON = 'Sign in to act on incidents.';

function holds(viewer: Viewer, permission: string): boolean {
  return viewer.permissions.includes(permission);
}

type Gate = { ok: true } | { ok: false; reason: string };

/** Full permission, or the assigned-incidents-only permission on an incident assigned to the viewer. */
function gate(viewer: Viewer, full: string, incident: IncidentFacts, assignedScope: boolean): Gate {
  if (holds(viewer, full)) return { ok: true };
  if (assignedScope && holds(viewer, 'incidents:write-assigned')) {
    return incident.assignee_id === viewer.identityId
      ? { ok: true }
      : { ok: false, reason: ASSIGNED_REASON };
  }
  return { ok: false, reason: ROLE_REASON };
}

function resolveAvailability(
  action: IncidentActionName,
  label: string,
  needsStepUp: boolean,
  permission: Gate,
  stateReason: string | null,
): ActionAvailability {
  // Permission first: a role that cannot do this learns nothing about state-dependent rules.
  if (!permission.ok) return { action, label, enabled: false, reason: permission.reason, needsStepUp };
  if (stateReason !== null) return { action, label, enabled: false, reason: stateReason, needsStepUp };
  return { action, label, enabled: true, reason: null, needsStepUp };
}

const PROGRESS_LABEL: Partial<Record<IncidentState, string>> = {
  acknowledged: 'Mark investigating',
  investigating: 'Mark mitigated',
};

export function availableIncidentActions(
  incident: IncidentFacts,
  viewer: Viewer | null,
): ActionAvailability[] {
  const { state } = incident;
  const signedOut: Gate = { ok: false, reason: SIGN_IN_REASON };
  const check = (full: string, assignedScope: boolean): Gate =>
    viewer === null ? signedOut : gate(viewer, full, incident, assignedScope);

  return [
    resolveAvailability(
      'acknowledge',
      'Acknowledge',
      false,
      check('incidents:transition', true),
      state === 'open' ? null : 'Only an open incident can be acknowledged.',
    ),
    resolveAvailability(
      'progress',
      PROGRESS_LABEL[state] ?? 'Advance',
      false,
      check('incidents:transition', true),
      state === 'acknowledged' || state === 'investigating'
        ? null
        : 'Available once the incident is acknowledged and until it is mitigated.',
    ),
    resolveAvailability('assign', 'Assign', false, check('incidents:assign', false), null),
    resolveAvailability('comment', 'Comment', false, check('incidents:comment', true), null),
    resolveAvailability(
      'resolve',
      'Resolve',
      true,
      check('incidents:resolve', false),
      state === 'mitigated' ? null : 'An incident can be resolved once it is mitigated.',
    ),
    resolveAvailability(
      'reopen',
      'Reopen',
      true,
      check('incidents:reopen', false),
      state === 'resolved' || state === 'closed'
        ? null
        : 'Only a resolved or closed incident can be reopened.',
    ),
  ];
}

// --- request planning ----------------------------------------------------------------

export type PlannedRequest =
  | {
      ok: true;
      path: string;
      body: Record<string, unknown>;
      /** What a successful response parses as. */
      result: 'incident' | 'event';
    }
  | { ok: false; message: string };

const MAX_ASSIGNEE = 255;
const MAX_COMMENT = 4000;
const MAX_REASON = 1000;
const MAX_RESOLUTION_TEXT = 2000;
const MAX_FOLLOW_UP = 500;
const MAX_FOLLOW_UPS = 32;
const DATETIME_LOCAL = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/;

function fail(message: string): PlannedRequest {
  return { ok: false, message };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function nonBlank(value: unknown, maximum: number): value is string {
  return typeof value === 'string' && /\S/.test(value) && codePointLength(value) <= maximum;
}

/** `YYYY-MM-DDTHH:mm` as typed into a datetime-local control, read as UTC. */
export function utcFromLocalInput(value: unknown): string | null {
  if (typeof value !== 'string' || !DATETIME_LOCAL.test(value)) return null;
  const withSeconds = value.length === 16 ? `${value}:00` : value;
  const iso = `${withSeconds}Z`;
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return null;
  // Date.parse rolls impossible dates over (31 February); the round trip does not.
  return new Date(ms).toISOString().slice(0, 19) === withSeconds ? iso : null;
}

function followUpLines(value: unknown): string[] | null {
  if (value === undefined || value === null || value === '') return [];
  if (typeof value !== 'string') return null;
  const lines = value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  if (lines.length > MAX_FOLLOW_UPS) return null;
  return lines.every((line) => codePointLength(line) <= MAX_FOLLOW_UP) ? lines : null;
}

function planResolve(path: string, input: Record<string, unknown>, nowMs: number): PlannedRequest {
  if (!nonBlank(input.summary, MAX_RESOLUTION_TEXT)) {
    return fail('Enter a resolution summary of at most 2000 characters.');
  }
  if (!nonBlank(input.impact, MAX_RESOLUTION_TEXT)) {
    return fail('Describe the impact in at most 2000 characters.');
  }
  if (!isOneOf(input.rootCauseStatus, ROOT_CAUSE_STATUSES)) {
    return fail('Choose whether the root cause was determined.');
  }
  const determined = input.rootCauseStatus === 'determined';
  if (determined && !nonBlank(input.rootCause, MAX_RESOLUTION_TEXT)) {
    return fail('Enter the accepted root cause, or choose "Not determined".');
  }
  const restoredAt = utcFromLocalInput(input.restoredAt);
  if (restoredAt === null) return fail('Enter the time service was restored (UTC), as a valid date and time.');
  if (Date.parse(restoredAt) > nowMs) return fail('The restoration time cannot be in the future.');
  const followUps = followUpLines(input.followUps);
  if (followUps === null) {
    return fail('Use at most 32 follow-up actions, one per line, each at most 500 characters.');
  }
  return {
    ok: true,
    path,
    result: 'incident',
    body: {
      summary: input.summary,
      root_cause_status: input.rootCauseStatus,
      root_cause: determined ? input.rootCause : null,
      impact: input.impact,
      restored_at: restoredAt,
      follow_up_actions: followUps,
    },
  };
}

function planAssign(path: string, input: Record<string, unknown>): PlannedRequest {
  if (input.assigneeId === null) {
    return { ok: true, path, body: { assignee_id: null }, result: 'incident' };
  }
  const trimmed = typeof input.assigneeId === 'string' ? input.assigneeId.trim() : '';
  if (trimmed.length === 0 || codePointLength(trimmed) > MAX_ASSIGNEE) {
    return fail('Enter an assignee identity of at most 255 characters, or choose "Unassign".');
  }
  return { ok: true, path, body: { assignee_id: trimmed }, result: 'incident' };
}

/**
 * Turn an untrusted form payload into the one API request it may become. Nothing the browser
 * sends is trusted: the id must match the contract pattern, the action must be known, and the
 * body is rebuilt field by field with the contract's bounds.
 */
export function planIncidentRequest(input: unknown, nowMs: number): PlannedRequest {
  if (!isRecord(input)) return fail('The request was not well formed.');
  const { incidentId, action } = input;
  if (typeof incidentId !== 'string' || !isIncidentId(incidentId)) {
    return fail('The incident identifier was not valid.');
  }
  const base = `/api/v1/incidents/${incidentId}`;
  switch (action) {
    case 'acknowledge':
      return { ok: true, path: `${base}/acknowledge`, body: {}, result: 'incident' };
    case 'progress':
      if (input.toState !== 'investigating' && input.toState !== 'mitigated') {
        return fail('Choose investigating or mitigated.');
      }
      return {
        ok: true,
        path: `${base}/transition`,
        body: { to_state: input.toState },
        result: 'incident',
      };
    case 'assign':
      return planAssign(`${base}/assign`, input);
    case 'comment':
      if (!nonBlank(input.message, MAX_COMMENT)) {
        return fail('Enter a comment of at most 4000 characters.');
      }
      return { ok: true, path: `${base}/comment`, body: { message: input.message }, result: 'event' };
    case 'resolve':
      return planResolve(`${base}/resolve`, input, nowMs);
    case 'reopen':
      if (!nonBlank(input.reason, MAX_REASON)) {
        return fail('Enter the reason for reopening, at most 1000 characters.');
      }
      return { ok: true, path: `${base}/reopen`, body: { reason: input.reason }, result: 'incident' };
    default:
      return fail('The action is not recognised.');
  }
}
