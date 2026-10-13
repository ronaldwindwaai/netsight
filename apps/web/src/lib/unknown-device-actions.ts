/**
 * Unknown-device finding actions as the UI understands them: which are available to the viewer in
 * the finding's current state, and how a form submission becomes an API request.
 *
 * Both halves are advisory/defensive only. The API re-checks authorisation, state, CSRF/origin and
 * step-up on every request. There is no action here that executes, approves or creates an isolation:
 * a quarantine is a recommendation shown on the finding, and the action engine (Step 14) owns it.
 */
import { FINDING_ID, isEvidenceVersion, type FindingState } from './api-contracts-unknown-devices.ts';
import { codePointLength, isOneOf } from './contract-guards.ts';
import type { Viewer } from './incident-actions.ts';

export type FindingActionName = 'acknowledge' | 'investigate' | 'assign' | 'comment' | 'resolve';

export interface FindingActionAvailability {
  action: FindingActionName;
  label: string;
  enabled: boolean;
  /** Why the action is disabled; null when enabled. Plain text. */
  reason: string | null;
  /** Resolving (and dismissing) needs a recent multi-factor sign-in; the API refuses otherwise. */
  needsStepUp: boolean;
}

const PERMISSION: Record<FindingActionName, string> = {
  acknowledge: 'unknown-devices:acknowledge',
  investigate: 'unknown-devices:acknowledge',
  assign: 'unknown-devices:assign',
  comment: 'unknown-devices:comment',
  resolve: 'unknown-devices:resolve',
};
const LABEL: Record<FindingActionName, string> = {
  acknowledge: 'Acknowledge',
  investigate: 'Mark investigating',
  assign: 'Assign',
  comment: 'Comment',
  resolve: 'Resolve or dismiss',
};
const ROLE_REASON = 'Your role does not permit this action.';
const SIGN_IN_REASON = 'Sign in to act on findings.';
const FINISHED = ['resolved', 'false-positive'] as const;

/** Why the state forbids the action, or null when the state allows it. */
function stateReason(action: FindingActionName, state: FindingState): string | null {
  const finished = (FINISHED as readonly string[]).includes(state);
  if (action === 'acknowledge') return state === 'new' ? null : 'Only a new finding can be acknowledged.';
  if (action === 'investigate') {
    return state === 'acknowledged' ? null : 'A finding must be acknowledged before it is investigated.';
  }
  if (action === 'assign') return finished ? 'A finished finding cannot be reassigned.' : null;
  if (action === 'resolve') return finished ? 'This finding is already finished.' : null;
  return null; // a comment is allowed in every state
}

export function availableFindingActions(
  finding: { state: FindingState; assignee_id: string | null },
  viewer: Viewer | null,
): FindingActionAvailability[] {
  return (Object.keys(PERMISSION) as FindingActionName[]).map((action) => {
    const needsStepUp = action === 'resolve';
    const base = { action, label: LABEL[action], needsStepUp };
    if (viewer === null) return { ...base, enabled: false, reason: SIGN_IN_REASON };
    // Permission first: a role that cannot do this learns nothing about state-dependent rules.
    if (!viewer.permissions.includes(PERMISSION[action])) return { ...base, enabled: false, reason: ROLE_REASON };
    const reason = stateReason(action, finding.state);
    return { ...base, enabled: reason === null, reason };
  });
}

// --- request planning -----------------------------------------------------------------------------------

export type PlannedFindingRequest =
  | { ok: true; path: string; body: Record<string, unknown>; result: 'finding' | 'event' }
  | { ok: false; message: string };

const MAX_ASSIGNEE = 255;
const MAX_COMMENT = 4000;
const MAX_REASON = 1000;
const DECISIONS = ['acknowledge', 'investigate', 'assign', 'resolve'] as const;

function fail(message: string): PlannedFindingRequest {
  return { ok: false, message };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function nonBlank(value: unknown, maximum: number): value is string {
  return typeof value === 'string' && /\S/.test(value) && codePointLength(value) <= maximum;
}

/**
 * Turn an untrusted form payload into the one API request it may become. Nothing the browser sends
 * is trusted: the id must match the contract pattern, the action must be known, and the body is
 * rebuilt field by field with the contract's bounds.
 */
export function planFindingRequest(input: unknown): PlannedFindingRequest {
  if (!isRecord(input)) return fail('The request was not well formed.');
  const { findingId, action } = input;
  if (typeof findingId !== 'string' || !FINDING_ID.test(findingId)) {
    return fail('The finding identifier was not valid.');
  }
  const base = `/api/v1/unknown-devices/${findingId}`;
  if (action === 'comment') {
    if (!nonBlank(input.message, MAX_COMMENT)) return fail('Enter a comment of at most 4000 characters.');
    return { ok: true, path: `${base}/comment`, body: { message: input.message }, result: 'event' };
  }
  // Every other decision is made on the evidence the person was shown, and loses if it changed.
  const expected = input.expectedEvidenceVersion;
  if (isOneOf(action, DECISIONS) && !isEvidenceVersion(expected)) {
    return fail('The evidence version this decision rests on is missing. Reload the finding and try again.');
  }
  const version = { expected_evidence_version: expected };
  switch (action) {
    case 'acknowledge':
    case 'investigate':
      return { ok: true, path: `${base}/${action}`, body: version, result: 'finding' };
    case 'assign': {
      if (input.assigneeId === null) {
        return { ok: true, path: `${base}/assign`, body: { assignee_id: null, ...version }, result: 'finding' };
      }
      const assignee = typeof input.assigneeId === 'string' ? input.assigneeId.trim() : '';
      if (assignee.length === 0 || codePointLength(assignee) > MAX_ASSIGNEE) {
        return fail('Enter an assignee identity of at most 255 characters, or choose "Unassign".');
      }
      return { ok: true, path: `${base}/assign`, body: { assignee_id: assignee, ...version }, result: 'finding' };
    }
    case 'resolve':
      if (!isOneOf(input.outcome, ['resolved', 'false-positive'] as const)) {
        return fail('Choose resolved or false positive as the outcome.');
      }
      if (!nonBlank(input.reason, MAX_REASON)) {
        return fail('Enter the reason, at most 1000 characters.');
      }
      return {
        ok: true,
        path: `${base}/resolve`,
        body: { outcome: input.outcome, reason: input.reason, ...version },
        result: 'finding',
      };
    default:
      return fail('The action is not recognised.');
  }
}
