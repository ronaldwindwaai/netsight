import {
  ACTION_ID,
  MAX_REASON,
  MIN_REASON,
  REQUEST_STATES,
  isActionText,
  parseActionDecisionRequest,
  parseActionFromFindingRequest,
  parseActionReasonRequest,
  parseKillSwitchRequest,
  type ActionList,
  type ActionRequest,
  type ActionStatus,
  type Risk,
  type RequestState,
} from './api-contracts-actions.ts';
import { FINDING_ID } from './api-contracts-unknown-devices.ts';
import type { FetchState } from './api-response.ts';
import { isOneOf } from './contract-guards.ts';
import type { Viewer } from './incident-actions.ts';
import type { PageHrefs } from './incident-view.ts';
import type { Presentation } from './inventory-view.ts';

/**
 * Pure presentation and planning rules for controlled remote actions. The wording is the honesty:
 * a request that was approved has not run; a dry run recorded what would happen and changed nothing;
 * nothing says "executed" or "applied" unless an executor did. Availability only explains; the API
 * re-checks permission, state, the requester rule, step-up and the kill switch on every call. The URL
 * and the form input are untrusted: they are validated here before they can reach an API path.
 */

export const PAGE_SIZE = 25;
const MAX_PAGE = 1000;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._-]{16,64}$/;
type Params = Record<string, string | string[] | undefined>;

export interface ActionsQuery {
  state: RequestState | null;
  page: number;
}

function first(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export function parseActionsQuery(params: Params): ActionsQuery {
  const rawPage = first(params.page);
  const page = rawPage !== undefined && /^[0-9]{1,4}$/.test(rawPage) ? Number(rawPage) : 1;
  const state = first(params.state);
  return {
    state: isOneOf(state, REQUEST_STATES) ? state : null,
    page: page >= 1 && page <= MAX_PAGE ? page : 1,
  };
}

export function actionsPath(query: ActionsQuery): string {
  const search = new URLSearchParams({ page: String(query.page), page_size: String(PAGE_SIZE) });
  if (query.state !== null) search.set('state', query.state);
  return `/api/v1/actions?${search.toString()}`;
}

export function actionPath(id: string): string | null {
  return ACTION_ID.test(id) ? `/api/v1/actions/${id}` : null;
}

export function actionHref(id: string): string {
  return `/actions/${id}`;
}

function pageLink(query: ActionsQuery, page: number): string {
  const search = new URLSearchParams();
  if (query.state !== null) search.set('state', query.state);
  if (page > 1) search.set('page', String(page));
  const rest = search.toString();
  return rest === '' ? '/actions' : `/actions?${rest}`;
}

export function pageHrefs(query: ActionsQuery, total: number, pageSize: number): PageHrefs {
  const last = Math.max(1, Math.ceil(total / pageSize));
  return {
    previous: query.page > 1 ? pageLink(query, query.page - 1) : null,
    next: query.page < last ? pageLink(query, query.page + 1) : null,
  };
}

export function filterHref(state: RequestState | null): string {
  return state === null ? '/actions' : `/actions?state=${state}`;
}

export function shortId(id: string): string {
  return id.slice(0, 15);
}

// --- presentation ----------------------------------------------------------------------------------------------

const STATES: Record<RequestState, Presentation> = {
  proposed: { label: 'Proposed', icon: 'bi-lightbulb', theme: 'secondary', explanation: 'Proposed and being checked against policy. Nothing has been approved or run.' },
  'pending-approval': { label: 'Awaiting approval', icon: 'bi-hourglass-split', theme: 'warning', explanation: 'Waiting for a different person to approve it. Nothing has been approved or run.' },
  approved: { label: 'Approved, not run', icon: 'bi-check2', theme: 'info', explanation: 'Every required approval is in. It has not been run, and it expires if it is not run in time.' },
  rejected: { label: 'Rejected', icon: 'bi-x-circle', theme: 'secondary', explanation: 'An approver rejected it. It will not run.' },
  expired: { label: 'Expired', icon: 'bi-clock-history', theme: 'secondary', explanation: 'It was not approved or not run in time. It will not run; propose it again if it is still needed.' },
  cancelled: { label: 'Cancelled', icon: 'bi-slash-circle', theme: 'secondary', explanation: 'It was withdrawn before it ran.' },
  executing: { label: 'Running', icon: 'bi-play-circle', theme: 'primary', explanation: 'An executor is running it now.' },
  succeeded: { label: 'Completed', icon: 'bi-check-circle', theme: 'success', explanation: 'The run finished and was verified. For a dry run this means what would happen was recorded, not that anything changed.' },
  failed: { label: 'Failed', icon: 'bi-exclamation-octagon', theme: 'danger', explanation: 'The run did not complete or could not be verified. Check the result before repeating it.' },
  'rolled-back': { label: 'Rolled back', icon: 'bi-arrow-counterclockwise', theme: 'warning', explanation: 'Verification failed and the change was reversed.' },
};

const DRY_RUN_RECORDED: Presentation = {
  label: 'Dry run recorded',
  icon: 'bi-journal-check',
  theme: 'info',
  explanation:
    'A dry run recorded what would happen. Nothing was changed on any device or network system and nothing was contacted.',
};

/** The execution mode matters: a finished dry run must never read as a completed change. */
export function statePresentation(state: RequestState, mode?: 'dry-run' | 'live'): Presentation {
  return state === 'succeeded' && mode === 'dry-run' ? DRY_RUN_RECORDED : STATES[state];
}

const RISKS: Record<Risk, Presentation> = {
  A: { label: 'Risk A', icon: 'bi-circle', theme: 'secondary', explanation: 'Read-only. Nothing is changed.' },
  B: { label: 'Risk B', icon: 'bi-circle-half', theme: 'info', explanation: 'Low risk and reversible. One person approves it.' },
  C: { label: 'Risk C', icon: 'bi-exclamation-triangle', theme: 'warning', explanation: 'High risk. One approver who is not the requester, with a recent multi-factor sign-in.' },
  D: { label: 'Risk D', icon: 'bi-exclamation-octagon', theme: 'danger', explanation: 'Critical. Two different approvers, neither the requester, each with a recent multi-factor sign-in.' },
};

export function riskPresentation(risk: Risk): Presentation {
  return RISKS[risk];
}

export interface ExecutionSummary {
  headline: string;
  detail: string;
  tone: 'info' | 'success' | 'warning' | 'danger' | 'secondary';
}

export function executionSummary(request: ActionRequest): ExecutionSummary {
  const run = request.execution;
  if (run === null) {
    return { headline: 'Not run', detail: 'No executor has been asked to do anything for this request.', tone: 'secondary' };
  }
  if (request.state === 'executing') {
    return { headline: 'Running', detail: 'An executor is running this request now.', tone: 'info' };
  }
  if (request.state === 'rolled-back') {
    return { headline: 'Rolled back', detail: 'The change was made, failed verification and was reversed.', tone: 'warning' };
  }
  if (request.state === 'failed') {
    const maybe = run.effect === 'unknown' ? ' It may have changed something before it failed; check the target before repeating it.' : ' Nothing was changed.';
    return { headline: 'Run failed', detail: `The run did not complete.${maybe}`, tone: 'danger' };
  }
  if (run.mode === 'dry-run') {
    return {
      headline: 'Dry run completed',
      detail: 'This recorded what would happen. Nothing was changed on any device or network system; nothing was contacted.',
      tone: 'info',
    };
  }
  return { headline: 'Run and verified', detail: 'The change was applied and verified.', tone: 'success' };
}

// --- list surface ------------------------------------------------------------------------------------------------

export type ListSurface =
  | 'permission'
  | 'unauthenticated'
  | 'error'
  | 'not-connected'
  | 'empty'
  | 'filtered-empty'
  | 'data';

export function listSurface(state: FetchState<ActionList>, query: ActionsQuery): ListSurface {
  if (state.kind === 'forbidden') return 'permission';
  if (state.kind === 'unauthenticated') return 'unauthenticated';
  if (state.kind !== 'ok') return 'error';
  if (state.data.state === 'not-connected') return 'not-connected';
  if (state.data.total === 0) return query.state !== null ? 'filtered-empty' : 'empty';
  return 'data';
}

// --- who can decide ----------------------------------------------------------------------------------------------------

export type DecisionVerb = 'approve' | 'reject' | 'cancel' | 'execute';

export interface DecisionAvailability {
  verb: DecisionVerb;
  label: string;
  enabled: boolean;
  /** Why the control is disabled; null when enabled. Plain text. */
  reason: string | null;
  needsStepUp: boolean;
}

const ROLE_REASON = 'Your role does not permit this action.';
const SIGN_IN_REASON = 'Sign in to act on action requests.';
const SELF_EXECUTE_REASON = 'The person who requested an action cannot execute it. A different person must run it.';
const KILL_REASON = 'The kill switch is engaged: no action can be approved or run until it is released.';

function holds(viewer: Viewer | null, permission: string): boolean {
  return viewer !== null && viewer.permissions.includes(permission);
}

export function decisionAvailability(
  request: ActionRequest,
  viewer: Viewer | null,
  status: ActionStatus | null,
): DecisionAvailability[] {
  const killed = status?.kill_switch.engaged === true;
  const dryRun = status === null || status.dry_run_only;
  const pending = request.state === 'pending-approval' || request.state === 'proposed';
  const isRequester = viewer !== null && viewer.identityId === request.requester.id;
  const alreadyApproved = viewer !== null && request.approvals.some((a) => a.approver_id === viewer.identityId);

  function gate(permitted: boolean, stateReason: string | null, extra: string | null = null): string | null {
    if (viewer === null) return SIGN_IN_REASON;
    if (!permitted) return ROLE_REASON;
    return stateReason ?? extra;
  }

  const approveReason = gate(
    holds(viewer, 'actions:approve'),
    request.state === 'pending-approval' ? null : 'Only a request that is awaiting approval can be approved.',
    isRequester
      ? 'You made this request; a different person must approve it.'
      : alreadyApproved
        ? 'You already approved this request; a different person must give the next approval.'
        : killed
          ? KILL_REASON
          : null,
  );
  const rejectReason = gate(holds(viewer, 'actions:approve'), pending ? null : 'Only a request that is awaiting approval can be rejected.');
  const mayCancel = holds(viewer, 'actions:approve') || (isRequester && holds(viewer, 'actions:propose'));
  const cancelReason = gate(
    mayCancel,
    pending || request.state === 'approved' ? null : 'Only an open request can be cancelled.',
  );
  const executeReason = gate(
    holds(viewer, 'actions:execute'),
    request.state === 'approved' ? null : 'Only an approved request can be run.',
    isRequester && status?.policy.self_execute_allowed !== true
      ? SELF_EXECUTE_REASON
      : killed
        ? KILL_REASON
        : null,
  );
  return [
    { verb: 'approve', label: 'Approve', enabled: approveReason === null, reason: approveReason, needsStepUp: true },
    { verb: 'reject', label: 'Reject', enabled: rejectReason === null, reason: rejectReason, needsStepUp: false },
    { verb: 'cancel', label: 'Cancel request', enabled: cancelReason === null, reason: cancelReason, needsStepUp: false },
    {
      verb: 'execute',
      label: dryRun ? 'Record a dry run' : 'Run',
      enabled: executeReason === null,
      reason: executeReason,
      needsStepUp: true,
    },
  ];
}

export interface DecisionOutcome {
  tone: 'success' | 'info' | 'warning' | 'danger';
  text: string;
}

/** What to tell the person after the API accepted a decision: the state it returned, in words. */
export function describeDecisionOutcome(
  verb: DecisionVerb,
  state: RequestState | string | undefined,
  dryRun: boolean,
): DecisionOutcome {
  if (verb === 'approve') {
    return state === 'approved'
      ? { tone: 'success', text: 'Approval recorded. Every required approval is in; the request has not been run.' }
      : { tone: 'success', text: 'Approval recorded. Another approver is still needed.' };
  }
  if (verb === 'reject') return { tone: 'success', text: 'Request rejected.' };
  if (verb === 'cancel') return { tone: 'success', text: 'Request cancelled.' };
  if (state === 'failed') {
    return { tone: 'danger', text: 'The run failed. See the result below before repeating it.' };
  }
  if (state === 'rolled-back') {
    return { tone: 'warning', text: 'The change failed verification and was rolled back. See the result below.' };
  }
  if (state === 'succeeded') {
    return dryRun
      ? { tone: 'info', text: 'Dry run recorded. Nothing was changed on any device or network system.' }
      : { tone: 'success', text: 'The run completed and was verified.' };
  }
  return { tone: 'info', text: 'The run was accepted. Refresh to see its result.' };
}

// --- the server action planners ----------------------------------------------------------------------------------------

export type DecisionPlan =
  | { ok: true; path: string; body: Record<string, unknown>; idempotencyKey: string | null }
  | { ok: false; message: string };

const VERBS: readonly DecisionVerb[] = ['approve', 'reject', 'cancel', 'execute'];
const NOT_SENT = 'The request is not valid, so it was not sent.';

function record(input: unknown): Record<string, unknown> | null {
  return typeof input === 'object' && input !== null && !Array.isArray(input) ? (input as Record<string, unknown>) : null;
}

/** Rebuild a decision field by field with the contract bounds; the verb selects one of four fixed paths. */
export function planDecision(input: unknown): DecisionPlan {
  const r = record(input);
  if (r === null || !isOneOf(r.verb, VERBS) || typeof r.actionId !== 'string' || !ACTION_ID.test(r.actionId)) {
    return { ok: false, message: NOT_SENT };
  }
  const path = `/api/v1/actions/${r.actionId}/${r.verb}`;
  const base = { expected_digest: r.digest, expected_version: r.version };
  if (r.verb === 'reject' || r.verb === 'cancel') {
    const reason = typeof r.reason === 'string' ? r.reason.trim() : r.reason;
    const parsed = parseActionReasonRequest({ ...base, reason });
    if (parsed === null) return { ok: false, message: reasonMessage() };
    return { ok: true, path, body: { ...parsed }, idempotencyKey: null };
  }
  const parsed = parseActionDecisionRequest(base);
  if (parsed === null) return { ok: false, message: NOT_SENT };
  if (r.verb === 'execute') {
    if (typeof r.key !== 'string' || !IDEMPOTENCY_KEY.test(r.key)) return { ok: false, message: NOT_SENT };
    return { ok: true, path, body: { ...parsed }, idempotencyKey: r.key };
  }
  return { ok: true, path, body: { ...parsed }, idempotencyKey: null };
}

function reasonMessage(): string {
  return `Give a reason of ${MIN_REASON} to ${MAX_REASON} characters, without control characters.`;
}

export type FindingProposalPlan =
  | { ok: true; body: Record<string, unknown>; idempotencyKey: string }
  | { ok: false; message: string };

export function planFindingProposal(input: unknown): FindingProposalPlan {
  const r = record(input);
  if (r === null || typeof r.key !== 'string' || !IDEMPOTENCY_KEY.test(r.key)) return { ok: false, message: NOT_SENT };
  if (typeof r.findingId !== 'string' || !FINDING_ID.test(r.findingId)) return { ok: false, message: NOT_SENT };
  const reason = typeof r.reason === 'string' ? r.reason.trim() : r.reason;
  const parsed = parseActionFromFindingRequest({
    finding_id: r.findingId,
    expected_evidence_version: r.evidenceVersion,
    reason,
  });
  if (parsed === null) return { ok: false, message: isActionText(reason, MIN_REASON, MAX_REASON) ? NOT_SENT : reasonMessage() };
  return { ok: true, body: { ...parsed }, idempotencyKey: r.key };
}

export type KillSwitchPlan = { ok: true; body: Record<string, unknown> } | { ok: false; message: string };

export function planKillSwitch(input: unknown): KillSwitchPlan {
  const r = record(input);
  const reason = r !== null && typeof r.reason === 'string' ? r.reason.trim() : r?.reason;
  const parsed = r === null ? null : parseKillSwitchRequest({ engaged: r.engaged, reason });
  if (parsed === null) return { ok: false, message: reasonMessage() };
  return { ok: true, body: { ...parsed } };
}
