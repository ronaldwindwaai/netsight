import { FINDING_ID } from './api-contracts-unknown-devices.ts';
import { isIntegerInRange, isOneOf, isText, parseArray } from './contract-guards.ts';
import { exactRecord, isBoolean, isNullableTimestamp, isTimestamp, type Raw } from './contract-helpers.ts';

/**
 * Controlled remote action contract, mirroring contracts/json-schema/actions.schema.json (shared
 * vectors: contracts/test-vectors/actions.vectors.json).
 *
 * Fail-closed: anything that does not satisfy the exact contract returns null and the caller renders
 * an explicit error state, never a guess. There is no field that can carry a command: parameters are
 * a bounded map of booleans, integers and short strings, and an unknown key anywhere is a refusal.
 * A dry-run execution that claims to have changed something is refused. The reason and the history
 * notes are untrusted text: bounded here and rendered as text only.
 */
export const ACTION_TYPES = ['endpoint.isolate', 'switch.port.disable', 'switch.port.enable'] as const;
export const RISKS = ['A', 'B', 'C', 'D'] as const;
export const REQUEST_STATES = [
  'proposed',
  'pending-approval',
  'approved',
  'rejected',
  'expired',
  'cancelled',
  'executing',
  'succeeded',
  'failed',
  'rolled-back',
] as const;
export const EVENT_TYPES = [
  'proposed',
  'policy-checked',
  'submitted',
  'approved',
  'rejected',
  'cancelled',
  'expired',
  'execution-started',
  'pre-check-failed',
  'executed',
  'verification-passed',
  'verification-failed',
  'rolled-back',
  'rollback-failed',
  'failed',
] as const;
const ACTOR_KINDS = ['human', 'service', 'ai'] as const;
const CHECK_STATES = ['pass', 'fail', 'unknown'] as const;
const VERIFICATION_STATES = ['passed', 'failed', 'not-applicable', 'unknown'] as const;
const ROLLBACK_STATES = ['completed', 'failed', 'not-needed'] as const;
const MODES = ['dry-run', 'live'] as const;
const EFFECTS = ['none', 'applied', 'unknown'] as const;
const ENGINE_STATES = ['ok', 'not-connected'] as const;
const EXECUTOR_STATES = ['ok', 'disabled', 'not-connected'] as const;
const KILL_SOURCES = ['none', 'runtime', 'environment'] as const;
const PARAM_KINDS = ['integer', 'boolean', 'choice'] as const;

export type ActionType = (typeof ACTION_TYPES)[number];
export type Risk = (typeof RISKS)[number];
export type RequestState = (typeof REQUEST_STATES)[number];
export type EventType = (typeof EVENT_TYPES)[number];
export type EngineState = (typeof ENGINE_STATES)[number];

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
export const ACTION_ID = new RegExp(`^action-${UUID}$`);
export const TARGET_ID = /^[a-z0-9][a-z0-9._:-]{0,127}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const HASH = /^[0-9a-f]{64}$/;
const CODE = /^[a-z][a-z0-9-]{1,63}$/;
const PARAM_NAME = /^[a-z][a-z0-9_]{0,31}$/;
const PERMISSION = /^actions:[a-z-]+$/;
export const MIN_REASON = 3;
export const MAX_REASON = 500;
const MAX_COUNT = 1_000_000;
const MAX_HISTORY = 100;
export const MAX_PAGE_SIZE = 50;
// Control, format (bidi, zero-width), surrogate, private-use, unassigned and line/paragraph separators.
const REFUSED_CHARACTERS = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}]/u;

export interface ActionActor {
  id: string;
  kind: 'human' | 'service' | 'ai';
}
export interface ActionSource {
  kind: 'unknown-device-finding';
  id: string;
  evidence_version: number;
}
export interface ActionApproval {
  approver_id: string;
  approved_at: string;
}
export interface ActionCheck {
  name: string;
  state: 'pass' | 'fail' | 'unknown';
  detail: string;
}
export interface ActionVerification {
  state: 'passed' | 'failed' | 'not-applicable' | 'unknown';
  detail: string;
}
export interface ActionRollback {
  state: 'completed' | 'failed' | 'not-needed';
  detail: string;
}
export interface ActionExecution {
  executor: string;
  mode: 'dry-run' | 'live';
  effect: 'none' | 'applied' | 'unknown';
  started_at: string;
  finished_at: string | null;
  planned_steps: string[];
  verification: ActionVerification;
  rollback: ActionRollback | null;
  failure: string | null;
}
export type ParamValue = string | number | boolean;
export interface ActionRequest {
  id: string;
  action_type: ActionType;
  target_id: string;
  params: Record<string, ParamValue>;
  risk: Risk;
  state: RequestState;
  requester: ActionActor;
  reason: string;
  source: ActionSource | null;
  approvals_required: number;
  approvals: ActionApproval[];
  created_at: string;
  approve_by: string;
  execute_by: string | null;
  version: number;
  digest: string;
  policy_checks: ActionCheck[];
  pre_checks: ActionCheck[];
  execution: ActionExecution | null;
}
export interface ActionEvent {
  seq: number;
  at: string;
  type: EventType;
  actor_id: string | null;
  from_state: RequestState | null;
  to_state: RequestState;
  code: string;
  note: string | null;
  prev_hash: string;
  hash: string;
}
export interface ActionParamSpec {
  name: string;
  kind: 'integer' | 'boolean' | 'choice';
  required: boolean;
  minimum: number | null;
  maximum: number | null;
  choices: string[] | null;
}
export interface ActionDefinition {
  action_type: ActionType;
  title: string;
  risk: Risk;
  target_kind: string;
  params: ActionParamSpec[];
  approvals_required: number;
  step_up_required: true;
  approve_within_seconds: number;
  execute_within_seconds: number;
  timeout_seconds: number;
  propose_permission: string;
  rollback_guidance: string;
}
export interface ExecutorStatus {
  id: string;
  mode: 'dry-run' | 'live';
  state: 'ok' | 'disabled' | 'not-connected';
}
export interface KillSwitchStatus {
  engaged: boolean;
  source: 'none' | 'runtime' | 'environment';
  since: string | null;
}
export interface ActionStatus {
  state: EngineState;
  generated_at: string;
  dry_run_only: boolean;
  kill_switch: KillSwitchStatus;
  store: { kind: 'memory'; durable: false };
  policy: { self_execute_allowed: boolean };
  executors: ExecutorStatus[];
  definitions: ActionDefinition[];
}
export interface ActionList {
  state: EngineState;
  generated_at: string;
  items: ActionRequest[];
  total: number;
  page: number;
  page_size: number;
}
export interface ActionDetail {
  generated_at: string;
  request: ActionRequest;
  history: ActionEvent[];
  chain_intact: boolean;
}
export interface ActionCreateRequest {
  action_type: ActionType;
  target_id: string;
  params: Record<string, ParamValue>;
  reason: string;
}
export interface ActionFromFindingRequest {
  finding_id: string;
  expected_evidence_version: number;
  reason: string;
}
export interface ActionDecisionRequest {
  expected_digest: string;
  expected_version: number;
}
export interface ActionReasonRequest extends ActionDecisionRequest {
  reason: string;
}
export interface KillSwitchRequest {
  engaged: boolean;
  reason: string;
}

// --- helpers ---------------------------------------------------------------------------------------------

const isCode = (value: unknown): value is string => isText(value, 2, 64) && CODE.test(value);
const isVersion = (value: unknown): value is number => isIntegerInRange(value, 1, MAX_COUNT);
const isActionId = (value: unknown): value is string => typeof value === 'string' && ACTION_ID.test(value);
const isTarget = (value: unknown): value is string => typeof value === 'string' && TARGET_ID.test(value);
const isDigest = (value: unknown): value is string => typeof value === 'string' && DIGEST.test(value);
const isHash = (value: unknown): value is string => typeof value === 'string' && HASH.test(value);
const isIdentity = (value: unknown): value is string => isText(value, 1, 255);

/** Free text is data: bounded, not blank, and free of control, format and separator characters. */
export function isActionText(value: unknown, minimum: number, maximum: number): value is string {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  return isText(trimmed, minimum, maximum) && /\S/.test(trimmed) && !REFUSED_CHARACTERS.test(value);
}

function isParamValue(value: unknown): value is ParamValue {
  if (typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isInteger(value);
  return isText(value, 1, 64);
}

function parseParams(value: unknown): Record<string, ParamValue> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const entries = Object.entries(value as Raw);
  if (entries.length > 8) return null;
  const out: Record<string, ParamValue> = {};
  for (const [name, item] of entries) {
    if (!PARAM_NAME.test(name) || !isParamValue(item)) return null;
    out[name] = item;
  }
  return out;
}

// --- parts -----------------------------------------------------------------------------------------------

function parseActor(value: unknown): ActionActor | null {
  const r = exactRecord(value, ['id', 'kind']);
  if (r === null || !isIdentity(r.id) || !isOneOf(r.kind, ACTOR_KINDS)) return null;
  return { id: r.id, kind: r.kind };
}

function parseSource(value: unknown): ActionSource | null {
  const r = exactRecord(value, ['kind', 'id', 'evidence_version']);
  if (
    r === null ||
    r.kind !== 'unknown-device-finding' ||
    typeof r.id !== 'string' ||
    !FINDING_ID.test(r.id) ||
    !isVersion(r.evidence_version)
  ) {
    return null;
  }
  return { kind: r.kind, id: r.id, evidence_version: r.evidence_version };
}

function parseApproval(value: unknown): ActionApproval | null {
  const r = exactRecord(value, ['approver_id', 'approved_at']);
  if (r === null || !isIdentity(r.approver_id) || !isTimestamp(r.approved_at)) return null;
  return { approver_id: r.approver_id, approved_at: r.approved_at };
}

export function parseActionCheck(value: unknown): ActionCheck | null {
  const r = exactRecord(value, ['name', 'state', 'detail']);
  if (r === null || !isCode(r.name) || !isOneOf(r.state, CHECK_STATES) || !isCode(r.detail)) return null;
  return { name: r.name, state: r.state, detail: r.detail };
}

function parseVerification(value: unknown): ActionVerification | null {
  const r = exactRecord(value, ['state', 'detail']);
  if (r === null || !isOneOf(r.state, VERIFICATION_STATES) || !isCode(r.detail)) return null;
  return { state: r.state, detail: r.detail };
}

function parseRollback(value: unknown): ActionRollback | null {
  const r = exactRecord(value, ['state', 'detail']);
  if (r === null || !isOneOf(r.state, ROLLBACK_STATES) || !isCode(r.detail)) return null;
  return { state: r.state, detail: r.detail };
}

export function parseActionExecution(value: unknown): ActionExecution | null {
  const r = exactRecord(value, [
    'executor',
    'mode',
    'effect',
    'started_at',
    'finished_at',
    'planned_steps',
    'verification',
    'rollback',
    'failure',
  ]);
  if (
    r === null ||
    !isCode(r.executor) ||
    !isOneOf(r.mode, MODES) ||
    !isOneOf(r.effect, EFFECTS) ||
    !isTimestamp(r.started_at) ||
    !isNullableTimestamp(r.finished_at) ||
    !(r.failure === null || isCode(r.failure))
  ) {
    return null;
  }
  // A dry run never changes anything, whatever the record says.
  if (r.mode === 'dry-run' && r.effect !== 'none') return null;
  if (r.finished_at !== null && Date.parse(r.finished_at) < Date.parse(r.started_at)) return null;
  const steps = parseArray(r.planned_steps, 0, 10, (s) => (isText(s, 1, 200) ? s : null));
  const verification = parseVerification(r.verification);
  const rollback = r.rollback === null ? null : parseRollback(r.rollback);
  if (steps === null || verification === null || (r.rollback !== null && rollback === null)) return null;
  return {
    executor: r.executor,
    mode: r.mode,
    effect: r.effect,
    started_at: r.started_at,
    finished_at: r.finished_at,
    planned_steps: steps,
    verification,
    rollback,
    failure: r.failure,
  };
}

// --- request ---------------------------------------------------------------------------------------------

const PAST_APPROVAL: readonly RequestState[] = ['approved', 'executing', 'succeeded', 'failed', 'rolled-back'];
const BEFORE_EXECUTION: readonly RequestState[] = ['proposed', 'pending-approval', 'approved'];

function approvalsAreSound(
  approvals: ActionApproval[],
  required: number,
  requester: string,
  state: RequestState,
): boolean {
  const ids = approvals.map((a) => a.approver_id);
  if (new Set(ids).size !== ids.length || ids.includes(requester) || ids.length > required) return false;
  return !PAST_APPROVAL.includes(state) || ids.length >= required;
}

export function parseActionRequest(value: unknown): ActionRequest | null {
  const r = exactRecord(value, [
    'id',
    'action_type',
    'target_id',
    'params',
    'risk',
    'state',
    'requester',
    'reason',
    'source',
    'approvals_required',
    'approvals',
    'created_at',
    'approve_by',
    'execute_by',
    'version',
    'digest',
    'policy_checks',
    'pre_checks',
    'execution',
  ]);
  if (
    r === null ||
    !isActionId(r.id) ||
    !isOneOf(r.action_type, ACTION_TYPES) ||
    !isTarget(r.target_id) ||
    !isOneOf(r.risk, RISKS) ||
    !isOneOf(r.state, REQUEST_STATES) ||
    !isActionText(r.reason, MIN_REASON, MAX_REASON) ||
    !isIntegerInRange(r.approvals_required, 1, 2) ||
    !isTimestamp(r.created_at) ||
    !isTimestamp(r.approve_by) ||
    !isNullableTimestamp(r.execute_by) ||
    !isVersion(r.version) ||
    !isDigest(r.digest)
  ) {
    return null;
  }
  const params = parseParams(r.params);
  const requester = parseActor(r.requester);
  const source = r.source === null ? null : parseSource(r.source);
  const approvals = parseArray(r.approvals, 0, 2, parseApproval);
  const policy = parseArray(r.policy_checks, 0, 16, parseActionCheck);
  const pre = parseArray(r.pre_checks, 0, 16, parseActionCheck);
  const execution = r.execution === null ? null : parseActionExecution(r.execution);
  if (
    params === null ||
    requester === null ||
    approvals === null ||
    policy === null ||
    pre === null ||
    (r.source !== null && source === null) ||
    (r.execution !== null && execution === null)
  ) {
    return null;
  }
  if (!approvalsAreSound(approvals, r.approvals_required, requester.id, r.state)) return null;
  if (r.state === 'approved' && r.execute_by === null) return null;
  if ((r.state === 'succeeded' || r.state === 'rolled-back') && execution === null) return null;
  if (BEFORE_EXECUTION.includes(r.state) && execution !== null) return null;
  return {
    id: r.id,
    action_type: r.action_type,
    target_id: r.target_id,
    params,
    risk: r.risk,
    state: r.state,
    requester,
    reason: r.reason,
    source,
    approvals_required: r.approvals_required,
    approvals,
    created_at: r.created_at,
    approve_by: r.approve_by,
    execute_by: r.execute_by,
    version: r.version,
    digest: r.digest,
    policy_checks: policy,
    pre_checks: pre,
    execution,
  };
}

export function parseActionEvent(value: unknown): ActionEvent | null {
  const r = exactRecord(value, [
    'seq',
    'at',
    'type',
    'actor_id',
    'from_state',
    'to_state',
    'code',
    'note',
    'prev_hash',
    'hash',
  ]);
  if (
    r === null ||
    !isIntegerInRange(r.seq, 1, MAX_COUNT) ||
    !isTimestamp(r.at) ||
    !isOneOf(r.type, EVENT_TYPES) ||
    !(r.actor_id === null || isIdentity(r.actor_id)) ||
    !(r.from_state === null || isOneOf(r.from_state, REQUEST_STATES)) ||
    !isOneOf(r.to_state, REQUEST_STATES) ||
    !isCode(r.code) ||
    !(r.note === null || isActionText(r.note, MIN_REASON, MAX_REASON)) ||
    !isHash(r.prev_hash) ||
    !isHash(r.hash)
  ) {
    return null;
  }
  return r as unknown as ActionEvent;
}

// --- definitions, status, list, detail ---------------------------------------------------------------------

function parseParamSpec(value: unknown): ActionParamSpec | null {
  const r = exactRecord(value, ['name', 'kind', 'required', 'minimum', 'maximum', 'choices']);
  if (
    r === null ||
    typeof r.name !== 'string' ||
    !PARAM_NAME.test(r.name) ||
    !isOneOf(r.kind, PARAM_KINDS) ||
    !isBoolean(r.required)
  ) {
    return null;
  }
  const bounded = (v: unknown): v is number | null => v === null || (typeof v === 'number' && Number.isInteger(v));
  if (!bounded(r.minimum) || !bounded(r.maximum)) return null;
  const choices =
    r.choices === null ? null : parseArray(r.choices, 0, 16, (c) => (isText(c, 1, 64) ? c : null));
  if (r.choices !== null && choices === null) return null;
  if (r.kind === 'integer') {
    if (r.minimum === null || r.maximum === null || r.minimum > r.maximum || choices !== null) return null;
  } else if (r.kind === 'choice') {
    if (choices === null || choices.length === 0 || r.minimum !== null || r.maximum !== null) return null;
  } else if (r.minimum !== null || r.maximum !== null || choices !== null) {
    return null;
  }
  return { name: r.name, kind: r.kind, required: r.required, minimum: r.minimum, maximum: r.maximum, choices };
}

export function parseActionDefinition(value: unknown): ActionDefinition | null {
  const r = exactRecord(value, [
    'action_type',
    'title',
    'risk',
    'target_kind',
    'params',
    'approvals_required',
    'step_up_required',
    'approve_within_seconds',
    'execute_within_seconds',
    'timeout_seconds',
    'propose_permission',
    'rollback_guidance',
  ]);
  if (
    r === null ||
    !isOneOf(r.action_type, ACTION_TYPES) ||
    !isText(r.title, 1, 80) ||
    !isOneOf(r.risk, RISKS) ||
    !isCode(r.target_kind) ||
    !isIntegerInRange(r.approvals_required, 1, 2) ||
    r.step_up_required !== true ||
    !isIntegerInRange(r.approve_within_seconds, 60, 604_800) ||
    !isIntegerInRange(r.execute_within_seconds, 60, 86_400) ||
    !isIntegerInRange(r.timeout_seconds, 1, 600) ||
    typeof r.propose_permission !== 'string' ||
    !PERMISSION.test(r.propose_permission) ||
    !isText(r.rollback_guidance, 1, 300)
  ) {
    return null;
  }
  const params = parseArray(r.params, 0, 8, parseParamSpec);
  if (params === null) return null;
  return {
    action_type: r.action_type,
    title: r.title,
    risk: r.risk,
    target_kind: r.target_kind,
    params,
    approvals_required: r.approvals_required,
    step_up_required: true,
    approve_within_seconds: r.approve_within_seconds,
    execute_within_seconds: r.execute_within_seconds,
    timeout_seconds: r.timeout_seconds,
    propose_permission: r.propose_permission,
    rollback_guidance: r.rollback_guidance,
  };
}

function parseExecutor(value: unknown): ExecutorStatus | null {
  const r = exactRecord(value, ['id', 'mode', 'state']);
  if (r === null || !isCode(r.id) || !isOneOf(r.mode, MODES) || !isOneOf(r.state, EXECUTOR_STATES)) return null;
  if (r.mode === 'dry-run' && r.state !== 'ok') return null; // the dry-run executor needs nothing
  return { id: r.id, mode: r.mode, state: r.state };
}

function parseKillSwitch(value: unknown): KillSwitchStatus | null {
  const r = exactRecord(value, ['engaged', 'source', 'since']);
  if (r === null || !isBoolean(r.engaged) || !isOneOf(r.source, KILL_SOURCES) || !isNullableTimestamp(r.since)) {
    return null;
  }
  if (r.engaged === (r.source === 'none')) return null;
  return { engaged: r.engaged, source: r.source, since: r.since };
}

export function parseActionStatus(value: unknown): ActionStatus | null {
  const r = exactRecord(value, [
    'state',
    'generated_at',
    'dry_run_only',
    'kill_switch',
    'store',
    'policy',
    'executors',
    'definitions',
  ]);
  if (r === null || !isOneOf(r.state, ENGINE_STATES) || !isTimestamp(r.generated_at) || !isBoolean(r.dry_run_only)) {
    return null;
  }
  const store = exactRecord(r.store, ['kind', 'durable']);
  if (store === null || store.kind !== 'memory' || store.durable !== false) return null;
  const policy = exactRecord(r.policy, ['self_execute_allowed']);
  if (policy === null || !isBoolean(policy.self_execute_allowed)) return null;
  const kill = parseKillSwitch(r.kill_switch);
  const executors = parseArray(r.executors, 0, 8, parseExecutor);
  const definitions = parseArray(r.definitions, 0, 16, parseActionDefinition);
  if (kill === null || executors === null || definitions === null) return null;
  const liveReady = executors.some((e) => e.mode === 'live' && e.state === 'ok');
  if (r.dry_run_only === liveReady) return null; // dry_run_only is exactly "no live executor is ready"
  if (r.state === 'not-connected' && (executors.length > 0 || definitions.length > 0)) return null;
  return {
    state: r.state,
    generated_at: r.generated_at,
    dry_run_only: r.dry_run_only,
    kill_switch: kill,
    store: { kind: 'memory', durable: false },
    policy: { self_execute_allowed: policy.self_execute_allowed },
    executors,
    definitions,
  };
}

export function parseActionList(value: unknown): ActionList | null {
  const r = exactRecord(value, ['state', 'generated_at', 'items', 'total', 'page', 'page_size']);
  if (
    r === null ||
    !isOneOf(r.state, ENGINE_STATES) ||
    !isTimestamp(r.generated_at) ||
    !isIntegerInRange(r.total, 0, MAX_COUNT) ||
    !isIntegerInRange(r.page, 1, 1000) ||
    !isIntegerInRange(r.page_size, 1, MAX_PAGE_SIZE)
  ) {
    return null;
  }
  const items = parseArray(r.items, 0, MAX_PAGE_SIZE, parseActionRequest);
  if (items === null) return null;
  if (r.state === 'not-connected' && (items.length > 0 || r.total > 0)) return null;
  return {
    state: r.state,
    generated_at: r.generated_at,
    items,
    total: r.total,
    page: r.page,
    page_size: r.page_size,
  };
}

export function parseActionDetail(value: unknown): ActionDetail | null {
  const r = exactRecord(value, ['generated_at', 'request', 'history', 'chain_intact']);
  if (r === null || !isTimestamp(r.generated_at) || !isBoolean(r.chain_intact)) return null;
  const request = parseActionRequest(r.request);
  const history = parseArray(r.history, 1, MAX_HISTORY, parseActionEvent);
  if (request === null || history === null) return null;
  return { generated_at: r.generated_at, request, history, chain_intact: r.chain_intact };
}

// --- requests ---------------------------------------------------------------------------------------------

export function parseActionCreateRequest(value: unknown): ActionCreateRequest | null {
  const r = exactRecord(value, ['action_type', 'target_id', 'params', 'reason']);
  if (
    r === null ||
    !isOneOf(r.action_type, ACTION_TYPES) ||
    !isTarget(r.target_id) ||
    !isActionText(r.reason, MIN_REASON, MAX_REASON)
  ) {
    return null;
  }
  const params = parseParams(r.params);
  if (params === null) return null;
  return { action_type: r.action_type, target_id: r.target_id, params, reason: r.reason };
}

export function parseActionFromFindingRequest(value: unknown): ActionFromFindingRequest | null {
  const r = exactRecord(value, ['finding_id', 'expected_evidence_version', 'reason']);
  if (
    r === null ||
    typeof r.finding_id !== 'string' ||
    !FINDING_ID.test(r.finding_id) ||
    !isVersion(r.expected_evidence_version) ||
    !isActionText(r.reason, MIN_REASON, MAX_REASON)
  ) {
    return null;
  }
  return { finding_id: r.finding_id, expected_evidence_version: r.expected_evidence_version, reason: r.reason };
}

export function parseActionDecisionRequest(value: unknown): ActionDecisionRequest | null {
  const r = exactRecord(value, ['expected_digest', 'expected_version']);
  if (r === null || !isDigest(r.expected_digest) || !isVersion(r.expected_version)) return null;
  return { expected_digest: r.expected_digest, expected_version: r.expected_version };
}

export function parseActionReasonRequest(value: unknown): ActionReasonRequest | null {
  const r = exactRecord(value, ['expected_digest', 'expected_version', 'reason']);
  if (
    r === null ||
    !isDigest(r.expected_digest) ||
    !isVersion(r.expected_version) ||
    !isActionText(r.reason, MIN_REASON, MAX_REASON)
  ) {
    return null;
  }
  return { expected_digest: r.expected_digest, expected_version: r.expected_version, reason: r.reason };
}

export function parseKillSwitchRequest(value: unknown): KillSwitchRequest | null {
  const r = exactRecord(value, ['engaged', 'reason']);
  if (r === null || !isBoolean(r.engaged) || !isActionText(r.reason, MIN_REASON, MAX_REASON)) return null;
  return { engaged: r.engaged, reason: r.reason };
}
