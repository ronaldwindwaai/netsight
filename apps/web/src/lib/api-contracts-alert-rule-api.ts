import { isRfc3339 } from './api-contracts.ts';
import {
  ALERT_RULE_STATUSES,
  MAINTENANCE_EVALUATIONS,
  parseAlertRule,
  parseAlertRuleDefinition,
  parseMaintenanceWindow,
  parseScope,
  type AlertRule,
  type AlertRuleDefinition,
  type AlertRuleStatus,
  type AlertScope,
  type MaintenanceEvaluation,
  type MaintenanceWindow,
} from './api-contracts-alert-rule.ts';
import {
  hasExactKeys,
  isIntegerInRange,
  isNullableText,
  isNonBlankText,
  isOneOf,
  isPlainRecord,
  isText,
  parseArray,
  textItem,
} from './contract-guards.ts';

/** not-connected: no store configured; unknown: the store failed; ok: stored rows. */
export const ALERTING_API_STATES = ['not-connected', 'ok', 'unknown'] as const;
export type AlertingApiState = (typeof ALERTING_API_STATES)[number];

/** Server-side caps; the API rejects anything beyond them with 422. */
export const MAX_RULE_PAGE_SIZE = 100;
export const MAX_RULE_LIST_OFFSET = 10_000;
export const MAX_EVALUATE_OBSERVATIONS = 200;
export const MAX_EVALUATE_WINDOWS = 20;
const MAX_RULE_VERSION = 1_000_000;
const VALUE_BOUND = 1_000_000_000_000_000;
const MAX_MAINTENANCE_MS = 30 * 24 * 60 * 60 * 1000;

export const EVALUATE_OUTCOMES = [
  'firing',
  'pending',
  'not-met',
  'excepted',
  'outside-schedule',
  'no-data',
  'out-of-scope',
  'stale',
  'future',
  'maintenance-disabled',
  'invalid-config',
  'rule-not-active',
] as const;
export const EVALUATE_PHASES = ['inactive', 'pending', 'firing'] as const;
export const EVALUATE_TRANSITIONS = ['fired', 'resolved'] as const;
export const EVALUATE_BLOCKERS = ['maintenance', 'cooldown'] as const;
export const OBSERVATION_ANOMALIES = ['above', 'below', 'normal'] as const;
export const SAMPLE_WINDOW_STATUSES = ['scheduled', 'cancelled'] as const;

export type EvaluateOutcome = (typeof EVALUATE_OUTCOMES)[number];
export type EvaluatePhase = (typeof EVALUATE_PHASES)[number];
export type EvaluateTransition = (typeof EVALUATE_TRANSITIONS)[number];
export type EvaluateBlocker = (typeof EVALUATE_BLOCKERS)[number];
export type ObservationAnomaly = (typeof OBSERVATION_ANOMALIES)[number];
export type SampleWindowStatus = (typeof SAMPLE_WINDOW_STATUSES)[number];

export interface AlertRuleListResponse {
  state: AlertingApiState;
  rules: AlertRule[];
  limit: number;
  offset: number;
  next_offset: number | null;
}

export interface AlertRuleDetailResponse {
  state: AlertingApiState;
  rule: AlertRule | null;
}

export interface MaintenanceWindowListResponse {
  state: AlertingApiState;
  windows: MaintenanceWindow[];
  limit: number;
  offset: number;
  next_offset: number | null;
}

export interface MaintenanceWindowDetailResponse {
  state: AlertingApiState;
  window: MaintenanceWindow | null;
}

export interface AlertRuleUpdateRequest {
  expected_version: number;
  definition: AlertRuleDefinition;
}

export interface AlertRuleApproveRequest {
  expected_version: number;
}

export interface MaintenanceWindowCreateRequest {
  name: string;
  scope: AlertScope;
  starts_at: string;
  ends_at: string;
  evaluation: MaintenanceEvaluation;
  reason: string;
}

export interface AlertRuleEvaluateObservation {
  at: string;
  entity: string;
  scopes: AlertScope[];
  value: number | null;
  text: string | null;
  anomaly: ObservationAnomaly | null;
  destination: string | null;
  device_groups: string[];
}

export interface AlertRuleEvaluateWindow {
  scope: AlertScope;
  starts_at: string;
  ends_at: string;
  evaluation: MaintenanceEvaluation;
  status: SampleWindowStatus;
}

export interface AlertRuleEvaluateRequest {
  definition: AlertRuleDefinition;
  observations: AlertRuleEvaluateObservation[];
  windows: AlertRuleEvaluateWindow[];
}

export interface AlertRuleEvaluateProblem {
  code: string;
  field: string;
}

export interface AlertRuleEvaluateResult {
  at: string;
  outcome: EvaluateOutcome;
  phase: EvaluatePhase;
  transition: EvaluateTransition | null;
  notify: boolean;
  blocked_by: EvaluateBlocker | null;
  maintenance_windows: number[];
}

export interface AlertRuleEvaluateResponse {
  valid: boolean;
  problems: AlertRuleEvaluateProblem[];
  results: AlertRuleEvaluateResult[];
}

const RULE_LIST_KEYS = ['state', 'rules', 'limit', 'offset', 'next_offset'] as const;
const RULE_DETAIL_KEYS = ['state', 'rule'] as const;
const WINDOW_LIST_KEYS = ['state', 'windows', 'limit', 'offset', 'next_offset'] as const;
const WINDOW_DETAIL_KEYS = ['state', 'window'] as const;
const UPDATE_KEYS = ['expected_version', 'definition'] as const;
const APPROVE_KEYS = ['expected_version'] as const;
const CREATE_KEYS = ['name', 'scope', 'starts_at', 'ends_at', 'evaluation', 'reason'] as const;
const OBSERVATION_KEYS = [
  'at',
  'entity',
  'scopes',
  'value',
  'text',
  'anomaly',
  'destination',
  'device_groups',
] as const;
const SAMPLE_WINDOW_KEYS = ['scope', 'starts_at', 'ends_at', 'evaluation', 'status'] as const;
const EVALUATE_REQUEST_KEYS = ['definition', 'observations', 'windows'] as const;
const PROBLEM_KEYS = ['code', 'field'] as const;
const RESULT_KEYS = [
  'at',
  'outcome',
  'phase',
  'transition',
  'notify',
  'blocked_by',
  'maintenance_windows',
] as const;
const EVALUATE_RESPONSE_KEYS = ['valid', 'problems', 'results'] as const;
const PROBLEM_CODE = /^[A-Z0-9_]+$/;

function isTimestamp(value: unknown): value is string {
  return typeof value === 'string' && isRfc3339(value);
}

function isNullableCursor(value: unknown): value is number | null {
  return value === null || isIntegerInRange(value, 1, MAX_RULE_LIST_OFFSET);
}

function isVersion(value: unknown): value is number {
  return isIntegerInRange(value, 1, MAX_RULE_VERSION);
}

/** Positive duration of at most 30 days (cross-field rule JSON Schema cannot express). */
function isBoundedSpan(startsAt: string, endsAt: string): boolean {
  const duration = Date.parse(endsAt) - Date.parse(startsAt);
  return duration > 0 && duration <= MAX_MAINTENANCE_MS;
}

function parseEnvelope<T>(
  value: unknown,
  keys: readonly string[],
  parseItem: (item: unknown) => T | null,
  rowsKey: string,
): { state: AlertingApiState; rows: T[]; limit: number; offset: number; next: number | null } | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, keys)) return null;
  if (
    !isOneOf(value.state, ALERTING_API_STATES) ||
    !isIntegerInRange(value.limit, 1, MAX_RULE_PAGE_SIZE) ||
    !isIntegerInRange(value.offset, 0, MAX_RULE_LIST_OFFSET) ||
    !isNullableCursor(value.next_offset)
  ) {
    return null;
  }
  const rows = parseArray(value[rowsKey], 0, MAX_RULE_PAGE_SIZE, parseItem);
  if (rows === null) return null;
  // Fail closed: a non-ok state never carries rows or a cursor, whatever the payload says.
  if (value.state !== 'ok' && (rows.length > 0 || value.next_offset !== null)) return null;
  return {
    state: value.state,
    rows,
    limit: value.limit,
    offset: value.offset,
    next: value.next_offset,
  };
}

export function parseAlertRuleListResponse(value: unknown): AlertRuleListResponse | null {
  const page = parseEnvelope(value, RULE_LIST_KEYS, parseAlertRule, 'rules');
  if (page === null) return null;
  return {
    state: page.state,
    rules: page.rows,
    limit: page.limit,
    offset: page.offset,
    next_offset: page.next,
  };
}

export function parseMaintenanceWindowListResponse(
  value: unknown,
): MaintenanceWindowListResponse | null {
  const page = parseEnvelope(value, WINDOW_LIST_KEYS, parseMaintenanceWindow, 'windows');
  if (page === null) return null;
  return {
    state: page.state,
    windows: page.rows,
    limit: page.limit,
    offset: page.offset,
    next_offset: page.next,
  };
}

function parseDetail<T>(
  value: unknown,
  keys: readonly string[],
  key: string,
  parseItem: (item: unknown) => T | null,
): { state: AlertingApiState; item: T | null } | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, keys)) return null;
  if (!isOneOf(value.state, ALERTING_API_STATES)) return null;
  const item = value[key] === null ? null : parseItem(value[key]);
  if (value[key] !== null && item === null) return null;
  // The record is present exactly when the state is ok.
  if ((value.state === 'ok') !== (item !== null)) return null;
  return { state: value.state, item };
}

export function parseAlertRuleDetailResponse(value: unknown): AlertRuleDetailResponse | null {
  const detail = parseDetail(value, RULE_DETAIL_KEYS, 'rule', parseAlertRule);
  return detail === null ? null : { state: detail.state, rule: detail.item };
}

export function parseMaintenanceWindowDetailResponse(
  value: unknown,
): MaintenanceWindowDetailResponse | null {
  const detail = parseDetail(value, WINDOW_DETAIL_KEYS, 'window', parseMaintenanceWindow);
  return detail === null ? null : { state: detail.state, window: detail.item };
}

export function parseAlertRuleUpdateRequest(value: unknown): AlertRuleUpdateRequest | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, UPDATE_KEYS)) return null;
  const definition = parseAlertRuleDefinition(value.definition);
  if (!isVersion(value.expected_version) || definition === null) return null;
  return { expected_version: value.expected_version, definition };
}

export function parseAlertRuleApproveRequest(value: unknown): AlertRuleApproveRequest | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, APPROVE_KEYS)) return null;
  if (!isVersion(value.expected_version)) return null;
  return { expected_version: value.expected_version };
}

export function parseMaintenanceWindowCreateRequest(
  value: unknown,
): MaintenanceWindowCreateRequest | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, CREATE_KEYS)) return null;
  const scope = parseScope(value.scope);
  if (
    !isNonBlankText(value.name, 255) ||
    scope === null ||
    !isTimestamp(value.starts_at) ||
    !isTimestamp(value.ends_at) ||
    !isOneOf(value.evaluation, MAINTENANCE_EVALUATIONS) ||
    !isNonBlankText(value.reason, 1000) ||
    !isBoundedSpan(value.starts_at, value.ends_at)
  ) {
    return null;
  }
  return {
    name: value.name,
    scope,
    starts_at: value.starts_at,
    ends_at: value.ends_at,
    evaluation: value.evaluation,
    reason: value.reason,
  };
}

function hasUniqueScopes(scopes: AlertScope[]): boolean {
  return new Set(scopes.map((scope) => `${scope.kind}\u001f${scope.ref}`)).size === scopes.length;
}

function parseObservation(value: unknown): AlertRuleEvaluateObservation | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, OBSERVATION_KEYS)) return null;
  const scopes = parseArray(value.scopes, 1, 16, parseScope);
  const groups = parseArray(value.device_groups, 0, 16, textItem(1, 128), true);
  const numeric = value.value;
  if (
    !isTimestamp(value.at) ||
    !isText(value.entity, 1, 255) ||
    scopes === null ||
    !hasUniqueScopes(scopes) ||
    !(
      numeric === null ||
      (typeof numeric === 'number' && Number.isFinite(numeric) && Math.abs(numeric) <= VALUE_BOUND)
    ) ||
    !isNullableText(value.text, 0, 4096) ||
    !(value.anomaly === null || isOneOf(value.anomaly, OBSERVATION_ANOMALIES)) ||
    !isNullableText(value.destination, 1, 255) ||
    groups === null
  ) {
    return null;
  }
  return {
    at: value.at,
    entity: value.entity,
    scopes,
    value: numeric as number | null,
    text: value.text,
    anomaly: value.anomaly as ObservationAnomaly | null,
    destination: value.destination,
    device_groups: groups,
  };
}

function parseSampleWindow(value: unknown): AlertRuleEvaluateWindow | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, SAMPLE_WINDOW_KEYS)) return null;
  const scope = parseScope(value.scope);
  if (
    scope === null ||
    !isTimestamp(value.starts_at) ||
    !isTimestamp(value.ends_at) ||
    !isOneOf(value.evaluation, MAINTENANCE_EVALUATIONS) ||
    !isOneOf(value.status, SAMPLE_WINDOW_STATUSES) ||
    !isBoundedSpan(value.starts_at, value.ends_at)
  ) {
    return null;
  }
  return {
    scope,
    starts_at: value.starts_at,
    ends_at: value.ends_at,
    evaluation: value.evaluation,
    status: value.status,
  };
}

export function parseAlertRuleEvaluateRequest(value: unknown): AlertRuleEvaluateRequest | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, EVALUATE_REQUEST_KEYS)) return null;
  const definition = parseAlertRuleDefinition(value.definition);
  const observations = parseArray(value.observations, 1, MAX_EVALUATE_OBSERVATIONS, parseObservation);
  const windows = parseArray(value.windows, 0, MAX_EVALUATE_WINDOWS, parseSampleWindow);
  if (definition === null || observations === null || windows === null) return null;
  // Strictly ascending time order (cross-field rule JSON Schema cannot express).
  for (let index = 1; index < observations.length; index += 1) {
    if (Date.parse(observations[index].at) <= Date.parse(observations[index - 1].at)) return null;
  }
  return { definition, observations, windows };
}

function parseProblem(value: unknown): AlertRuleEvaluateProblem | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, PROBLEM_KEYS)) return null;
  if (
    !isText(value.code, 1, 64) ||
    !PROBLEM_CODE.test(value.code) ||
    !isText(value.field, 1, 64)
  ) {
    return null;
  }
  return { code: value.code, field: value.field };
}

function parseResult(value: unknown): AlertRuleEvaluateResult | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, RESULT_KEYS)) return null;
  const indexes = parseArray(
    value.maintenance_windows,
    0,
    MAX_EVALUATE_WINDOWS,
    (item) => (isIntegerInRange(item, 0, MAX_EVALUATE_WINDOWS - 1) ? item : null),
    true,
  );
  if (
    !isTimestamp(value.at) ||
    !isOneOf(value.outcome, EVALUATE_OUTCOMES) ||
    !isOneOf(value.phase, EVALUATE_PHASES) ||
    !(value.transition === null || isOneOf(value.transition, EVALUATE_TRANSITIONS)) ||
    typeof value.notify !== 'boolean' ||
    !(value.blocked_by === null || isOneOf(value.blocked_by, EVALUATE_BLOCKERS)) ||
    indexes === null
  ) {
    return null;
  }
  return {
    at: value.at,
    outcome: value.outcome,
    phase: value.phase,
    transition: value.transition as EvaluateTransition | null,
    notify: value.notify,
    blocked_by: value.blocked_by as EvaluateBlocker | null,
    maintenance_windows: indexes,
  };
}

/** Fail closed: an invalid verdict explains why and never carries decisions. */
export function parseAlertRuleEvaluateResponse(value: unknown): AlertRuleEvaluateResponse | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, EVALUATE_RESPONSE_KEYS)) return null;
  const problems = parseArray(value.problems, 0, 8, parseProblem);
  const results = parseArray(value.results, 0, MAX_EVALUATE_OBSERVATIONS, parseResult);
  if (typeof value.valid !== 'boolean' || problems === null || results === null) return null;
  if (value.valid && problems.length > 0) return null;
  if (!value.valid && (problems.length === 0 || results.length > 0)) return null;
  return { valid: value.valid, problems, results };
}

export type { AlertRuleStatus };
export { ALERT_RULE_STATUSES };
