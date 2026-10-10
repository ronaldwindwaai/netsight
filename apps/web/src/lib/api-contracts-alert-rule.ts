import { ALERT_SEVERITIES, isRfc3339, type AlertSeverity } from './api-contracts.ts';
import {
  hasExactKeys,
  isIntegerInRange,
  isNonBlankText,
  isNullableText,
  isOneOf,
  isPlainRecord,
  isText,
  parseArray,
  textItem,
  type UnknownRecord,
} from './contract-guards.ts';

export const ALERT_SCOPE_KINDS = [
  'organisation',
  'site',
  'device',
  'device_group',
  'vlan',
  'user',
  'service',
] as const;
export const ALERT_OPERATORS = ['gt', 'gte', 'lt', 'lte', 'eq', 'ne', 'matches'] as const;
export const BASELINE_MODES = [
  'none',
  'above-baseline',
  'below-baseline',
  'outside-baseline',
] as const;
export const WEEKDAYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'] as const;
export const ALERT_RULE_STATUSES = ['draft', 'active', 'disabled'] as const;
export const ALERT_ACTIONS = ['create_alert', 'email', 'push'] as const;
export const INCIDENT_POLICIES = ['none', 'create', 'group'] as const;
export const MAINTENANCE_EVALUATIONS = ['retain', 'disable'] as const;
export const MAINTENANCE_STATUSES = ['scheduled', 'cancelled'] as const;

export type AlertScopeKind = (typeof ALERT_SCOPE_KINDS)[number];
export type AlertOperator = (typeof ALERT_OPERATORS)[number];
export type BaselineMode = (typeof BASELINE_MODES)[number];
export type Weekday = (typeof WEEKDAYS)[number];
export type AlertRuleStatus = (typeof ALERT_RULE_STATUSES)[number];
export type AlertAction = (typeof ALERT_ACTIONS)[number];
export type IncidentPolicy = (typeof INCIDENT_POLICIES)[number];
export type MaintenanceEvaluation = (typeof MAINTENANCE_EVALUATIONS)[number];
export type MaintenanceStatus = (typeof MAINTENANCE_STATUSES)[number];

export interface AlertScope {
  kind: AlertScopeKind;
  ref: string;
}

export interface AlertCondition {
  metric: string;
  operator: AlertOperator;
  threshold: number | null;
  pattern: string | null;
}

export interface AlertScheduleEntry {
  weekdays: Weekday[];
  from: string;
  to: string;
}

export interface AlertSchedule {
  timezone: string;
  active: AlertScheduleEntry[];
}

export interface AlertExceptions {
  destinations: string[];
  device_groups: string[];
}

export interface AlertRule {
  id: string;
  name: string;
  status: AlertRuleStatus;
  scope: AlertScope;
  condition: AlertCondition;
  baseline_mode: BaselineMode;
  window_seconds: number;
  for_seconds: number;
  cooldown_seconds: number;
  schedule: AlertSchedule | null;
  exceptions: AlertExceptions;
  severity: AlertSeverity;
  labels: Record<string, string>;
  actions: AlertAction[];
  incident_policy: IncidentPolicy;
  created_by: string;
  created_at: string;
  updated_at: string;
  approved_by: string | null;
  approved_at: string | null;
  version: number;
}

export interface MaintenanceWindow {
  id: string;
  name: string;
  scope: AlertScope;
  starts_at: string;
  ends_at: string;
  evaluation: MaintenanceEvaluation;
  status: MaintenanceStatus;
  reason: string;
  created_by: string;
  created_at: string;
  cancelled_by: string | null;
  cancelled_at: string | null;
}

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const RULE_ID = new RegExp(`^alert-rule-${UUID}$`);
const WINDOW_ID = new RegExp(`^maintenance-${UUID}$`);
export function isAlertRuleId(value: unknown): value is string {
  return typeof value === 'string' && RULE_ID.test(value);
}

export function isMaintenanceWindowId(value: unknown): value is string {
  return typeof value === 'string' && WINDOW_ID.test(value);
}

const METRIC = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$/;
const TIME_OF_DAY = /^([01][0-9]|2[0-3]):[0-5][0-9]$/;
const TIMEZONE = /^(UTC|[A-Za-z][A-Za-z0-9_+-]*(\/[A-Za-z][A-Za-z0-9_+-]*){1,2})$/;
const LABEL_KEY = /^[a-z][a-z0-9_]{0,62}$/;
const THRESHOLD_BOUND = 1_000_000_000_000_000;
const MAX_MAINTENANCE_MS = 30 * 24 * 60 * 60 * 1000;

const SCOPE_KEYS = ['kind', 'ref'] as const;
const CONDITION_KEYS = ['metric', 'operator', 'threshold', 'pattern'] as const;
const SCHEDULE_KEYS = ['timezone', 'active'] as const;
const SCHEDULE_ENTRY_KEYS = ['weekdays', 'from', 'to'] as const;
const EXCEPTION_KEYS = ['destinations', 'device_groups'] as const;
const RULE_KEYS = [
  'id',
  'name',
  'status',
  'scope',
  'condition',
  'baseline_mode',
  'window_seconds',
  'for_seconds',
  'cooldown_seconds',
  'schedule',
  'exceptions',
  'severity',
  'labels',
  'actions',
  'incident_policy',
  'created_by',
  'created_at',
  'updated_at',
  'approved_by',
  'approved_at',
  'version',
] as const;
const WINDOW_KEYS = [
  'id',
  'name',
  'scope',
  'starts_at',
  'ends_at',
  'evaluation',
  'status',
  'reason',
  'created_by',
  'created_at',
  'cancelled_by',
  'cancelled_at',
] as const;

function isTimestamp(value: unknown): value is string {
  return typeof value === 'string' && isRfc3339(value);
}

function isNullableTimestamp(value: unknown): value is string | null {
  return value === null || isTimestamp(value);
}

export function parseScope(value: unknown): AlertScope | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, SCOPE_KEYS)) return null;
  if (!isOneOf(value.kind, ALERT_SCOPE_KINDS) || !isText(value.ref, 1, 255)) return null;
  return { kind: value.kind, ref: value.ref };
}

function parseCondition(value: unknown): AlertCondition | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, CONDITION_KEYS)) return null;
  const threshold = value.threshold;
  if (
    !isText(value.metric, 1, 128) ||
    !METRIC.test(value.metric) ||
    !isOneOf(value.operator, ALERT_OPERATORS) ||
    !(
      threshold === null ||
      (typeof threshold === 'number' &&
        Number.isFinite(threshold) &&
        Math.abs(threshold) <= THRESHOLD_BOUND)
    ) ||
    !isNullableText(value.pattern, 1, 256)
  ) {
    return null;
  }
  // matches <=> pattern (no threshold); every other operator <=> threshold (no pattern).
  if (value.operator === 'matches') {
    if (value.pattern === null || threshold !== null) return null;
  } else if (threshold === null || value.pattern !== null) {
    return null;
  }
  return {
    metric: value.metric,
    operator: value.operator,
    threshold: threshold as number | null,
    pattern: value.pattern,
  };
}

function parseScheduleEntry(value: unknown): AlertScheduleEntry | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, SCHEDULE_ENTRY_KEYS)) return null;
  const weekdays = parseArray(
    value.weekdays,
    1,
    7,
    (day) => (isOneOf(day, WEEKDAYS) ? day : null),
    true,
  );
  if (
    weekdays === null ||
    typeof value.from !== 'string' ||
    !TIME_OF_DAY.test(value.from) ||
    typeof value.to !== 'string' ||
    !TIME_OF_DAY.test(value.to)
  ) {
    return null;
  }
  return { weekdays, from: value.from, to: value.to };
}

function parseSchedule(value: unknown): AlertSchedule | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, SCHEDULE_KEYS)) return null;
  const active = parseArray(value.active, 1, 14, parseScheduleEntry);
  if (
    active === null ||
    typeof value.timezone !== 'string' ||
    !isText(value.timezone, 1, 64) ||
    !TIMEZONE.test(value.timezone)
  ) {
    return null;
  }
  return { timezone: value.timezone, active };
}

function parseExceptions(value: unknown): AlertExceptions | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, EXCEPTION_KEYS)) return null;
  const destinations = parseArray(value.destinations, 0, 64, textItem(1, 128), true);
  const deviceGroups = parseArray(value.device_groups, 0, 64, textItem(1, 128), true);
  if (destinations === null || deviceGroups === null) return null;
  return { destinations, device_groups: deviceGroups };
}

function parseLabels(value: unknown): Record<string, string> | null {
  if (!isPlainRecord(value)) return null;
  const keys = Object.keys(value);
  if (keys.length > 32) return null;
  const labels: Record<string, string> = {};
  for (const key of keys) {
    const label = value[key];
    if (!LABEL_KEY.test(key) || !isText(label, 0, 128)) return null;
    labels[key] = label;
  }
  return labels;
}

/** Operator-editable fields of a rule (everything but lifecycle and audit). */
export interface AlertRuleDefinition {
  name: string;
  scope: AlertScope;
  condition: AlertCondition;
  baseline_mode: BaselineMode;
  window_seconds: number;
  for_seconds: number;
  cooldown_seconds: number;
  schedule: AlertSchedule | null;
  exceptions: AlertExceptions;
  severity: AlertSeverity;
  labels: Record<string, string>;
  actions: AlertAction[];
  incident_policy: IncidentPolicy;
}

const DEFINITION_KEYS = [
  'name',
  'scope',
  'condition',
  'baseline_mode',
  'window_seconds',
  'for_seconds',
  'cooldown_seconds',
  'schedule',
  'exceptions',
  'severity',
  'labels',
  'actions',
  'incident_policy',
] as const;

function parseDefinitionFields(value: UnknownRecord): AlertRuleDefinition | null {
  const scope = parseScope(value.scope);
  const condition = parseCondition(value.condition);
  const schedule = value.schedule === null ? null : parseSchedule(value.schedule);
  const exceptions = parseExceptions(value.exceptions);
  const labels = parseLabels(value.labels);
  const actions = parseArray(
    value.actions,
    1,
    3,
    (action) => (isOneOf(action, ALERT_ACTIONS) ? action : null),
    true,
  );
  if (
    !isNonBlankText(value.name, 255) ||
    scope === null ||
    condition === null ||
    !isOneOf(value.baseline_mode, BASELINE_MODES) ||
    !isIntegerInRange(value.window_seconds, 60, 86_400) ||
    !isIntegerInRange(value.for_seconds, 0, 86_400) ||
    !isIntegerInRange(value.cooldown_seconds, 0, 604_800) ||
    (value.schedule !== null && schedule === null) ||
    exceptions === null ||
    !isOneOf(value.severity, ALERT_SEVERITIES) ||
    labels === null ||
    actions === null ||
    !isOneOf(value.incident_policy, INCIDENT_POLICIES)
  ) {
    return null;
  }
  return {
    name: value.name,
    scope,
    condition,
    baseline_mode: value.baseline_mode,
    window_seconds: value.window_seconds,
    for_seconds: value.for_seconds,
    cooldown_seconds: value.cooldown_seconds,
    schedule,
    exceptions,
    severity: value.severity,
    labels,
    actions,
    incident_policy: value.incident_policy,
  };
}

/** Exactly the definition fields: lifecycle or audit fields make it invalid (fail closed). */
export function parseAlertRuleDefinition(value: unknown): AlertRuleDefinition | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, DEFINITION_KEYS)) return null;
  return parseDefinitionFields(value);
}

export function parseAlertRule(value: unknown): AlertRule | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, RULE_KEYS)) return null;
  const definition = parseDefinitionFields(value);
  if (
    definition === null ||
    typeof value.id !== 'string' ||
    !RULE_ID.test(value.id) ||
    !isOneOf(value.status, ALERT_RULE_STATUSES) ||
    !isText(value.created_by, 1, 255) ||
    !isTimestamp(value.created_at) ||
    !isTimestamp(value.updated_at) ||
    !isNullableText(value.approved_by, 1, 255) ||
    !isNullableTimestamp(value.approved_at) ||
    !isIntegerInRange(value.version, 1, 1_000_000)
  ) {
    return null;
  }
  // Approval invariants: set together, required for active, forbidden for draft.
  if ((value.approved_by === null) !== (value.approved_at === null)) return null;
  if (value.status === 'active' && value.approved_by === null) return null;
  if (value.status === 'draft' && value.approved_by !== null) return null;
  return {
    id: value.id,
    status: value.status,
    ...definition,
    created_by: value.created_by,
    created_at: value.created_at,
    updated_at: value.updated_at,
    approved_by: value.approved_by,
    approved_at: value.approved_at,
    version: value.version,
  };
}

export function parseMaintenanceWindow(value: unknown): MaintenanceWindow | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, WINDOW_KEYS)) return null;
  const scope = parseScope(value.scope);
  if (
    typeof value.id !== 'string' ||
    !WINDOW_ID.test(value.id) ||
    !isNonBlankText(value.name, 255) ||
    scope === null ||
    !isTimestamp(value.starts_at) ||
    !isTimestamp(value.ends_at) ||
    !isOneOf(value.evaluation, MAINTENANCE_EVALUATIONS) ||
    !isOneOf(value.status, MAINTENANCE_STATUSES) ||
    !isNonBlankText(value.reason, 1000) ||
    !isText(value.created_by, 1, 255) ||
    !isTimestamp(value.created_at) ||
    !isNullableText(value.cancelled_by, 1, 255) ||
    !isNullableTimestamp(value.cancelled_at)
  ) {
    return null;
  }
  // Cross-field rules JSON Schema cannot express: positive duration, at most 30 days.
  const duration = Date.parse(value.ends_at) - Date.parse(value.starts_at);
  if (duration <= 0 || duration > MAX_MAINTENANCE_MS) return null;
  // cancelled <=> both cancellation fields present.
  const hasCancellation = value.cancelled_by !== null && value.cancelled_at !== null;
  if ((value.cancelled_by === null) !== (value.cancelled_at === null)) return null;
  if ((value.status === 'cancelled') !== hasCancellation) return null;
  return {
    id: value.id,
    name: value.name,
    scope,
    starts_at: value.starts_at,
    ends_at: value.ends_at,
    evaluation: value.evaluation,
    status: value.status,
    reason: value.reason,
    created_by: value.created_by,
    created_at: value.created_at,
    cancelled_by: value.cancelled_by,
    cancelled_at: value.cancelled_at,
  };
}
