/**
 * Alert-rule and maintenance-window forms: values <-> contract bodies, which actions the viewer
 * may take, and how a submission becomes an API request.
 *
 * Everything here is defensive and advisory. The API re-validates every body, re-checks every
 * permission and owns the lifecycle rules; the browser-side checks mirror the contract so the
 * operator gets field-level feedback and so the server action never forwards a shape the
 * contract does not describe. Operator text (names, labels, patterns, reasons) is carried as
 * data and never interpreted. Pure, so each rule is unit-tested.
 */
import {
  ALERT_ACTIONS,
  ALERT_OPERATORS,
  ALERT_SCOPE_KINDS,
  BASELINE_MODES,
  INCIDENT_POLICIES,
  MAINTENANCE_EVALUATIONS,
  WEEKDAYS,
  isAlertRuleId,
  isMaintenanceWindowId,
  parseAlertRuleDefinition,
  type AlertAction,
  type AlertOperator,
  type AlertRule,
  type AlertRuleDefinition,
  type AlertScopeKind,
  type BaselineMode,
  type IncidentPolicy,
  type MaintenanceEvaluation,
  type MaintenanceWindow,
  type Weekday,
} from './api-contracts-alert-rule.ts';
import {
  parseMaintenanceWindowCreateRequest,
  type MaintenanceWindowCreateRequest,
} from './api-contracts-alert-rule-api.ts';
import { ALERT_SEVERITIES, type AlertSeverity } from './api-contracts.ts';
import { codePointLength, isOneOf } from './contract-guards.ts';
import { utcFromLocalInput, type Viewer } from './incident-actions.ts';

export type FieldErrors = Record<string, string>;

const THRESHOLD_BOUND = 1_000_000_000_000_000;
const MAX_RULE_VERSION = 1_000_000;
const MAX_MAINTENANCE_MS = 30 * 24 * 60 * 60 * 1000;
const NUMBER = /^-?\d+(\.\d+)?([eE][+-]?\d+)?$/;
const INTEGER = /^\d{1,9}$/;
const METRIC = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$/;
const LABEL_KEY = /^[a-z][a-z0-9_]{0,62}$/;
const TIME_OF_DAY = /^([01][0-9]|2[0-3]):[0-5][0-9]$/;
const SCHEDULE_LINE = /^([a-z]{3}(?:\s*,\s*[a-z]{3})*)\s+(\d{2}:\d{2})\s*-\s*(\d{2}:\d{2})$/;

// --- rule form -------------------------------------------------------------------------

/** Every control as the browser holds it: text, never a half-parsed number. */
export interface RuleFormValues {
  name: string;
  scopeKind: AlertScopeKind;
  scopeRef: string;
  metric: string;
  operator: AlertOperator;
  /** A number, or the pattern when the operator is `matches`. */
  operand: string;
  baselineMode: BaselineMode;
  windowSeconds: string;
  forSeconds: string;
  cooldownSeconds: string;
  severity: AlertSeverity;
  actions: AlertAction[];
  incidentPolicy: IncidentPolicy;
  /** One `key=value` per line. */
  labels: string;
  exceptionDestinations: string;
  exceptionDeviceGroups: string;
  /** Empty (with no lines) means the rule is always in schedule. */
  scheduleTimezone: string;
  /** One `mon,tue 08:00-18:00` per line. */
  scheduleLines: string;
}

export function emptyRuleForm(): RuleFormValues {
  return {
    name: '',
    scopeKind: 'device',
    scopeRef: '',
    metric: '',
    operator: 'gt',
    operand: '',
    baselineMode: 'none',
    windowSeconds: '300',
    forSeconds: '0',
    cooldownSeconds: '600',
    severity: 'medium',
    actions: ['create_alert'],
    incidentPolicy: 'none',
    labels: '',
    exceptionDestinations: '',
    exceptionDeviceGroups: '',
    scheduleTimezone: '',
    scheduleLines: '',
  };
}

export function ruleToForm(rule: AlertRuleDefinition | AlertRule): RuleFormValues {
  return {
    name: rule.name,
    scopeKind: rule.scope.kind,
    scopeRef: rule.scope.ref,
    metric: rule.condition.metric,
    operator: rule.condition.operator,
    operand:
      rule.condition.pattern ??
      (rule.condition.threshold === null ? '' : String(rule.condition.threshold)),
    baselineMode: rule.baseline_mode,
    windowSeconds: String(rule.window_seconds),
    forSeconds: String(rule.for_seconds),
    cooldownSeconds: String(rule.cooldown_seconds),
    severity: rule.severity,
    actions: [...rule.actions],
    incidentPolicy: rule.incident_policy,
    labels: Object.entries(rule.labels)
      .map(([key, value]) => `${key}=${value}`)
      .join('\n'),
    exceptionDestinations: rule.exceptions.destinations.join('\n'),
    exceptionDeviceGroups: rule.exceptions.device_groups.join('\n'),
    scheduleTimezone: rule.schedule?.timezone ?? '',
    scheduleLines:
      rule.schedule?.active
        .map((entry) => `${entry.weekdays.join(',')} ${entry.from}-${entry.to}`)
        .join('\n') ?? '',
  };
}

function lines(value: string): string[] {
  return value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function text(source: Record<string, unknown>, key: string): string {
  const value = source[key];
  return typeof value === 'string' ? value : '';
}

function boundedInteger(raw: string, minimum: number, maximum: number): number | null {
  const trimmed = raw.trim();
  if (!INTEGER.test(trimmed)) return null;
  const value = Number(trimmed);
  return value >= minimum && value <= maximum ? value : null;
}

function parseThreshold(raw: string): number | null {
  const trimmed = raw.trim();
  if (!NUMBER.test(trimmed)) return null;
  const value = Number(trimmed);
  return Number.isFinite(value) && Math.abs(value) <= THRESHOLD_BOUND ? value : null;
}

function parseLabels(raw: string, errors: FieldErrors): Record<string, string> {
  const labels: Record<string, string> = {};
  const all = lines(raw);
  if (all.length > 32) errors.labels = 'Use at most 32 labels.';
  for (const line of all) {
    const index = line.indexOf('=');
    const key = index < 0 ? '' : line.slice(0, index).trim();
    const value = index < 0 ? '' : line.slice(index + 1).trim();
    if (index < 0 || !LABEL_KEY.test(key) || codePointLength(value) > 128) {
      errors.labels =
        'Each label is key=value; keys are lower-case letters, digits and underscores, values at most 128 characters.';
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(labels, key)) {
      errors.labels = `The label "${key}" is listed twice.`;
      continue;
    }
    labels[key] = value;
  }
  return labels;
}

function parseNameList(raw: string, field: string, errors: FieldErrors): string[] {
  const items = lines(raw);
  if (
    items.length > 64 ||
    items.some((item) => codePointLength(item) > 128) ||
    new Set(items).size !== items.length
  ) {
    errors[field] = 'Use at most 64 distinct entries, one per line, each at most 128 characters.';
  }
  return items;
}

interface ParsedSchedule {
  timezone: string;
  active: Array<{ weekdays: Weekday[]; from: string; to: string }>;
}

function parseSchedule(timezone: string, raw: string, errors: FieldErrors): ParsedSchedule | null {
  const zone = timezone.trim();
  const entries = lines(raw);
  if (zone === '' && entries.length === 0) return null;
  if (zone === '' || entries.length === 0) {
    errors.scheduleLines = 'A schedule needs both a timezone and at least one weekday and time range.';
    return null;
  }
  if (entries.length > 14) errors.scheduleLines = 'Use at most 14 schedule lines.';
  const active: ParsedSchedule['active'] = [];
  for (const entry of entries) {
    const match = SCHEDULE_LINE.exec(entry);
    const days = match === null ? [] : match[1].split(',').map((day) => day.trim());
    if (
      match === null ||
      !days.every((day): day is Weekday => isOneOf(day, WEEKDAYS)) ||
      new Set(days).size !== days.length ||
      !TIME_OF_DAY.test(match[2]) ||
      !TIME_OF_DAY.test(match[3])
    ) {
      errors.scheduleLines =
        'Each line is weekdays then a range, for example "mon,tue,wed 08:00-18:00" (24-hour times, each weekday once).';
      continue;
    }
    active.push({ weekdays: days as Weekday[], from: match[2], to: match[3] });
  }
  return { timezone: zone, active };
}

export type RuleBuild =
  | { ok: true; definition: AlertRuleDefinition }
  | { ok: false; errors: FieldErrors };

/** Rebuild the contract definition from raw form values; the contract parser is the last gate. */
export function buildRuleDefinition(input: unknown): RuleBuild {
  if (!isRecord(input)) return { ok: false, errors: { _form: 'The form was not well formed.' } };
  const errors: FieldErrors = {};
  const name = text(input, 'name');
  if (!/\S/.test(name) || codePointLength(name) > 255) errors.name = 'Enter a name of at most 255 characters.';
  const scopeKind = input.scopeKind;
  if (!isOneOf(scopeKind, ALERT_SCOPE_KINDS)) errors.scopeKind = 'Choose a scope.';
  const scopeRef = text(input, 'scopeRef');
  if (scopeRef.length === 0 || codePointLength(scopeRef) > 255) {
    errors.scopeRef = 'Enter the scope reference (1 to 255 characters).';
  }
  const metric = text(input, 'metric').trim();
  if (!METRIC.test(metric) || metric.length > 128) {
    errors.metric = 'Use a dotted lower-case metric name such as interface.utilisation_percent.';
  }
  const operator = input.operator;
  if (!isOneOf(operator, ALERT_OPERATORS)) errors.operator = 'Choose an operator.';
  const operand = text(input, 'operand');
  let threshold: number | null = null;
  let pattern: string | null = null;
  if (operator === 'matches') {
    if (operand.length === 0 || codePointLength(operand) > 256) {
      errors.operand = 'Enter a pattern of 1 to 256 characters.';
    }
    pattern = operand;
  } else {
    threshold = parseThreshold(operand);
    if (threshold === null) errors.operand = 'Enter a finite number.';
  }
  const baselineMode = input.baselineMode;
  if (!isOneOf(baselineMode, BASELINE_MODES)) errors.baselineMode = 'Choose a baseline mode.';
  const windowSeconds = boundedInteger(text(input, 'windowSeconds'), 60, 86_400);
  if (windowSeconds === null) errors.windowSeconds = 'Enter whole seconds from 60 to 86400.';
  const forSeconds = boundedInteger(text(input, 'forSeconds'), 0, 86_400);
  if (forSeconds === null) errors.forSeconds = 'Enter whole seconds from 0 to 86400.';
  const cooldownSeconds = boundedInteger(text(input, 'cooldownSeconds'), 0, 604_800);
  if (cooldownSeconds === null) errors.cooldownSeconds = 'Enter whole seconds from 0 to 604800.';
  const severity = input.severity;
  if (!isOneOf(severity, ALERT_SEVERITIES)) errors.severity = 'Choose a severity.';
  const actions = Array.isArray(input.actions) ? input.actions : [];
  if (
    actions.length < 1 ||
    actions.length > 3 ||
    !actions.every((action) => isOneOf(action, ALERT_ACTIONS)) ||
    new Set(actions).size !== actions.length
  ) {
    errors.actions = 'Choose between one and three distinct actions.';
  }
  const incidentPolicy = input.incidentPolicy;
  if (!isOneOf(incidentPolicy, INCIDENT_POLICIES)) errors.incidentPolicy = 'Choose an incident policy.';

  const labels = parseLabels(text(input, 'labels'), errors);
  const destinations = parseNameList(text(input, 'exceptionDestinations'), 'exceptionDestinations', errors);
  const deviceGroups = parseNameList(text(input, 'exceptionDeviceGroups'), 'exceptionDeviceGroups', errors);
  const schedule = parseSchedule(text(input, 'scheduleTimezone'), text(input, 'scheduleLines'), errors);

  if (Object.keys(errors).length > 0) return { ok: false, errors };

  const candidate = {
    name,
    scope: { kind: scopeKind, ref: scopeRef },
    condition: { metric, operator, threshold, pattern },
    baseline_mode: baselineMode,
    window_seconds: windowSeconds,
    for_seconds: forSeconds,
    cooldown_seconds: cooldownSeconds,
    schedule,
    exceptions: { destinations, device_groups: deviceGroups },
    severity,
    labels,
    actions,
    incident_policy: incidentPolicy,
  };
  const definition = parseAlertRuleDefinition(candidate);
  if (definition === null) {
    // Typically a schedule timezone the contract pattern rejects.
    return {
      ok: false,
      errors: {
        _form: 'Some values do not match the alert-rule contract (check the schedule timezone).',
      },
    };
  }
  return { ok: true, definition };
}

// --- window form -----------------------------------------------------------------------

export interface WindowFormValues {
  name: string;
  scopeKind: AlertScopeKind;
  scopeRef: string;
  /** `YYYY-MM-DDTHH:mm`, read as UTC. */
  startsAt: string;
  endsAt: string;
  evaluation: MaintenanceEvaluation;
  reason: string;
}

export function emptyWindowForm(): WindowFormValues {
  return {
    name: '',
    scopeKind: 'device',
    scopeRef: '',
    startsAt: '',
    endsAt: '',
    evaluation: 'retain',
    reason: '',
  };
}

export type WindowBuild =
  | { ok: true; request: MaintenanceWindowCreateRequest }
  | { ok: false; errors: FieldErrors };

export function buildWindowRequest(input: unknown, nowMs: number): WindowBuild {
  if (!isRecord(input)) return { ok: false, errors: { _form: 'The form was not well formed.' } };
  const errors: FieldErrors = {};
  const name = text(input, 'name');
  if (!/\S/.test(name) || codePointLength(name) > 255) errors.name = 'Enter a name of at most 255 characters.';
  if (!isOneOf(input.scopeKind, ALERT_SCOPE_KINDS)) errors.scopeKind = 'Choose a scope.';
  const scopeRef = text(input, 'scopeRef');
  if (scopeRef.length === 0 || codePointLength(scopeRef) > 255) {
    errors.scopeRef = 'Enter the scope reference (1 to 255 characters).';
  }
  if (!isOneOf(input.evaluation, MAINTENANCE_EVALUATIONS)) errors.evaluation = 'Choose an effect.';
  const reason = text(input, 'reason');
  if (!/\S/.test(reason) || codePointLength(reason) > 1000) {
    errors.reason = 'Enter a reason of at most 1000 characters.';
  }
  const startsAt = utcFromLocalInput(input.startsAt);
  const endsAt = utcFromLocalInput(input.endsAt);
  if (startsAt === null) errors.startsAt = 'Enter a valid start (UTC).';
  if (endsAt === null) errors.endsAt = 'Enter a valid end (UTC).';
  if (startsAt !== null && endsAt !== null) {
    const span = Date.parse(endsAt) - Date.parse(startsAt);
    if (span <= 0) errors.endsAt = 'The end must be after the start.';
    else if (span > MAX_MAINTENANCE_MS) errors.endsAt = 'A window may last at most 30 days.';
    else if (Date.parse(endsAt) <= nowMs) errors.endsAt = 'The window has already ended.';
  }
  if (Object.keys(errors).length > 0) return { ok: false, errors };

  const request = parseMaintenanceWindowCreateRequest({
    name,
    scope: { kind: input.scopeKind, ref: scopeRef },
    starts_at: startsAt,
    ends_at: endsAt,
    evaluation: input.evaluation,
    reason,
  });
  if (request === null) {
    return { ok: false, errors: { _form: 'Some values do not match the maintenance-window contract.' } };
  }
  return { ok: true, request };
}

// --- availability ----------------------------------------------------------------------

export interface AvailableAction<T extends string> {
  action: T;
  label: string;
  enabled: boolean;
  reason: string | null;
}

const ROLE_REASON = 'Your role does not permit this action.';
const SIGN_IN_REASON = 'Sign in to change alerting configuration.';

function permitted(viewer: Viewer | null, permission: string): string | null {
  if (viewer === null) return SIGN_IN_REASON;
  return viewer.permissions.includes(permission) ? null : ROLE_REASON;
}

function pick<T extends string>(
  action: T,
  label: string,
  permissionReason: string | null,
  stateReason: string | null,
): AvailableAction<T> {
  const reason = permissionReason ?? stateReason;
  return { action, label, enabled: reason === null, reason };
}

export type RuleActionName = 'edit' | 'approve' | 'disable';

/** Permission first, then lifecycle: a role that cannot act learns nothing about the state rules. */
export function availableRuleActions(
  rule: Pick<AlertRule, 'status'>,
  viewer: Viewer | null,
): Array<AvailableAction<RuleActionName>> {
  return [
    pick(
      'edit',
      'Edit',
      permitted(viewer, 'alert-rules:write'),
      rule.status === 'active' ? 'Disable the rule before editing it.' : null,
    ),
    pick(
      'approve',
      'Approve',
      permitted(viewer, 'alert-rules:approve'),
      rule.status === 'active' ? 'The rule is already active.' : null,
    ),
    pick(
      'disable',
      'Disable',
      permitted(viewer, 'alert-rules:disable'),
      rule.status === 'active' ? null : 'Only an active rule can be disabled.',
    ),
  ];
}

export function canCreateRule(viewer: Viewer | null): AvailableAction<'create'> {
  return pick('create', 'New rule', permitted(viewer, 'alert-rules:write'), null);
}

export interface WindowAvailability {
  create: AvailableAction<'create'>;
  cancel: AvailableAction<'cancel'>;
  /** Whether the viewer may use organisation scope and the "disable evaluation" effect. */
  organisationScope: boolean;
}

export function availableWindowActions(
  window: Pick<MaintenanceWindow, 'status' | 'scope' | 'ends_at'>,
  viewer: Viewer | null,
  nowMs: number,
): WindowAvailability {
  const organisationScope = viewer?.permissions.includes('maintenance:write-organisation') ?? false;
  let cancelStateReason: string | null = null;
  if (window.status === 'cancelled') cancelStateReason = 'The window is already cancelled.';
  else if (Date.parse(window.ends_at) <= nowMs) cancelStateReason = 'The window has already ended.';
  else if (window.scope.kind === 'organisation' && !organisationScope) {
    cancelStateReason = 'Cancelling an organisation-wide window needs the organisation permission.';
  }
  return {
    create: pick('create', 'New window', permitted(viewer, 'maintenance:write'), null),
    cancel: pick('cancel', 'Cancel window', permitted(viewer, 'maintenance:write'), cancelStateReason),
    organisationScope,
  };
}

export function canCreateWindow(viewer: Viewer | null): WindowAvailability['create'] & {
  organisationScope: boolean;
} {
  const base = availableWindowActions(
    { status: 'scheduled', scope: { kind: 'device', ref: '' }, ends_at: '9999-12-31T00:00:00Z' },
    viewer,
    0,
  );
  return { ...base.create, organisationScope: base.organisationScope };
}

// --- request planning ------------------------------------------------------------------

export type AlertingPlan =
  | {
      ok: true;
      method: 'POST' | 'PUT';
      path: string;
      body: Record<string, unknown>;
      /** What a successful response parses as. */
      result: 'rule' | 'window';
    }
  | { ok: false; message: string };

function fail(message: string): AlertingPlan {
  return { ok: false, message };
}

function firstError(errors: FieldErrors): string {
  return Object.values(errors)[0] ?? 'The values were not valid.';
}

function expectedVersion(value: unknown): number | null {
  return typeof value === 'number' &&
    Number.isInteger(value) &&
    value >= 1 &&
    value <= MAX_RULE_VERSION
    ? value
    : null;
}

/**
 * The one API request a submission may become. Ids must match the contract patterns, form
 * values are rebuilt from scratch, and approve/update carry the version the operator reviewed.
 * (Disable and cancel take no version: the API treats them as idempotent state transitions
 * and answers 409 if the state already changed.)
 */
export function planAlertingRequest(input: unknown, nowMs: number): AlertingPlan {
  if (!isRecord(input)) return fail('The request was not well formed.');
  switch (input.action) {
    case 'rule.create': {
      const built = buildRuleDefinition(input.values);
      if (!built.ok) return fail(firstError(built.errors));
      return {
        ok: true,
        method: 'POST',
        path: '/api/v1/alert-rules',
        body: { ...built.definition },
        result: 'rule',
      };
    }
    case 'rule.update':
    case 'rule.approve': {
      if (!isAlertRuleId(input.ruleId)) return fail('The rule identifier was not valid.');
      const version = expectedVersion(input.expectedVersion);
      if (version === null) return fail('The rule version was not valid; reload and try again.');
      if (input.action === 'rule.approve') {
        return {
          ok: true,
          method: 'POST',
          path: `/api/v1/alert-rules/${input.ruleId}/approve`,
          body: { expected_version: version },
          result: 'rule',
        };
      }
      const built = buildRuleDefinition(input.values);
      if (!built.ok) return fail(firstError(built.errors));
      return {
        ok: true,
        method: 'PUT',
        path: `/api/v1/alert-rules/${input.ruleId}`,
        body: { expected_version: version, definition: { ...built.definition } },
        result: 'rule',
      };
    }
    case 'rule.disable':
      if (!isAlertRuleId(input.ruleId)) return fail('The rule identifier was not valid.');
      return {
        ok: true,
        method: 'POST',
        path: `/api/v1/alert-rules/${input.ruleId}/disable`,
        body: {},
        result: 'rule',
      };
    case 'window.create': {
      const built = buildWindowRequest(input.values, nowMs);
      if (!built.ok) return fail(firstError(built.errors));
      return {
        ok: true,
        method: 'POST',
        path: '/api/v1/maintenance-windows',
        body: { ...built.request },
        result: 'window',
      };
    }
    case 'window.cancel':
      if (!isMaintenanceWindowId(input.windowId)) return fail('The window identifier was not valid.');
      return {
        ok: true,
        method: 'POST',
        path: `/api/v1/maintenance-windows/${input.windowId}/cancel`,
        body: {},
        result: 'window',
      };
    default:
      return fail('The action is not recognised.');
  }
}
