'use client';

import {
  ALERT_ACTIONS,
  ALERT_OPERATORS,
  ALERT_SCOPE_KINDS,
  BASELINE_MODES,
  INCIDENT_POLICIES,
  type AlertAction,
} from '@/lib/api-contracts-alert-rule';
import { ALERT_SEVERITIES } from '@/lib/api-contracts';
import type { FieldErrors, RuleFormValues } from '@/lib/alerting-forms';

const ACTION_LABELS: Record<AlertAction, string> = {
  create_alert: 'Create an alert',
  email: 'Send email',
  push: 'Send push notification',
};

const BASELINE_LABELS: Record<(typeof BASELINE_MODES)[number], string> = {
  none: 'No baseline (fixed threshold only)',
  'above-baseline': 'Only when above the learned baseline',
  'below-baseline': 'Only when below the learned baseline',
  'outside-baseline': 'Only when outside the learned baseline',
};

const POLICY_LABELS: Record<(typeof INCIDENT_POLICIES)[number], string> = {
  none: 'Do not open incidents',
  create: 'Open one incident per alert',
  group: 'Group related alerts into one incident',
};

function Field({
  id,
  label,
  error,
  hint,
  children,
}: {
  id: string;
  label: string;
  error?: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="mb-3">
      <label className="form-label" htmlFor={id}>
        {label}
      </label>
      {children}
      {hint ? (
        <div className="form-text" id={`${id}-hint`}>
          {hint}
        </div>
      ) : null}
      {error ? (
        <div className="invalid-feedback d-block" id={`${id}-error`} role="alert">
          {error}
        </div>
      ) : null}
    </div>
  );
}

function controlProps(id: string, error: string | undefined, hint: boolean) {
  const describedBy = [hint ? `${id}-hint` : null, error ? `${id}-error` : null]
    .filter(Boolean)
    .join(' ');
  return {
    id,
    'aria-invalid': error ? true : undefined,
    'aria-describedby': describedBy || undefined,
  } as const;
}

/**
 * The alert-rule definition as a form. Every value is held as text and rebuilt into the contract
 * body (and re-validated) before anything is sent; names, labels and patterns are operator text
 * and are only ever placed in controls and text nodes.
 */
export function RuleFormFields({
  values,
  errors,
  disabled,
  onChange,
}: {
  values: RuleFormValues;
  errors: FieldErrors;
  disabled: boolean;
  onChange: (next: RuleFormValues) => void;
}) {
  const set = <K extends keyof RuleFormValues>(key: K, value: RuleFormValues[K]) =>
    onChange({ ...values, [key]: value });
  const matches = values.operator === 'matches';

  return (
    <>
      <Field id="rule-name" label="Name" error={errors.name}>
        <input
          {...controlProps('rule-name', errors.name, false)}
          className="form-control"
          type="text"
          required
          maxLength={255}
          value={values.name}
          onChange={(event) => set('name', event.target.value)}
          disabled={disabled}
        />
      </Field>

      <div className="row g-3">
        <div className="col-md-4">
          <Field id="rule-scope-kind" label="Scope" error={errors.scopeKind}>
            <select
              {...controlProps('rule-scope-kind', errors.scopeKind, false)}
              className="form-select"
              value={values.scopeKind}
              onChange={(event) => set('scopeKind', event.target.value as RuleFormValues['scopeKind'])}
              disabled={disabled}
            >
              {ALERT_SCOPE_KINDS.map((kind) => (
                <option key={kind} value={kind}>
                  {kind.replace('_', ' ')}
                </option>
              ))}
            </select>
          </Field>
        </div>
        <div className="col-md-8">
          <Field
            id="rule-scope-ref"
            label="Scope reference"
            error={errors.scopeRef}
            hint="The device, site, group, VLAN, user or service the rule applies to. Netsight does not yet check it against inventory."
          >
            <input
              {...controlProps('rule-scope-ref', errors.scopeRef, true)}
              className="form-control"
              type="text"
              required
              maxLength={255}
              value={values.scopeRef}
              onChange={(event) => set('scopeRef', event.target.value)}
              disabled={disabled}
            />
          </Field>
        </div>
      </div>

      <div className="row g-3">
        <div className="col-md-5">
          <Field
            id="rule-metric"
            label="Metric"
            error={errors.metric}
            hint="Dotted lower-case name, for example device.status. An unsupported metric is accepted and never receives data."
          >
            <input
              {...controlProps('rule-metric', errors.metric, true)}
              className="form-control"
              type="text"
              required
              maxLength={128}
              autoComplete="off"
              spellCheck={false}
              value={values.metric}
              onChange={(event) => set('metric', event.target.value)}
              disabled={disabled}
            />
          </Field>
        </div>
        <div className="col-md-3">
          <Field id="rule-operator" label="Operator" error={errors.operator}>
            <select
              {...controlProps('rule-operator', errors.operator, false)}
              className="form-select"
              value={values.operator}
              onChange={(event) => set('operator', event.target.value as RuleFormValues['operator'])}
              disabled={disabled}
            >
              {ALERT_OPERATORS.map((operator) => (
                <option key={operator} value={operator}>
                  {operator}
                </option>
              ))}
            </select>
          </Field>
        </div>
        <div className="col-md-4">
          <Field
            id="rule-operand"
            label={matches ? 'Pattern' : 'Threshold'}
            error={errors.operand}
            hint={matches ? 'A glob such as link * down. It is matched, never executed.' : undefined}
          >
            <input
              {...controlProps('rule-operand', errors.operand, matches)}
              className="form-control"
              type="text"
              required
              inputMode={matches ? 'text' : 'decimal'}
              maxLength={256}
              autoComplete="off"
              value={values.operand}
              onChange={(event) => set('operand', event.target.value)}
              disabled={disabled}
            />
          </Field>
        </div>
      </div>

      <Field id="rule-baseline" label="Baseline" error={errors.baselineMode}>
        <select
          {...controlProps('rule-baseline', errors.baselineMode, false)}
          className="form-select"
          value={values.baselineMode}
          onChange={(event) => set('baselineMode', event.target.value as RuleFormValues['baselineMode'])}
          disabled={disabled}
        >
          {BASELINE_MODES.map((mode) => (
            <option key={mode} value={mode}>
              {BASELINE_LABELS[mode]}
            </option>
          ))}
        </select>
      </Field>

      <div className="row g-3">
        <div className="col-md-4">
          <Field id="rule-window" label="Window (seconds)" error={errors.windowSeconds} hint="60 to 86400">
            <input
              {...controlProps('rule-window', errors.windowSeconds, true)}
              className="form-control"
              type="text"
              inputMode="numeric"
              required
              value={values.windowSeconds}
              onChange={(event) => set('windowSeconds', event.target.value)}
              disabled={disabled}
            />
          </Field>
        </div>
        <div className="col-md-4">
          <Field
            id="rule-for"
            label="Must hold for (seconds)"
            error={errors.forSeconds}
            hint="0 to 86400"
          >
            <input
              {...controlProps('rule-for', errors.forSeconds, true)}
              className="form-control"
              type="text"
              inputMode="numeric"
              required
              value={values.forSeconds}
              onChange={(event) => set('forSeconds', event.target.value)}
              disabled={disabled}
            />
          </Field>
        </div>
        <div className="col-md-4">
          <Field
            id="rule-cooldown"
            label="Cooldown (seconds)"
            error={errors.cooldownSeconds}
            hint="0 to 604800"
          >
            <input
              {...controlProps('rule-cooldown', errors.cooldownSeconds, true)}
              className="form-control"
              type="text"
              inputMode="numeric"
              required
              value={values.cooldownSeconds}
              onChange={(event) => set('cooldownSeconds', event.target.value)}
              disabled={disabled}
            />
          </Field>
        </div>
      </div>

      <div className="row g-3">
        <div className="col-md-4">
          <Field id="rule-severity" label="Severity" error={errors.severity}>
            <select
              {...controlProps('rule-severity', errors.severity, false)}
              className="form-select"
              value={values.severity}
              onChange={(event) => set('severity', event.target.value as RuleFormValues['severity'])}
              disabled={disabled}
            >
              {ALERT_SEVERITIES.map((severity) => (
                <option key={severity} value={severity}>
                  {severity}
                </option>
              ))}
            </select>
          </Field>
        </div>
        <div className="col-md-8">
          <Field id="rule-policy" label="Incidents" error={errors.incidentPolicy}>
            <select
              {...controlProps('rule-policy', errors.incidentPolicy, false)}
              className="form-select"
              value={values.incidentPolicy}
              onChange={(event) =>
                set('incidentPolicy', event.target.value as RuleFormValues['incidentPolicy'])
              }
              disabled={disabled}
            >
              {INCIDENT_POLICIES.map((policy) => (
                <option key={policy} value={policy}>
                  {POLICY_LABELS[policy]}
                </option>
              ))}
            </select>
          </Field>
        </div>
      </div>

      <fieldset className="mb-3" aria-describedby={errors.actions ? 'rule-actions-error' : undefined}>
        <legend className="form-label fs-6">Actions when the rule fires</legend>
        {ALERT_ACTIONS.map((action) => (
          <div className="form-check" key={action}>
            <input
              id={`rule-action-${action}`}
              className="form-check-input"
              type="checkbox"
              checked={values.actions.includes(action)}
              onChange={(event) =>
                set(
                  'actions',
                  event.target.checked
                    ? [...values.actions, action]
                    : values.actions.filter((item) => item !== action),
                )
              }
              disabled={disabled}
            />
            <label className="form-check-label" htmlFor={`rule-action-${action}`}>
              {ACTION_LABELS[action]}
            </label>
          </div>
        ))}
        {errors.actions ? (
          <div className="invalid-feedback d-block" id="rule-actions-error" role="alert">
            {errors.actions}
          </div>
        ) : null}
      </fieldset>

      <Field
        id="rule-labels"
        label="Labels (optional)"
        error={errors.labels}
        hint="One key=value per line, for example team=network. Used for routing."
      >
        <textarea
          {...controlProps('rule-labels', errors.labels, true)}
          className="form-control"
          rows={3}
          value={values.labels}
          onChange={(event) => set('labels', event.target.value)}
          disabled={disabled}
        />
      </Field>

      <div className="row g-3">
        <div className="col-md-6">
          <Field
            id="rule-exc-destinations"
            label="Excepted destinations (optional)"
            error={errors.exceptionDestinations}
            hint="One per line."
          >
            <textarea
              {...controlProps('rule-exc-destinations', errors.exceptionDestinations, true)}
              className="form-control"
              rows={2}
              value={values.exceptionDestinations}
              onChange={(event) => set('exceptionDestinations', event.target.value)}
              disabled={disabled}
            />
          </Field>
        </div>
        <div className="col-md-6">
          <Field
            id="rule-exc-groups"
            label="Excepted device groups (optional)"
            error={errors.exceptionDeviceGroups}
            hint="One per line."
          >
            <textarea
              {...controlProps('rule-exc-groups', errors.exceptionDeviceGroups, true)}
              className="form-control"
              rows={2}
              value={values.exceptionDeviceGroups}
              onChange={(event) => set('exceptionDeviceGroups', event.target.value)}
              disabled={disabled}
            />
          </Field>
        </div>
      </div>

      <div className="row g-3">
        <div className="col-md-4">
          <Field
            id="rule-tz"
            label="Schedule timezone (optional)"
            error={errors.scheduleTimezone}
            hint="For example Europe/London or UTC. Leave both schedule fields empty for always."
          >
            <input
              {...controlProps('rule-tz', errors.scheduleTimezone, true)}
              className="form-control"
              type="text"
              maxLength={64}
              autoComplete="off"
              spellCheck={false}
              value={values.scheduleTimezone}
              onChange={(event) => set('scheduleTimezone', event.target.value)}
              disabled={disabled}
            />
          </Field>
        </div>
        <div className="col-md-8">
          <Field
            id="rule-schedule"
            label="Active periods (optional)"
            error={errors.scheduleLines}
            hint="One per line: weekdays then a 24-hour range, for example mon,tue,wed 08:00-18:00."
          >
            <textarea
              {...controlProps('rule-schedule', errors.scheduleLines, true)}
              className="form-control"
              rows={3}
              spellCheck={false}
              value={values.scheduleLines}
              onChange={(event) => set('scheduleLines', event.target.value)}
              disabled={disabled}
            />
          </Field>
        </div>
      </div>
    </>
  );
}

export { Field };
