'use client';

import { MultilineField, SelectField, TextField } from '@/components/form-field';
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

/** What every section of the rule form receives. */
interface SectionProps {
  values: RuleFormValues;
  errors: FieldErrors;
  disabled: boolean;
  /** Replace one field, keeping the rest of the form as it is. */
  set: <K extends keyof RuleFormValues>(key: K, value: RuleFormValues[K]) => void;
}

function IdentitySection({ values, errors, disabled, set }: SectionProps) {
  return (
    <>
      <TextField
        id="rule-name"
        label="Name"
        error={errors.name}
        required
        maxLength={255}
        value={values.name}
        onChange={(next) => set('name', next)}
        disabled={disabled}
      />
      <div className="row g-3">
        <div className="col-md-4">
          <SelectField
            id="rule-scope-kind"
            label="Scope"
            error={errors.scopeKind}
            value={values.scopeKind}
            options={ALERT_SCOPE_KINDS.map((kind) => ({ value: kind, label: kind.replace('_', ' ') }))}
            onChange={(next) => set('scopeKind', next)}
            disabled={disabled}
          />
        </div>
        <div className="col-md-8">
          <TextField
            id="rule-scope-ref"
            label="Scope reference"
            error={errors.scopeRef}
            hint="The device, site, group, VLAN, user or service the rule applies to. Netsight does not yet check it against inventory."
            required
            maxLength={255}
            value={values.scopeRef}
            onChange={(next) => set('scopeRef', next)}
            disabled={disabled}
          />
        </div>
      </div>
    </>
  );
}

function ConditionSection({ values, errors, disabled, set }: SectionProps) {
  const matches = values.operator === 'matches';
  return (
    <>
      <div className="row g-3">
        <div className="col-md-5">
          <TextField
            id="rule-metric"
            label="Metric"
            error={errors.metric}
            hint="Dotted lower-case name, for example device.status. An unsupported metric is accepted and never receives data."
            required
            maxLength={128}
            autoComplete="off"
            spellCheck={false}
            value={values.metric}
            onChange={(next) => set('metric', next)}
            disabled={disabled}
          />
        </div>
        <div className="col-md-3">
          <SelectField
            id="rule-operator"
            label="Operator"
            error={errors.operator}
            value={values.operator}
            options={ALERT_OPERATORS.map((operator) => ({ value: operator, label: operator }))}
            onChange={(next) => set('operator', next)}
            disabled={disabled}
          />
        </div>
        <div className="col-md-4">
          <TextField
            id="rule-operand"
            label={matches ? 'Pattern' : 'Threshold'}
            error={errors.operand}
            hint={matches ? 'A glob such as link * down. It is matched, never executed.' : undefined}
            required
            inputMode={matches ? 'text' : 'decimal'}
            maxLength={256}
            autoComplete="off"
            value={values.operand}
            onChange={(next) => set('operand', next)}
            disabled={disabled}
          />
        </div>
      </div>
      <SelectField
        id="rule-baseline"
        label="Baseline"
        error={errors.baselineMode}
        value={values.baselineMode}
        options={BASELINE_MODES.map((mode) => ({ value: mode, label: BASELINE_LABELS[mode] }))}
        onChange={(next) => set('baselineMode', next)}
        disabled={disabled}
      />
    </>
  );
}

function TimingSection({ values, errors, disabled, set }: SectionProps) {
  return (
    <div className="row g-3">
      <div className="col-md-4">
        <TextField
          id="rule-window"
          label="Window (seconds)"
          error={errors.windowSeconds}
          hint="60 to 86400"
          inputMode="numeric"
          required
          value={values.windowSeconds}
          onChange={(next) => set('windowSeconds', next)}
          disabled={disabled}
        />
      </div>
      <div className="col-md-4">
        <TextField
          id="rule-for"
          label="Must hold for (seconds)"
          error={errors.forSeconds}
          hint="0 to 86400"
          inputMode="numeric"
          required
          value={values.forSeconds}
          onChange={(next) => set('forSeconds', next)}
          disabled={disabled}
        />
      </div>
      <div className="col-md-4">
        <TextField
          id="rule-cooldown"
          label="Cooldown (seconds)"
          error={errors.cooldownSeconds}
          hint="0 to 604800"
          inputMode="numeric"
          required
          value={values.cooldownSeconds}
          onChange={(next) => set('cooldownSeconds', next)}
          disabled={disabled}
        />
      </div>
    </div>
  );
}

function ActionChoices({ values, errors, disabled, set }: SectionProps) {
  return (
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
  );
}

function OutcomeSection(props: SectionProps) {
  const { values, errors, disabled, set } = props;
  return (
    <>
      <div className="row g-3">
        <div className="col-md-4">
          <SelectField
            id="rule-severity"
            label="Severity"
            error={errors.severity}
            value={values.severity}
            options={ALERT_SEVERITIES.map((severity) => ({ value: severity, label: severity }))}
            onChange={(next) => set('severity', next)}
            disabled={disabled}
          />
        </div>
        <div className="col-md-8">
          <SelectField
            id="rule-policy"
            label="Incidents"
            error={errors.incidentPolicy}
            value={values.incidentPolicy}
            options={INCIDENT_POLICIES.map((policy) => ({ value: policy, label: POLICY_LABELS[policy] }))}
            onChange={(next) => set('incidentPolicy', next)}
            disabled={disabled}
          />
        </div>
      </div>
      <ActionChoices {...props} />
    </>
  );
}

function RoutingSection({ values, errors, disabled, set }: SectionProps) {
  return (
    <>
      <MultilineField
        id="rule-labels"
        label="Labels (optional)"
        error={errors.labels}
        hint="One key=value per line, for example team=network. Used for routing."
        rows={3}
        value={values.labels}
        onChange={(next) => set('labels', next)}
        disabled={disabled}
      />
      <div className="row g-3">
        <div className="col-md-6">
          <MultilineField
            id="rule-exc-destinations"
            label="Excepted destinations (optional)"
            error={errors.exceptionDestinations}
            hint="One per line."
            rows={2}
            value={values.exceptionDestinations}
            onChange={(next) => set('exceptionDestinations', next)}
            disabled={disabled}
          />
        </div>
        <div className="col-md-6">
          <MultilineField
            id="rule-exc-groups"
            label="Excepted device groups (optional)"
            error={errors.exceptionDeviceGroups}
            hint="One per line."
            rows={2}
            value={values.exceptionDeviceGroups}
            onChange={(next) => set('exceptionDeviceGroups', next)}
            disabled={disabled}
          />
        </div>
      </div>
    </>
  );
}

function ScheduleSection({ values, errors, disabled, set }: SectionProps) {
  return (
    <div className="row g-3">
      <div className="col-md-4">
        <TextField
          id="rule-tz"
          label="Schedule timezone (optional)"
          error={errors.scheduleTimezone}
          hint="For example Europe/London or UTC. Leave both schedule fields empty for always."
          maxLength={64}
          autoComplete="off"
          spellCheck={false}
          value={values.scheduleTimezone}
          onChange={(next) => set('scheduleTimezone', next)}
          disabled={disabled}
        />
      </div>
      <div className="col-md-8">
        <MultilineField
          id="rule-schedule"
          label="Active periods (optional)"
          error={errors.scheduleLines}
          hint="One per line: weekdays then a 24-hour range, for example mon,tue,wed 08:00-18:00."
          rows={3}
          spellCheck={false}
          value={values.scheduleLines}
          onChange={(next) => set('scheduleLines', next)}
          disabled={disabled}
        />
      </div>
    </div>
  );
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
  const set: SectionProps['set'] = (key, value) => onChange({ ...values, [key]: value });
  const section: SectionProps = { values, errors, disabled, set };
  return (
    <>
      <IdentitySection {...section} />
      <ConditionSection {...section} />
      <TimingSection {...section} />
      <OutcomeSection {...section} />
      <RoutingSection {...section} />
      <ScheduleSection {...section} />
    </>
  );
}
