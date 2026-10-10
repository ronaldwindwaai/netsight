'use client';

import { MultilineField, SelectField, TextField } from '@/components/form-field';
import { ALERT_SCOPE_KINDS, MAINTENANCE_EVALUATIONS } from '@/lib/api-contracts-alert-rule';
import type { FieldErrors, WindowFormValues } from '@/lib/alerting-forms';

const EVALUATION_LABELS: Record<(typeof MAINTENANCE_EVALUATIONS)[number], string> = {
  retain: 'Keep evaluating; hold notifications until the window ends',
  disable: 'Stop evaluating rules in scope (organisation permission)',
};

/** The maintenance-window definition as a form; times are entered and read as UTC. */
export function WindowFormFields({
  values,
  errors,
  disabled,
  organisationScope,
  onChange,
}: {
  values: WindowFormValues;
  errors: FieldErrors;
  disabled: boolean;
  /** Organisation-wide scope and "stop evaluating" need the organisation permission. */
  organisationScope: boolean;
  onChange: (next: WindowFormValues) => void;
}) {
  const set = <K extends keyof WindowFormValues>(key: K, value: WindowFormValues[K]) =>
    onChange({ ...values, [key]: value });

  return (
    <>
      <TextField
        id="window-name"
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
            id="window-scope-kind"
            label="Scope"
            error={errors.scopeKind}
            value={values.scopeKind}
            options={ALERT_SCOPE_KINDS.map((kind) => {
              const restricted = kind === 'organisation' && !organisationScope;
              return {
                value: kind,
                label: `${kind.replace('_', ' ')}${restricted ? ' (needs organisation permission)' : ''}`,
                disabled: restricted,
              };
            })}
            onChange={(next) => set('scopeKind', next)}
            disabled={disabled}
          />
        </div>
        <div className="col-md-8">
          <TextField
            id="window-scope-ref"
            label="Scope reference"
            error={errors.scopeRef}
            required
            maxLength={255}
            value={values.scopeRef}
            onChange={(next) => set('scopeRef', next)}
            disabled={disabled}
          />
        </div>
      </div>
      <div className="row g-3">
        <div className="col-md-6">
          <TextField
            id="window-starts"
            label="Starts (UTC)"
            error={errors.startsAt}
            type="datetime-local"
            required
            value={values.startsAt}
            onChange={(next) => set('startsAt', next)}
            disabled={disabled}
          />
        </div>
        <div className="col-md-6">
          <TextField
            id="window-ends"
            label="Ends (UTC)"
            error={errors.endsAt}
            hint="At most 30 days long, and it may start at most one year ahead."
            type="datetime-local"
            required
            value={values.endsAt}
            onChange={(next) => set('endsAt', next)}
            disabled={disabled}
          />
        </div>
      </div>
      <SelectField
        id="window-evaluation"
        label="Effect"
        error={errors.evaluation}
        value={values.evaluation}
        options={MAINTENANCE_EVALUATIONS.map((evaluation) => ({
          value: evaluation,
          label: EVALUATION_LABELS[evaluation],
          disabled: evaluation === 'disable' && !organisationScope,
        }))}
        onChange={(next) => set('evaluation', next)}
        disabled={disabled}
      />
      <MultilineField
        id="window-reason"
        label="Reason"
        error={errors.reason}
        rows={3}
        required
        maxLength={1000}
        value={values.reason}
        onChange={(next) => set('reason', next)}
        disabled={disabled}
      />
    </>
  );
}
