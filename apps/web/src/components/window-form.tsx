'use client';

import { Field } from '@/components/rule-form';
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
      <Field id="window-name" label="Name" error={errors.name}>
        <input
          id="window-name"
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
          <Field id="window-scope-kind" label="Scope" error={errors.scopeKind}>
            <select
              id="window-scope-kind"
              className="form-select"
              value={values.scopeKind}
              onChange={(event) => set('scopeKind', event.target.value as WindowFormValues['scopeKind'])}
              disabled={disabled}
            >
              {ALERT_SCOPE_KINDS.map((kind) => (
                <option key={kind} value={kind} disabled={kind === 'organisation' && !organisationScope}>
                  {kind.replace('_', ' ')}
                  {kind === 'organisation' && !organisationScope ? ' (needs organisation permission)' : ''}
                </option>
              ))}
            </select>
          </Field>
        </div>
        <div className="col-md-8">
          <Field id="window-scope-ref" label="Scope reference" error={errors.scopeRef}>
            <input
              id="window-scope-ref"
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
        <div className="col-md-6">
          <Field id="window-starts" label="Starts (UTC)" error={errors.startsAt}>
            <input
              id="window-starts"
              className="form-control"
              type="datetime-local"
              required
              value={values.startsAt}
              onChange={(event) => set('startsAt', event.target.value)}
              disabled={disabled}
            />
          </Field>
        </div>
        <div className="col-md-6">
          <Field
            id="window-ends"
            label="Ends (UTC)"
            error={errors.endsAt}
            hint="At most 30 days long, and it may start at most one year ahead."
          >
            <input
              id="window-ends"
              className="form-control"
              type="datetime-local"
              required
              aria-describedby="window-ends-hint"
              value={values.endsAt}
              onChange={(event) => set('endsAt', event.target.value)}
              disabled={disabled}
            />
          </Field>
        </div>
      </div>
      <Field id="window-evaluation" label="Effect" error={errors.evaluation}>
        <select
          id="window-evaluation"
          className="form-select"
          value={values.evaluation}
          onChange={(event) => set('evaluation', event.target.value as WindowFormValues['evaluation'])}
          disabled={disabled}
        >
          {MAINTENANCE_EVALUATIONS.map((evaluation) => (
            <option key={evaluation} value={evaluation} disabled={evaluation === 'disable' && !organisationScope}>
              {EVALUATION_LABELS[evaluation]}
            </option>
          ))}
        </select>
      </Field>
      <Field id="window-reason" label="Reason" error={errors.reason}>
        <textarea
          id="window-reason"
          className="form-control"
          rows={3}
          required
          maxLength={1000}
          value={values.reason}
          onChange={(event) => set('reason', event.target.value)}
          disabled={disabled}
        />
      </Field>
    </>
  );
}
