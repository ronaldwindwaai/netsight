'use client';

import type { IncidentActionName } from '@/lib/incident-actions';

/**
 * Pieces shared by the incident action forms. Each form calls `onSubmit` with a plain payload;
 * the server action rebuilds and re-validates everything, so the bounds here (`maxLength`,
 * `required`) are guidance, not the control.
 */

export type FormPayload = Record<string, unknown> & { action: IncidentActionName };

export interface FormProps {
  /** A request is in flight: every control is inert. */
  disabled: boolean;
  /**
   * The last result could not be confirmed, so sending again could repeat the change. The form
   * stays readable (the operator may copy their text) but cannot submit until the page reloads.
   */
  locked: boolean;
  onSubmit: (payload: FormPayload) => void;
  onCancel: () => void;
}

export function Footer({
  disabled,
  locked,
  onCancel,
  submitLabel,
  theme = 'primary',
}: {
  disabled: boolean;
  locked: boolean;
  onCancel: () => void;
  submitLabel: string;
  theme?: string;
}) {
  return (
    <div className="d-flex justify-content-end gap-2 mt-3">
      <button type="button" className="btn btn-outline-secondary" onClick={onCancel} disabled={disabled}>
        Cancel
      </button>
      <button type="submit" className={`btn btn-${theme}`} disabled={disabled || locked}>
        {disabled ? 'Working…' : submitLabel}
      </button>
    </div>
  );
}

/** A labelled multi-line field with the bounds the contract sets. */
export function TextAreaField({
  id,
  label,
  rows,
  maxLength,
  required = true,
  value,
  disabled,
  onChange,
}: {
  id: string;
  label: React.ReactNode;
  rows: number;
  maxLength?: number;
  required?: boolean;
  value: string;
  disabled: boolean;
  onChange: (next: string) => void;
}) {
  return (
    <div className="mb-3">
      <label className="form-label" htmlFor={id}>
        {label}
      </label>
      <textarea
        id={id}
        className="form-control"
        rows={rows}
        required={required}
        maxLength={maxLength}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        disabled={disabled}
      />
    </div>
  );
}
