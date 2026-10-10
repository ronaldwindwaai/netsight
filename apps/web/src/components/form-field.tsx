'use client';

/**
 * Labelled form controls with an optional hint and error, wired for assistive technology
 * (`aria-describedby`, `aria-invalid`). Operator text is only ever placed in controls and text
 * nodes, never in markup.
 */

export function Field({
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

export function controlProps(id: string, error: string | undefined, hint: boolean) {
  const describedBy = [hint ? `${id}-hint` : null, error ? `${id}-error` : null]
    .filter(Boolean)
    .join(' ');
  return {
    id,
    'aria-invalid': error ? true : undefined,
    'aria-describedby': describedBy || undefined,
  } as const;
}

interface FieldShape {
  id: string;
  label: string;
  error?: string;
  hint?: string;
  disabled: boolean;
}

type InputExtras = Pick<
  React.InputHTMLAttributes<HTMLInputElement>,
  'type' | 'required' | 'maxLength' | 'inputMode' | 'autoComplete' | 'spellCheck'
>;

export function TextField({
  value,
  onChange,
  disabled,
  ...rest
}: FieldShape & InputExtras & { value: string; onChange: (next: string) => void }) {
  const { id, label, error, hint, ...inputProps } = rest;
  return (
    <Field id={id} label={label} error={error} hint={hint}>
      <input
        {...controlProps(id, error, hint !== undefined)}
        {...inputProps}
        className="form-control"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        disabled={disabled}
      />
    </Field>
  );
}

export function MultilineField({
  value,
  onChange,
  disabled,
  rows,
  required,
  maxLength,
  spellCheck,
  ...rest
}: FieldShape & {
  rows: number;
  required?: boolean;
  maxLength?: number;
  spellCheck?: boolean;
  value: string;
  onChange: (next: string) => void;
}) {
  const { id, label, error, hint } = rest;
  return (
    <Field id={id} label={label} error={error} hint={hint}>
      <textarea
        {...controlProps(id, error, hint !== undefined)}
        className="form-control"
        rows={rows}
        required={required}
        maxLength={maxLength}
        spellCheck={spellCheck}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        disabled={disabled}
      />
    </Field>
  );
}

export interface SelectOption<T extends string> {
  value: T;
  label: string;
  disabled?: boolean;
}

export function SelectField<T extends string>({
  value,
  options,
  onChange,
  disabled,
  ...rest
}: FieldShape & { value: T; options: Array<SelectOption<T>>; onChange: (next: T) => void }) {
  const { id, label, error, hint } = rest;
  return (
    <Field id={id} label={label} error={error} hint={hint}>
      <select
        {...controlProps(id, error, hint !== undefined)}
        className="form-select"
        value={value}
        onChange={(event) => onChange(event.target.value as T)}
        disabled={disabled}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value} disabled={option.disabled}>
            {option.label}
          </option>
        ))}
      </select>
    </Field>
  );
}
