'use client';

import { ALERT_SEVERITIES, ALERT_STATES } from '@/lib/api-contracts';

const SORT_OPTIONS: readonly { value: string; label: string }[] = [
  { value: '', label: 'Source order' },
  { value: '-observed', label: 'Newest first' },
  { value: 'observed', label: 'Oldest first' },
  { value: 'severity', label: 'Severity, most severe first' },
  { value: '-severity', label: 'Severity, least severe first' },
  { value: 'state', label: 'State' },
  { value: 'title', label: 'Title A to Z' },
];

function titleCase(value: string): string {
  return value.replace(/^./, (first) => first.toUpperCase());
}

export interface AlertToolbarValues {
  readonly q: string;
  readonly severity: string;
  readonly state: string;
  /** `observed`, `-severity`, ... or an empty string for the source order. */
  readonly sort: string;
}

interface AlertToolbarProps {
  readonly values: AlertToolbarValues;
  readonly filtering: boolean;
  readonly onChange: (patch: Partial<AlertToolbarValues>) => void;
  readonly onClear: () => void;
}

function SelectField({
  id,
  label,
  value,
  onChange,
  children,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className="form-label" htmlFor={id}>
        {label}
      </label>
      <select
        className="form-select form-select-sm"
        id={id}
        onChange={(event) => onChange(event.target.value)}
        value={value}
      >
        {children}
      </select>
    </div>
  );
}

export function AlertToolbar({ values, filtering, onChange, onClear }: AlertToolbarProps) {
  return (
    <div className="border-bottom p-3 d-flex flex-wrap gap-3 align-items-end">
      <div className="flex-grow-1">
        <label className="form-label" htmlFor="alert-search">
          Filter this page
        </label>
        <input
          className="form-control form-control-sm"
          id="alert-search"
          maxLength={128}
          onChange={(event) => onChange({ q: event.target.value })}
          placeholder="Title or alert ID"
          type="search"
          value={values.q}
        />
      </div>
      <SelectField id="alert-severity" label="Severity" onChange={(severity) => onChange({ severity })} value={values.severity}>
        <option value="">All</option>
        {ALERT_SEVERITIES.map((item) => (
          <option key={item} value={item}>
            {titleCase(item)}
          </option>
        ))}
      </SelectField>
      <SelectField id="alert-state" label="State" onChange={(state) => onChange({ state })} value={values.state}>
        <option value="">All</option>
        {ALERT_STATES.map((item) => (
          <option key={item} value={item}>
            {titleCase(item)}
          </option>
        ))}
      </SelectField>
      <SelectField id="alert-sort" label="Sort" onChange={(sort) => onChange({ sort })} value={values.sort}>
        {SORT_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </SelectField>
      <button className="btn btn-sm btn-outline-secondary" disabled={!filtering} onClick={onClear} type="button">
        <i className="bi bi-x-circle me-1" aria-hidden="true" />
        Clear filters
      </button>
    </div>
  );
}
