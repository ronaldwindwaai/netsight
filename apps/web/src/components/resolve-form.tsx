'use client';

import { useState } from 'react';

import { Footer, TextAreaField } from '@/components/incident-form-parts';
import type { FormProps } from '@/components/incident-form-parts';

type RootCauseStatus = 'determined' | 'not-determined';

const STATUS_CHOICES: Array<{ value: RootCauseStatus; id: string; label: string }> = [
  { value: 'not-determined', id: 'resolve-cause-no', label: 'Not determined' },
  { value: 'determined', id: 'resolve-cause-yes', label: 'Determined' },
];

/** The root cause is a human judgement: the text is only required, and enabled, once accepted. */
function RootCauseFieldset({
  status,
  rootCause,
  disabled,
  onStatus,
  onRootCause,
}: {
  status: RootCauseStatus;
  rootCause: string;
  disabled: boolean;
  onStatus: (next: RootCauseStatus) => void;
  onRootCause: (next: string) => void;
}) {
  return (
    <fieldset className="mb-3">
      <legend className="form-label fs-6">Root cause</legend>
      {STATUS_CHOICES.map((choice) => (
        <div className="form-check" key={choice.value}>
          <input
            id={choice.id}
            className="form-check-input"
            type="radio"
            name="root-cause-status"
            checked={status === choice.value}
            onChange={() => onStatus(choice.value)}
            disabled={disabled}
          />
          <label className="form-check-label" htmlFor={choice.id}>
            {choice.label}
          </label>
        </div>
      ))}
      <label className="form-label visually-hidden" htmlFor="resolve-root-cause">
        Accepted root cause
      </label>
      <textarea
        id="resolve-root-cause"
        className="form-control mt-2"
        rows={2}
        maxLength={2000}
        placeholder="The root cause you accept"
        value={rootCause}
        onChange={(event) => onRootCause(event.target.value)}
        required={status === 'determined'}
        disabled={disabled || status !== 'determined'}
      />
    </fieldset>
  );
}

function RestoredAtField({
  value,
  disabled,
  onChange,
}: {
  value: string;
  disabled: boolean;
  onChange: (next: string) => void;
}) {
  return (
    <div className="mb-3">
      <label className="form-label" htmlFor="resolve-restored">
        Service restored at (UTC)
      </label>
      <input
        id="resolve-restored"
        className="form-control"
        type="datetime-local"
        required
        value={value}
        onChange={(event) => onChange(event.target.value)}
        disabled={disabled}
      />
      <div className="form-text">Enter the time in UTC; it cannot be in the future.</div>
    </div>
  );
}

/** Records the human resolution of an incident; resolving needs a recent multi-factor sign-in. */
export function ResolveForm({ disabled, locked, onSubmit, onCancel }: FormProps) {
  const [summary, setSummary] = useState('');
  const [status, setStatus] = useState<RootCauseStatus>('not-determined');
  const [rootCause, setRootCause] = useState('');
  const [impact, setImpact] = useState('');
  const [restoredAt, setRestoredAt] = useState('');
  const [followUps, setFollowUps] = useState('');
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit({
          action: 'resolve',
          summary,
          rootCauseStatus: status,
          rootCause,
          impact,
          restoredAt,
          followUps,
        });
      }}
    >
      <p className="small text-body-secondary">
        You are recording a human judgement. Nothing proposed by an automated system is saved as the
        root cause unless you enter it here.
      </p>
      <TextAreaField
        id="resolve-summary"
        label="Resolution summary"
        rows={3}
        maxLength={2000}
        value={summary}
        disabled={disabled}
        onChange={setSummary}
      />
      <RootCauseFieldset
        status={status}
        rootCause={rootCause}
        disabled={disabled}
        onStatus={setStatus}
        onRootCause={setRootCause}
      />
      <TextAreaField
        id="resolve-impact"
        label="Impact"
        rows={2}
        maxLength={2000}
        value={impact}
        disabled={disabled}
        onChange={setImpact}
      />
      <RestoredAtField value={restoredAt} disabled={disabled} onChange={setRestoredAt} />
      <TextAreaField
        id="resolve-followups"
        label={
          <>
            Follow-up actions <span className="text-body-secondary">(optional, one per line)</span>
          </>
        }
        rows={3}
        required={false}
        value={followUps}
        disabled={disabled}
        onChange={setFollowUps}
      />
      <p className="small text-body-secondary mt-2 mb-0">
        <i className="bi bi-shield-lock me-1" aria-hidden="true" />
        Resolving needs a recent multi-factor sign-in. If yours is too old you will be asked to sign
        in again.
      </p>
      <Footer
        disabled={disabled}
        locked={locked}
        onCancel={onCancel}
        submitLabel="Resolve incident"
        theme="success"
      />
    </form>
  );
}
