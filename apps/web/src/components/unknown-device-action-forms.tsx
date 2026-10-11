'use client';

import { useState } from 'react';

import { Footer, TextAreaField } from '@/components/incident-form-parts';
import type { FindingActionName } from '@/lib/unknown-device-actions';

/**
 * Form bodies for the finding actions that need input. Each calls `onSubmit` with a plain payload;
 * the server action rebuilds and re-validates it, so the bounds here are guidance, not the control.
 */
export type FindingPayload = Record<string, unknown> & { action: FindingActionName };

export interface FindingFormProps {
  /** A request is in flight: every control is inert. */
  disabled: boolean;
  /** The last result could not be confirmed, so submitting again could repeat the change. */
  locked: boolean;
  onSubmit: (payload: FindingPayload) => void;
  onCancel: () => void;
}

export function AssignFindingForm({
  currentAssignee,
  disabled,
  locked,
  onSubmit,
  onCancel,
}: FindingFormProps & { currentAssignee: string | null }) {
  const [assignee, setAssignee] = useState('');
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit({ action: 'assign', assigneeId: assignee });
      }}
    >
      <p className="small text-body-secondary">
        Current assignee: {currentAssignee === null ? 'none' : <span className="text-break">{currentAssignee}</span>}
      </p>
      <label className="form-label" htmlFor="finding-assignee">
        Assignee identity
      </label>
      <input
        id="finding-assignee"
        className="form-control"
        type="text"
        required
        maxLength={255}
        autoComplete="off"
        spellCheck={false}
        placeholder="provider:subject"
        value={assignee}
        onChange={(event) => setAssignee(event.target.value)}
        disabled={disabled}
      />
      <div className="form-text">Use the identity as Netsight records it (provider and subject), not an email address.</div>
      <div className="d-flex justify-content-between align-items-center mt-3">
        {currentAssignee === null ? (
          <span />
        ) : (
          <button
            type="button"
            className="btn btn-outline-danger"
            disabled={disabled || locked}
            onClick={() => onSubmit({ action: 'assign', assigneeId: null })}
          >
            Unassign
          </button>
        )}
        <div className="d-flex gap-2">
          <button type="button" className="btn btn-outline-secondary" onClick={onCancel} disabled={disabled}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={disabled || locked}>
            {disabled ? 'Working…' : 'Assign'}
          </button>
        </div>
      </div>
    </form>
  );
}

export function CommentFindingForm({ disabled, locked, onSubmit, onCancel }: FindingFormProps) {
  const [message, setMessage] = useState('');
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit({ action: 'comment', message });
      }}
    >
      <TextAreaField
        id="finding-comment"
        label="Comment"
        rows={5}
        maxLength={4000}
        value={message}
        disabled={disabled}
        onChange={setMessage}
      />
      <div className="form-text">
        {message.length} / 4000. Comments join the append-only timeline and cannot be edited or removed.
        The text is stored and shown as plain text.
      </div>
      <Footer disabled={disabled} locked={locked} onCancel={onCancel} submitLabel="Add comment" />
    </form>
  );
}

type Outcome = 'resolved' | 'false-positive';
const OUTCOMES: Array<{ value: Outcome; id: string; label: string; help: string }> = [
  { value: 'resolved', id: 'finding-outcome-resolved', label: 'Resolved', help: 'The device was dealt with or added to NetBox.' },
  {
    value: 'false-positive',
    id: 'finding-outcome-false-positive',
    label: 'False positive',
    help: 'This is not an unknown device. Later sightings of the same endpoint are suppressed.',
  },
];

export function ResolveFindingForm({ disabled, locked, onSubmit, onCancel }: FindingFormProps) {
  const [outcome, setOutcome] = useState<Outcome>('resolved');
  const [reason, setReason] = useState('');
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit({ action: 'resolve', outcome, reason });
      }}
    >
      <fieldset className="mb-3">
        <legend className="form-label fs-6">Outcome</legend>
        {OUTCOMES.map((choice) => (
          <div className="form-check" key={choice.value}>
            <input
              id={choice.id}
              className="form-check-input"
              type="radio"
              name="finding-outcome"
              checked={outcome === choice.value}
              onChange={() => setOutcome(choice.value)}
              disabled={disabled}
            />
            <label className="form-check-label" htmlFor={choice.id}>
              {choice.label}
              <span className="d-block small text-body-secondary">{choice.help}</span>
            </label>
          </div>
        ))}
      </fieldset>
      <TextAreaField
        id="finding-reason"
        label="Reason"
        rows={4}
        maxLength={1000}
        value={reason}
        disabled={disabled}
        onChange={setReason}
      />
      <div className="form-text">
        {reason.length} / 1000. The reason is recorded on the timeline and in the audit log. This needs a
        recent multi-factor sign-in.
      </div>
      <Footer disabled={disabled} locked={locked} onCancel={onCancel} submitLabel="Finish finding" theme="success" />
    </form>
  );
}
