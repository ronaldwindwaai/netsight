'use client';

import { useState } from 'react';

import type { IncidentActionName } from '@/lib/incident-actions';

/**
 * Form bodies for the incident actions that need input. Each calls `onSubmit` with the plain
 * payload; the server action rebuilds and re-validates everything, so the bounds here
 * (`maxLength`, `required`) are guidance, not the control.
 */

export type FormPayload = Record<string, unknown> & { action: IncidentActionName };

interface FormProps {
  disabled: boolean;
  onSubmit: (payload: FormPayload) => void;
  onCancel: () => void;
}

function Footer({
  disabled,
  onCancel,
  submitLabel,
  theme = 'primary',
}: {
  disabled: boolean;
  onCancel: () => void;
  submitLabel: string;
  theme?: string;
}) {
  return (
    <div className="d-flex justify-content-end gap-2 mt-3">
      <button type="button" className="btn btn-outline-secondary" onClick={onCancel} disabled={disabled}>
        Cancel
      </button>
      <button type="submit" className={`btn btn-${theme}`} disabled={disabled}>
        {disabled ? 'Working…' : submitLabel}
      </button>
    </div>
  );
}

export function AssignForm({
  currentAssignee,
  disabled,
  onSubmit,
  onCancel,
}: FormProps & { currentAssignee: string | null }) {
  const [assignee, setAssignee] = useState('');
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit({ action: 'assign', assigneeId: assignee });
      }}
    >
      <p className="small text-body-secondary">
        Current assignee:{' '}
        {currentAssignee === null ? 'none' : <span className="text-break">{currentAssignee}</span>}
      </p>
      <label className="form-label" htmlFor="assign-identity">
        Assignee identity
      </label>
      <input
        id="assign-identity"
        className="form-control"
        type="text"
        required
        maxLength={255}
        autoComplete="off"
        spellCheck={false}
        placeholder="provider:subject, for example microsoft:…"
        value={assignee}
        onChange={(event) => setAssignee(event.target.value)}
        disabled={disabled}
      />
      <div className="form-text">
        Use the identity as Netsight records it (provider and subject), not an email address. A
        technician can only act on incidents assigned to their own identity.
      </div>
      <div className="d-flex justify-content-between align-items-center mt-3">
        {currentAssignee === null ? (
          <span />
        ) : (
          <button
            type="button"
            className="btn btn-outline-danger"
            disabled={disabled}
            onClick={() => onSubmit({ action: 'assign', assigneeId: null })}
          >
            Unassign
          </button>
        )}
        <div className="d-flex gap-2">
          <button type="button" className="btn btn-outline-secondary" onClick={onCancel} disabled={disabled}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={disabled}>
            {disabled ? 'Working…' : 'Assign'}
          </button>
        </div>
      </div>
    </form>
  );
}

export function CommentForm({ disabled, onSubmit, onCancel }: FormProps) {
  const [message, setMessage] = useState('');
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit({ action: 'comment', message });
      }}
    >
      <label className="form-label" htmlFor="comment-message">
        Comment
      </label>
      <textarea
        id="comment-message"
        className="form-control"
        rows={5}
        required
        maxLength={4000}
        value={message}
        onChange={(event) => setMessage(event.target.value)}
        disabled={disabled}
      />
      <div className="form-text">
        {message.length} / 4000. Comments are added to the append-only timeline and cannot be edited
        or removed. The text is stored and shown as plain text.
      </div>
      <Footer disabled={disabled} onCancel={onCancel} submitLabel="Add comment" />
    </form>
  );
}

export function ReopenForm({ disabled, onSubmit, onCancel }: FormProps) {
  const [reason, setReason] = useState('');
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit({ action: 'reopen', reason });
      }}
    >
      <label className="form-label" htmlFor="reopen-reason">
        Reason for reopening
      </label>
      <textarea
        id="reopen-reason"
        className="form-control"
        rows={4}
        required
        maxLength={1000}
        value={reason}
        onChange={(event) => setReason(event.target.value)}
        disabled={disabled}
      />
      <div className="form-text">
        {reason.length} / 1000. The reason is recorded on the timeline and in the audit log. The
        resolution record is removed from the incident when it reopens; the timeline keeps it.
      </div>
      <Footer disabled={disabled} onCancel={onCancel} submitLabel="Reopen incident" theme="warning" />
    </form>
  );
}

export function ResolveForm({ disabled, onSubmit, onCancel }: FormProps) {
  const [summary, setSummary] = useState('');
  const [status, setStatus] = useState<'determined' | 'not-determined'>('not-determined');
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
      <div className="mb-3">
        <label className="form-label" htmlFor="resolve-summary">
          Resolution summary
        </label>
        <textarea
          id="resolve-summary"
          className="form-control"
          rows={3}
          required
          maxLength={2000}
          value={summary}
          onChange={(event) => setSummary(event.target.value)}
          disabled={disabled}
        />
      </div>
      <fieldset className="mb-3">
        <legend className="form-label fs-6">Root cause</legend>
        <div className="form-check">
          <input
            id="resolve-cause-no"
            className="form-check-input"
            type="radio"
            name="root-cause-status"
            checked={status === 'not-determined'}
            onChange={() => setStatus('not-determined')}
            disabled={disabled}
          />
          <label className="form-check-label" htmlFor="resolve-cause-no">
            Not determined
          </label>
        </div>
        <div className="form-check">
          <input
            id="resolve-cause-yes"
            className="form-check-input"
            type="radio"
            name="root-cause-status"
            checked={status === 'determined'}
            onChange={() => setStatus('determined')}
            disabled={disabled}
          />
          <label className="form-check-label" htmlFor="resolve-cause-yes">
            Determined
          </label>
        </div>
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
          onChange={(event) => setRootCause(event.target.value)}
          required={status === 'determined'}
          disabled={disabled || status !== 'determined'}
        />
      </fieldset>
      <div className="mb-3">
        <label className="form-label" htmlFor="resolve-impact">
          Impact
        </label>
        <textarea
          id="resolve-impact"
          className="form-control"
          rows={2}
          required
          maxLength={2000}
          value={impact}
          onChange={(event) => setImpact(event.target.value)}
          disabled={disabled}
        />
      </div>
      <div className="mb-3">
        <label className="form-label" htmlFor="resolve-restored">
          Service restored at (UTC)
        </label>
        <input
          id="resolve-restored"
          className="form-control"
          type="datetime-local"
          required
          value={restoredAt}
          onChange={(event) => setRestoredAt(event.target.value)}
          disabled={disabled}
        />
        <div className="form-text">Enter the time in UTC; it cannot be in the future.</div>
      </div>
      <div className="mb-1">
        <label className="form-label" htmlFor="resolve-followups">
          Follow-up actions <span className="text-body-secondary">(optional, one per line)</span>
        </label>
        <textarea
          id="resolve-followups"
          className="form-control"
          rows={3}
          value={followUps}
          onChange={(event) => setFollowUps(event.target.value)}
          disabled={disabled}
        />
      </div>
      <p className="small text-body-secondary mt-2 mb-0">
        <i className="bi bi-shield-lock me-1" aria-hidden="true" />
        Resolving needs a recent multi-factor sign-in. If yours is too old you will be asked to sign
        in again.
      </p>
      <Footer disabled={disabled} onCancel={onCancel} submitLabel="Resolve incident" theme="success" />
    </form>
  );
}
