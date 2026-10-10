'use client';

import { useState } from 'react';

import { Footer, TextAreaField } from '@/components/incident-form-parts';
import type { FormProps } from '@/components/incident-form-parts';

/**
 * Form bodies for the incident actions that need input (resolve lives in `resolve-form.tsx`).
 * Each calls `onSubmit` with the plain payload; the server action rebuilds and re-validates it.
 */

export function AssignForm({
  currentAssignee,
  disabled,
  locked,
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

export function CommentForm({ disabled, locked, onSubmit, onCancel }: FormProps) {
  const [message, setMessage] = useState('');
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit({ action: 'comment', message });
      }}
    >
      <TextAreaField
        id="comment-message"
        label="Comment"
        rows={5}
        maxLength={4000}
        value={message}
        disabled={disabled}
        onChange={setMessage}
      />
      <div className="form-text">
        {message.length} / 4000. Comments are added to the append-only timeline and cannot be edited
        or removed. The text is stored and shown as plain text.
      </div>
      <Footer disabled={disabled} locked={locked} onCancel={onCancel} submitLabel="Add comment" />
    </form>
  );
}

export function ReopenForm({ disabled, locked, onSubmit, onCancel }: FormProps) {
  const [reason, setReason] = useState('');
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit({ action: 'reopen', reason });
      }}
    >
      <TextAreaField
        id="reopen-reason"
        label="Reason for reopening"
        rows={4}
        maxLength={1000}
        value={reason}
        disabled={disabled}
        onChange={setReason}
      />
      <div className="form-text">
        {reason.length} / 1000. The reason is recorded on the timeline and in the audit log. The
        resolution record is removed from the incident when it reopens; the timeline keeps it.
      </div>
      <Footer
        disabled={disabled}
        locked={locked}
        onCancel={onCancel}
        submitLabel="Reopen incident"
        theme="warning"
      />
    </form>
  );
}
