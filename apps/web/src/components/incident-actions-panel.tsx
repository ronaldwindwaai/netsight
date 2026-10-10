'use client';

import { useId, useState } from 'react';

import { performIncidentAction } from '@/app/(dashboard)/incidents/[incidentId]/actions';
import {
  AssignForm,
  CommentForm,
  ReopenForm,
  ResolveForm,
  type FormPayload,
} from '@/components/incident-action-forms';
import { ActionDialog, DisabledReason, WriteFeedback, useServerWrite } from '@/components/write-ui';
import { availableIncidentActions } from '@/lib/incident-actions';
import type { IncidentActionName, Viewer } from '@/lib/incident-actions';
import type { IncidentState } from '@/lib/api-contracts-incident';

const DIALOG_TITLES: Partial<Record<IncidentActionName, string>> = {
  assign: 'Assign incident',
  comment: 'Add a comment',
  resolve: 'Resolve incident',
  reopen: 'Reopen incident',
};

const BUTTON_THEME: Record<IncidentActionName, string> = {
  acknowledge: 'btn-primary',
  progress: 'btn-primary',
  assign: 'btn-outline-primary',
  comment: 'btn-outline-secondary',
  resolve: 'btn-success',
  reopen: 'btn-outline-warning',
};

/** `progress` advances exactly one step; the target follows from the current state. */
function progressTarget(state: IncidentState): 'investigating' | 'mitigated' {
  return state === 'acknowledged' ? 'investigating' : 'mitigated';
}

/**
 * Incident write actions. Availability comes from the permissions the API reported for the
 * session and the incident's state; it only explains. The API enforces permission, assigned
 * scope, state, CSRF/origin and step-up on every call, and its refusal is shown if the page was
 * stale or the role changed.
 */
export function IncidentActionsPanel({
  incident,
  viewer,
  currentPath,
}: {
  incident: { id: string; state: IncidentState; assignee_id: string | null };
  viewer: Viewer | null;
  currentPath: string;
}) {
  const [open, setOpen] = useState<IncidentActionName | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const runner = useServerWrite(performIncidentAction);
  const noteId = useId();
  const actions = availableIncidentActions(incident, viewer);
  const disabledActions = actions.filter((item) => !item.enabled);

  async function run(payload: FormPayload, label: string) {
    const accepted = await runner.submit({ ...payload, incidentId: incident.id });
    if (accepted) {
      setOpen(null);
      setNotice(`${label}: saved. The incident below has been refreshed.`);
    }
  }

  function start(action: IncidentActionName, label: string) {
    setNotice(null);
    runner.reset();
    if (action === 'acknowledge') void run({ action }, label);
    else if (action === 'progress') {
      void run({ action, toState: progressTarget(incident.state) }, label);
    } else setOpen(action);
  }

  function close() {
    if (runner.pending) return;
    setOpen(null);
    runner.reset();
  }

  const label = open === null ? '' : (actions.find((item) => item.action === open)?.label ?? '');
  const dialogProps = {
    disabled: runner.pending,
    onCancel: close,
    onSubmit: (payload: FormPayload) => void run(payload, label),
  };

  return (
    <div>
      <div className="d-flex flex-wrap gap-2" role="group" aria-label="Incident actions">
        {actions.map((item) => (
          <button
            key={item.action}
            type="button"
            className={`btn btn-sm ${item.enabled ? BUTTON_THEME[item.action] : 'btn-outline-secondary'}`}
            disabled={!item.enabled || runner.pending}
            aria-disabled={!item.enabled}
            aria-describedby={item.enabled ? undefined : `${noteId}-${item.action}`}
            onClick={() => start(item.action, item.label)}
          >
            {item.label}
            {item.needsStepUp ? (
              <i className="bi bi-shield-lock ms-1" aria-label="needs recent multi-factor sign-in" />
            ) : null}
          </button>
        ))}
      </div>

      {disabledActions.length > 0 ? (
        <div className="mt-2">
          {disabledActions.map((item) => (
            <DisabledReason key={item.action} id={`${noteId}-${item.action}`}>
              <strong>{item.label}:</strong> {item.reason}
            </DisabledReason>
          ))}
        </div>
      ) : null}

      <div className="mt-2" aria-live="polite">
        {notice !== null ? (
          <div className="alert alert-success py-2 mb-0" role="status">
            <i className="bi bi-check-circle me-1" aria-hidden="true" />
            {notice}
          </div>
        ) : null}
        {open === null ? <WriteFeedback result={runner.result} currentPath={currentPath} /> : null}
      </div>

      {open !== null ? (
        <ActionDialog title={DIALOG_TITLES[open] ?? 'Incident action'} onClose={close} busy={runner.pending}>
          {open === 'assign' ? (
            <AssignForm currentAssignee={incident.assignee_id} {...dialogProps} />
          ) : null}
          {open === 'comment' ? <CommentForm {...dialogProps} /> : null}
          {open === 'resolve' ? <ResolveForm {...dialogProps} /> : null}
          {open === 'reopen' ? <ReopenForm {...dialogProps} /> : null}
          <div className="mt-3" aria-live="polite">
            <WriteFeedback result={runner.result} currentPath={currentPath} />
          </div>
        </ActionDialog>
      ) : null}
    </div>
  );
}
