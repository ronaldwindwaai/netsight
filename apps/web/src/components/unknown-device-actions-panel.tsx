'use client';

import { useId, useState } from 'react';

import { performFindingAction } from '@/app/(dashboard)/unknown-devices/[findingId]/actions';
import {
  AssignFindingForm,
  CommentFindingForm,
  ResolveFindingForm,
  type FindingPayload,
} from '@/components/unknown-device-action-forms';
import {
  ActionDialog,
  DisabledReason,
  StepUpMarker,
  WriteFeedback,
  useServerWrite,
} from '@/components/write-ui';
import type { FindingState } from '@/lib/api-contracts-unknown-devices';
import type { Viewer } from '@/lib/incident-actions';
import { availableFindingActions, type FindingActionName } from '@/lib/unknown-device-actions';

const DIALOG_TITLES: Partial<Record<FindingActionName, string>> = {
  assign: 'Assign finding',
  comment: 'Add a comment',
  resolve: 'Resolve or dismiss finding',
};

const BUTTON_THEME: Record<FindingActionName, string> = {
  acknowledge: 'btn-primary',
  investigate: 'btn-primary',
  assign: 'btn-outline-primary',
  comment: 'btn-outline-secondary',
  resolve: 'btn-success',
};

/**
 * Finding workflow actions. Availability comes from the permissions the API reported for the session
 * and the finding state; it only explains. The API enforces permission, state, CSRF/origin and
 * step-up on every call, and its refusal is shown if the page was stale. There is deliberately no
 * isolate or quarantine control: a quarantine is a recommendation, executed by nothing here.
 */
export function UnknownDeviceActionsPanel({
  finding,
  viewer,
  currentPath,
}: {
  finding: { id: string; state: FindingState; assignee_id: string | null; evidence_version: number };
  viewer: Viewer | null;
  currentPath: string;
}) {
  const [open, setOpen] = useState<FindingActionName | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const runner = useServerWrite(performFindingAction);
  const noteId = useId();
  const actions = availableFindingActions(finding, viewer);
  const disabledActions = actions.filter((item) => !item.enabled);

  async function run(payload: FindingPayload, label: string) {
    const accepted = await runner.submit({
      ...payload,
      findingId: finding.id,
      expectedEvidenceVersion: finding.evidence_version,
    });
    if (accepted) {
      setOpen(null);
      setNotice(`${label}: saved. The finding below has been refreshed.`);
    }
  }

  function start(action: FindingActionName, label: string) {
    setNotice(null);
    runner.reset();
    if (action === 'acknowledge' || action === 'investigate') void run({ action }, label);
    else setOpen(action);
  }

  function close() {
    if (runner.pending) return;
    setOpen(null);
    if (!runner.unconfirmed) runner.reset();
  }

  const label = open === null ? '' : (actions.find((item) => item.action === open)?.label ?? '');
  const dialogProps = {
    disabled: runner.pending,
    locked: runner.unconfirmed,
    onCancel: close,
    onSubmit: (payload: FindingPayload) => void run(payload, label),
  };

  return (
    <div>
      <div className="d-flex flex-wrap gap-2" role="group" aria-label="Finding actions">
        {actions.map((item) => (
          <button
            key={item.action}
            type="button"
            className={`btn btn-sm ${item.enabled ? BUTTON_THEME[item.action] : 'btn-outline-secondary'}`}
            disabled={!item.enabled || runner.pending || runner.unconfirmed}
            aria-describedby={item.enabled ? undefined : `${noteId}-${item.action}`}
            onClick={() => start(item.action, item.label)}
          >
            {item.label}
            {item.needsStepUp ? <StepUpMarker /> : null}
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
        {open === null ? (
          <WriteFeedback result={runner.result} currentPath={currentPath} onReload={runner.reload} />
        ) : null}
      </div>

      {open !== null ? (
        <ActionDialog title={DIALOG_TITLES[open] ?? 'Finding action'} onClose={close} busy={runner.pending}>
          {open === 'assign' ? <AssignFindingForm currentAssignee={finding.assignee_id} {...dialogProps} /> : null}
          {open === 'comment' ? <CommentFindingForm {...dialogProps} /> : null}
          {open === 'resolve' ? <ResolveFindingForm {...dialogProps} /> : null}
          <div className="mt-3" aria-live="polite">
            <WriteFeedback result={runner.result} currentPath={currentPath} onReload={runner.reload} />
          </div>
        </ActionDialog>
      ) : null}
    </div>
  );
}
