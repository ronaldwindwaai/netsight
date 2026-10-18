'use client';

import { useId, useMemo, useState } from 'react';

import { performActionDecision } from '@/app/(dashboard)/actions/actions';
import { Footer, TextAreaField } from '@/components/incident-form-parts';
import { ActionDialog, DisabledReason, StepUpMarker, WriteFeedback, useServerWrite } from '@/components/write-ui';
import { decisionAvailability, describeDecisionOutcome, type DecisionVerb } from '@/lib/actions-view';
import type { ActionRequest, ActionStatus } from '@/lib/api-contracts-actions';
import type { Viewer } from '@/lib/incident-actions';

const THEME: Record<DecisionVerb, string> = {
  approve: 'btn-success',
  reject: 'btn-outline-danger',
  cancel: 'btn-outline-secondary',
  execute: 'btn-primary',
};
const TITLE: Record<DecisionVerb, string> = {
  approve: 'Approve this request',
  reject: 'Reject this request',
  cancel: 'Cancel this request',
  execute: 'Run this request',
};
const SUBMIT: Record<DecisionVerb, string> = {
  approve: 'Approve',
  reject: 'Reject',
  cancel: 'Cancel request',
  execute: 'Run',
};
const NOTICE_CLASS = {
  success: 'alert-success',
  info: 'alert-info',
  warning: 'alert-warning',
  danger: 'alert-danger',
} as const;

/**
 * Approve, reject, cancel or run (a dry run today) one request. Availability only explains; the API
 * enforces permission, the requester rule, the digest and version quoted here, step-up and the kill
 * switch. The person sees what they are deciding on before they confirm, and the digest and version
 * of that view are what is sent, so a request that changed is refused instead of approved.
 */
export function ActionDecisionPanel({
  request,
  viewer,
  status,
  currentPath,
}: {
  request: ActionRequest;
  viewer: Viewer | null;
  status: ActionStatus | null;
  currentPath: string;
}) {
  const [open, setOpen] = useState<DecisionVerb | null>(null);
  const [reason, setReason] = useState('');
  const [lastVerb, setLastVerb] = useState<DecisionVerb | null>(null);
  const runner = useServerWrite(performActionDecision);
  const noteId = useId();
  // One key per intention: the same request at the same version retries safely, a changed one does not.
  const executionKey = useMemo(() => crypto.randomUUID(), [request.id, request.version]); // eslint-disable-line react-hooks/exhaustive-deps
  const actions = decisionAvailability(request, viewer, status);
  const dryRun = status === null || status.dry_run_only;

  async function run(verb: DecisionVerb) {
    const accepted = await runner.submit({
      verb,
      actionId: request.id,
      digest: request.digest,
      version: request.version,
      ...(verb === 'reject' || verb === 'cancel' ? { reason } : {}),
      ...(verb === 'execute' ? { key: executionKey } : {}),
    });
    if (accepted) {
      setOpen(null);
      setReason('');
      setLastVerb(verb);
    }
  }

  function close() {
    if (runner.pending) return;
    setOpen(null);
    if (!runner.unconfirmed) runner.reset();
  }

  const disabledActions = actions.filter((item) => !item.enabled);
  const outcome =
    lastVerb !== null && runner.result !== null && runner.result.ok
      ? describeDecisionOutcome(lastVerb, runner.result.state, dryRun)
      : null;
  const needsReason = open === 'reject' || open === 'cancel';
  return (
    <div>
      <div className="d-flex flex-wrap gap-2" role="group" aria-label="Request decisions">
        {actions.map((item) => (
          <button
            key={item.verb}
            type="button"
            className={`btn btn-sm ${item.enabled ? THEME[item.verb] : 'btn-outline-secondary'}`}
            disabled={!item.enabled || runner.pending || runner.unconfirmed}
            aria-describedby={item.enabled ? undefined : `${noteId}-${item.verb}`}
            onClick={() => {
              setLastVerb(null);
              runner.reset();
              setOpen(item.verb);
            }}
          >
            {item.label}
            {item.needsStepUp ? <StepUpMarker /> : null}
          </button>
        ))}
      </div>
      {disabledActions.length > 0 ? (
        <div className="mt-2">
          {disabledActions.map((item) => (
            <DisabledReason key={item.verb} id={`${noteId}-${item.verb}`}>
              <strong>{item.label}:</strong> {item.reason}
            </DisabledReason>
          ))}
        </div>
      ) : null}
      <div className="mt-2" aria-live="polite">
        {outcome !== null ? (
          <div
            className={`alert ${NOTICE_CLASS[outcome.tone]} py-2 mb-0`}
            role={outcome.tone === 'danger' || outcome.tone === 'warning' ? 'alert' : 'status'}
          >
            <i className="bi bi-info-circle me-1" aria-hidden="true" />
            {outcome.text} The request below has been refreshed.
          </div>
        ) : null}
        {open === null ? <WriteFeedback result={runner.result} currentPath={currentPath} onReload={runner.reload} /> : null}
      </div>
      {open !== null ? (
        <ActionDialog title={TITLE[open]} onClose={close} busy={runner.pending}>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void run(open);
            }}
          >
            <dl className="small">
              <dt>You are deciding on</dt>
              <dd className="mb-1">
                {request.action_type} → <span className="font-monospace text-break">{request.target_id}</span>
              </dd>
              <dd className="mb-1 text-break">“{request.reason}”</dd>
              <dd className="mb-0 text-body-secondary">
                Version {request.version}, digest <code className="text-break">{request.digest}</code>. If the request
                has changed since you opened this page, the decision is refused.
              </dd>
            </dl>
            {open === 'execute' && dryRun ? (
              <p className="small">
                This is a <strong>dry run</strong>: it records what would happen. It does not contact or change any
                device or network system.
              </p>
            ) : null}
            {open === 'approve' ? (
              <p className="small">
                You are not the person who made this request. Approving needs a recent multi-factor sign-in
                {request.approvals_required > 1
                  ? `, and ${request.approvals_required} different approvers are required`
                  : ''}
                .
              </p>
            ) : null}
            {needsReason ? (
              <TextAreaField
                id="action-reason"
                label="Reason"
                rows={4}
                maxLength={500}
                value={reason}
                disabled={runner.pending}
                onChange={setReason}
              />
            ) : null}
            <Footer
              disabled={runner.pending}
              locked={runner.unconfirmed}
              onCancel={close}
              submitLabel={open === 'execute' && dryRun ? 'Record dry run' : SUBMIT[open]}
              theme={open === 'approve' ? 'success' : open === 'reject' ? 'danger' : 'primary'}
            />
          </form>
          <div className="mt-3" aria-live="polite">
            <WriteFeedback result={runner.result} currentPath={currentPath} onReload={runner.reload} />
          </div>
        </ActionDialog>
      ) : null}
    </div>
  );
}
