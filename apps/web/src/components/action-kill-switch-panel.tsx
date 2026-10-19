'use client';

import { useState } from 'react';

import { performKillSwitch } from '@/app/(dashboard)/actions/actions';
import { Footer, TextAreaField } from '@/components/incident-form-parts';
import { ActionDialog, StepUpMarker, WriteFeedback, useServerWrite } from '@/components/write-ui';

/**
 * Engage or release the action kill switch. Engaging is available at once (stopping must be easy);
 * releasing needs a recent multi-factor sign-in, and a switch set in the environment cannot be
 * released here at all (the API refuses and says so). Advisory only: the API decides.
 */
export function ActionKillSwitchPanel({
  engaged,
  fromEnvironment,
  currentPath,
}: {
  engaged: boolean;
  fromEnvironment: boolean;
  currentPath: string;
}) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState('');
  const [notice, setNotice] = useState<string | null>(null);
  const runner = useServerWrite(performKillSwitch);

  async function submit() {
    const accepted = await runner.submit({ engaged: !engaged, reason });
    if (accepted) {
      setOpen(false);
      setReason('');
      setNotice(engaged ? 'Kill switch released.' : 'Kill switch engaged: no action can be proposed, approved or run.');
    }
  }

  function close() {
    if (runner.pending) return;
    setOpen(false);
    if (!runner.unconfirmed) runner.reset();
  }

  const blocked = engaged && fromEnvironment;
  return (
    <div className="mb-3">
      <button
        type="button"
        className={`btn btn-sm ${engaged ? 'btn-outline-secondary' : 'btn-outline-danger'}`}
        disabled={blocked || runner.pending || runner.unconfirmed}
        aria-describedby={blocked ? 'kill-switch-env' : undefined}
        onClick={() => {
          setNotice(null);
          runner.reset();
          setOpen(true);
        }}
      >
        <i className="bi bi-sign-stop me-1" aria-hidden="true" />
        {engaged ? 'Release the kill switch' : 'Engage the kill switch'}
        {engaged ? <StepUpMarker /> : null}
      </button>
      {blocked ? (
        <span id="kill-switch-env" className="d-block small text-body-secondary mt-1">
          <i className="bi bi-lock me-1" aria-hidden="true" />
          It is set in the environment and cannot be released here.
        </span>
      ) : null}
      <div className="mt-2" aria-live="polite">
        {notice !== null ? (
          <div className="alert alert-success py-2 mb-0" role="status">
            <i className="bi bi-check-circle me-1" aria-hidden="true" />
            {notice}
          </div>
        ) : null}
        {!open ? <WriteFeedback result={runner.result} currentPath={currentPath} onReload={runner.reload} /> : null}
      </div>
      {open ? (
        <ActionDialog title={engaged ? 'Release the kill switch' : 'Engage the kill switch'} onClose={close} busy={runner.pending}>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void submit();
            }}
          >
            <p className="small">
              {engaged
                ? 'Releasing lets requests be proposed, approved and run again. It needs a recent multi-factor sign-in.'
                : 'Engaging stops every request from being proposed, approved or run, in this service process. Reading, rejecting and cancelling still work. Releasing it needs a recent multi-factor sign-in. For a stop across all workers, set it in the environment and restart.'}
            </p>
            <TextAreaField id="kill-switch-reason" label="Reason" rows={3} maxLength={500} value={reason} disabled={runner.pending} onChange={setReason} />
            <Footer
              disabled={runner.pending}
              locked={runner.unconfirmed}
              onCancel={close}
              submitLabel={engaged ? 'Release' : 'Engage'}
              theme={engaged ? 'primary' : 'danger'}
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
