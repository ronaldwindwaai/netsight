'use client';

import Link from 'next/link';
import { useMemo, useState } from 'react';

import { proposeActionFromFinding } from '@/app/(dashboard)/actions/actions';
import { Footer, TextAreaField } from '@/components/incident-form-parts';
import { ActionDialog, WriteFeedback, useServerWrite } from '@/components/write-ui';
import { actionHref } from '@/lib/actions-view';

/**
 * "Create an action request" for a finding that carries a quarantine proposal. This only creates a
 * request that waits for a different person to approve it; nothing is isolated, and the page says so.
 * Shown only to a viewer who may propose a high-risk action (advisory: the API decides).
 */
export function ProposeActionPanel({
  findingId,
  evidenceVersion,
  currentPath,
}: {
  findingId: string;
  evidenceVersion: number;
  currentPath: string;
}) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState('');
  const runner = useServerWrite(proposeActionFromFinding);
  // One key per finding version: a double submit or a retry returns the same request, not a second one.
  const key = useMemo(() => crypto.randomUUID(), [findingId, evidenceVersion]); // eslint-disable-line react-hooks/exhaustive-deps

  async function submit() {
    const accepted = await runner.submit({ findingId, evidenceVersion, reason, key });
    if (accepted) setOpen(false);
  }

  function close() {
    if (runner.pending) return;
    setOpen(false);
    if (!runner.unconfirmed) runner.reset();
  }

  const created = runner.result !== null && runner.result.ok;
  const createdId = runner.result !== null && runner.result.ok ? (runner.result.id ?? null) : null;
  return (
    <div className="mt-3">
      <button
        type="button"
        className="btn btn-sm btn-outline-primary"
        disabled={runner.pending || runner.unconfirmed || created}
        onClick={() => {
          runner.reset();
          setOpen(true);
        }}
      >
        <i className="bi bi-shield-check me-1" aria-hidden="true" />
        Create an action request
      </button>
      <span className="d-block small text-body-secondary mt-1">
        This only proposes the quarantine for approval by a different person. Nothing is isolated, and nothing in
        this release can isolate a device.
      </span>
      <div className="mt-2" aria-live="polite">
        {created ? (
          <div className="alert alert-success py-2 mb-0" role="status">
            <i className="bi bi-check-circle me-1" aria-hidden="true" />
            Action request created and waiting for approval.{' '}
            {createdId !== null ? <Link href={actionHref(createdId)}>Open the request</Link> : <Link href="/actions">Open action requests</Link>}
          </div>
        ) : null}
        {!open ? <WriteFeedback result={runner.result} currentPath={currentPath} onReload={runner.reload} /> : null}
      </div>
      {open ? (
        <ActionDialog title="Create an action request" onClose={close} busy={runner.pending}>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void submit();
            }}
          >
            <p className="small">
              Proposes isolating this endpoint for the default duration. It is created in the state “awaiting
              approval”. If the finding&apos;s evidence changes before it is approved or run, it is refused.
            </p>
            <TextAreaField id="propose-reason" label="Reason" rows={4} maxLength={500} value={reason} disabled={runner.pending} onChange={setReason} />
            <Footer disabled={runner.pending} locked={runner.unconfirmed} onCancel={close} submitLabel="Create request" />
          </form>
          <div className="mt-3" aria-live="polite">
            <WriteFeedback result={runner.result} currentPath={currentPath} onReload={runner.reload} />
          </div>
        </ActionDialog>
      ) : null}
    </div>
  );
}
