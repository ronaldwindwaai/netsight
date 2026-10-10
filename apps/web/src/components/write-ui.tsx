'use client';

import { useEffect, useId, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';

import { stepUpHref } from '@/lib/sign-in-redirect';
import { describeWriteFailure } from '@/lib/write-outcome';
import type { WriteActionResult } from '@/lib/write-result';

/**
 * Shared client building blocks for write actions: a modal dialog, a hook that runs a server
 * action with a double-submit guard, and the failure account (conflict, validation, step-up ...).
 * Nothing here holds a credential: the server action attaches the session and CSRF token.
 */

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function ActionDialog({
  title,
  onClose,
  busy,
  children,
}: {
  title: string;
  onClose: () => void;
  /** While a request is in flight the dialog cannot be dismissed (the write may still land). */
  busy: boolean;
  children: React.ReactNode;
}) {
  const titleId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    document.body.classList.add('modal-open');
    dialogRef.current?.focus();
    return () => {
      document.body.classList.remove('modal-open');
      previous?.focus?.();
    };
  }, []);

  function onKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    if (event.key === 'Escape' && !busy) {
      event.stopPropagation();
      onClose();
      return;
    }
    if (event.key !== 'Tab' || dialogRef.current === null) return;
    const items = Array.from(dialogRef.current.querySelectorAll<HTMLElement>(FOCUSABLE));
    if (items.length === 0) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  return (
    <>
      <div className="modal-backdrop fade show" />
      <div
        className="modal fade show d-block"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        ref={dialogRef}
        onKeyDown={onKeyDown}
      >
        <div className="modal-dialog modal-lg modal-dialog-scrollable">
          <div className="modal-content">
            <div className="modal-header">
              <h2 className="modal-title h5" id={titleId}>
                {title}
              </h2>
              <button
                type="button"
                className="btn-close"
                aria-label="Close"
                onClick={onClose}
                disabled={busy}
              />
            </div>
            <div className="modal-body">{children}</div>
          </div>
        </div>
      </div>
    </>
  );
}

export type ServerWrite = (input: unknown) => Promise<WriteActionResult>;

export interface WriteRunner {
  pending: boolean;
  result: WriteActionResult | null;
  /** Resolves true when the API accepted the write. */
  submit: (input: unknown) => Promise<boolean>;
  reset: () => void;
}

/** Runs a server action once at a time and refreshes the server-rendered page on success. */
export function useServerWrite(perform: ServerWrite): WriteRunner {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<WriteActionResult | null>(null);
  // A ref, not the state: two clicks in the same tick must still produce one request.
  const inFlight = useRef(false);

  async function submit(input: unknown): Promise<boolean> {
    if (inFlight.current) return false;
    inFlight.current = true;
    setPending(true);
    setResult(null);
    try {
      const next = await perform(input);
      setResult(next);
      if (next.ok) router.refresh();
      return next.ok;
    } catch {
      setResult({
        ok: false,
        kind: 'failed',
        failure: describeWriteFailure({
          kind: 'error',
          code: 'ACTION_FAILED',
          message: '',
          correlationId: 'not-available',
          status: null,
        }),
      });
      return false;
    } finally {
      inFlight.current = false;
      setPending(false);
    }
  }

  return { pending, result, submit, reset: () => setResult(null) };
}

/** The account of a failed write; nothing is rendered for success or before a result. */
export function WriteFeedback({
  result,
  currentPath,
}: {
  result: WriteActionResult | null;
  /** Where to return after a step-up sign-in. */
  currentPath: string;
}) {
  const router = useRouter();
  if (result === null || result.ok) return null;
  if (result.kind === 'rejected') {
    return (
      <div className="alert alert-warning py-2 mb-0" role="alert">
        <i className="bi bi-exclamation-triangle me-1" aria-hidden="true" />
        {result.message}
      </div>
    );
  }
  const { failure } = result;
  return (
    <div className="alert alert-danger py-2 mb-0" role="alert">
      <p className="fw-semibold mb-1">
        <i className="bi bi-exclamation-octagon me-1" aria-hidden="true" />
        {failure.title}
      </p>
      <p className="mb-2">{failure.message}</p>
      <div className="d-flex flex-wrap gap-2 align-items-center">
        {failure.advice === 'step-up' ? (
          <a className="btn btn-sm btn-primary" href={stepUpHref(currentPath)}>
            <i className="bi bi-shield-lock me-1" aria-hidden="true" />
            Sign in again
          </a>
        ) : null}
        {failure.advice === 'sign-in' ? (
          <a className="btn btn-sm btn-primary" href="/login">
            <i className="bi bi-box-arrow-in-right me-1" aria-hidden="true" />
            Sign in
          </a>
        ) : null}
        {failure.advice === 'reload' ? (
          <button
            type="button"
            className="btn btn-sm btn-outline-secondary"
            onClick={() => router.refresh()}
          >
            <i className="bi bi-arrow-clockwise me-1" aria-hidden="true" />
            Reload current state
          </button>
        ) : null}
        <small className="text-body-secondary">
          Reference: <code>{failure.correlationId}</code>
        </small>
      </div>
      {failure.advice === 'step-up' ? (
        <p className="small mb-0 mt-2">
          Signing in again discards what you have typed here, so copy any long text first.
        </p>
      ) : null}
    </div>
  );
}

/** The reason a control is disabled, announced and linked to the control that references it. */
export function DisabledReason({ id, children }: { id: string; children: React.ReactNode }) {
  return (
    <span id={id} className="d-block small text-body-secondary">
      <i className="bi bi-lock me-1" aria-hidden="true" />
      {children}
    </span>
  );
}
