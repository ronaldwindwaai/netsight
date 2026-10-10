'use client';

import { useEffect, useId, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';

import { signInHref, stepUpHref } from '@/lib/sign-in-redirect';
import { describeWriteFailure } from '@/lib/write-outcome';
import type { WriteActionResult } from '@/lib/write-result';

/**
 * Shared client building blocks for write actions: a modal dialog, a hook that runs a server
 * action with a double-submit guard, and the failure account (conflict, validation, step-up ...).
 * Nothing here holds a credential: the server action attaches the session and CSRF token.
 */

const FIRST_FIELD = 'input:not([disabled]):not([type="hidden"]), textarea:not([disabled]), select:not([disabled])';

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** Escape closes an idle dialog; Tab and Shift+Tab wrap inside it and never leave a modal. */
function handleDialogKey(
  event: KeyboardEvent,
  dialog: HTMLElement,
  state: { busy: boolean; onClose: () => void },
): void {
  if (event.key === 'Escape') {
    if (state.busy) return;
    event.stopPropagation();
    state.onClose();
    return;
  }
  if (event.key !== 'Tab') return;
  const items = Array.from(dialog.querySelectorAll<HTMLElement>(FOCUSABLE));
  if (items.length === 0) {
    // Nothing to move to (every control is disabled while a write is in flight): focus stays on
    // the dialog itself rather than carrying on to the page behind it.
    event.preventDefault();
    dialog.focus();
    return;
  }
  const first = items[0];
  const last = items[items.length - 1];
  const active = document.activeElement;
  if (!dialog.contains(active)) {
    event.preventDefault();
    (event.shiftKey ? last : first).focus();
  } else if (event.shiftKey && active === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && active === last) {
    event.preventDefault();
    first.focus();
  }
}

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
  // The key handler outlives renders; it reads the latest props through this ref.
  const latest = useRef({ busy, onClose });
  useEffect(() => {
    latest.current = { busy, onClose };
  });

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    document.body.classList.add('modal-open');
    // Land on the first thing to fill in; a dialog without a field (a confirmation) takes focus itself.
    const field = dialogRef.current?.querySelector<HTMLElement>(FIRST_FIELD);
    (field ?? dialogRef.current)?.focus();
    // On the document, not the dialog: when the focused submit button is disabled mid-request the
    // browser drops focus to <body>, and keys pressed there must still reach the dialog.
    const onKeyDown = (event: KeyboardEvent) => {
      if (dialogRef.current !== null) handleDialogKey(event, dialogRef.current, latest.current);
    };
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.body.classList.remove('modal-open');
      previous?.focus?.();
    };
  }, []);

  useEffect(() => {
    // A control that was focused and became disabled (the submit button) loses focus to <body>.
    const dialog = dialogRef.current;
    if (dialog !== null && !dialog.contains(document.activeElement)) dialog.focus();
  }, [busy]);

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
  /**
   * True after a write whose outcome could not be confirmed (no usable answer). The change may
   * have been applied, so nothing more is sent until the page has been reloaded (`reload`).
   */
  unconfirmed: boolean;
  /** Resolves true when the API accepted the write; false when it was refused or not sent. */
  submit: (input: unknown) => Promise<boolean>;
  reset: () => void;
  /** Refresh the server-rendered state and lift the unconfirmed lock. */
  reload: () => void;
}

/** Runs a server action once at a time and refreshes the server-rendered page on success. */
export function useServerWrite(perform: ServerWrite): WriteRunner {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<WriteActionResult | null>(null);
  const [unconfirmed, setUnconfirmed] = useState(false);
  // Refs, not the state: two clicks in the same tick must still produce one request.
  const inFlight = useRef(false);
  const unconfirmedRef = useRef(false);

  function settle(next: WriteActionResult): void {
    setResult(next);
    if (!next.ok && next.kind === 'failed' && next.failure.category === 'unknown-result') {
      unconfirmedRef.current = true;
      setUnconfirmed(true);
    }
  }

  async function submit(input: unknown): Promise<boolean> {
    if (inFlight.current || unconfirmedRef.current) return false;
    inFlight.current = true;
    setPending(true);
    setResult(null);
    try {
      const next = await perform(input);
      settle(next);
      if (next.ok) router.refresh();
      return next.ok;
    } catch {
      settle({
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

  function reload(): void {
    unconfirmedRef.current = false;
    setUnconfirmed(false);
    setResult(null);
    router.refresh();
  }

  return { pending, result, unconfirmed, submit, reset: () => setResult(null), reload };
}

/** The account of a failed write; nothing is rendered for success or before a result. */
export function WriteFeedback({
  result,
  currentPath,
  onReload,
}: {
  result: WriteActionResult | null;
  /** Where to return after a sign-in or a step-up sign-in. */
  currentPath: string;
  /** What "Reload current state" does; defaults to refreshing the page. */
  onReload?: () => void;
}) {
  const router = useRouter();
  if (result === null || result.ok) return null;
  const reload = onReload ?? (() => router.refresh());
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
          <a className="btn btn-sm btn-primary" href={signInHref(currentPath)}>
            <i className="bi bi-box-arrow-in-right me-1" aria-hidden="true" />
            Sign in
          </a>
        ) : null}
        {failure.advice === 'reload' ? (
          <button
            type="button"
            className="btn btn-sm btn-outline-secondary"
            onClick={reload}
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

/** Marks an action that needs a recent multi-factor sign-in: readable text, decorative icon. */
export function StepUpMarker() {
  return (
    <>
      <i className="bi bi-shield-lock ms-1" aria-hidden="true" />
      <span className="visually-hidden"> (needs recent multi-factor sign-in)</span>
    </>
  );
}
