/**
 * Every state of the /diagnostics/[id] page (S7 Step 4e), as a pure component of the fetch result so
 * the whole matrix is testable: ok, empty, partial and stale (inside the body), not-connected,
 * unknown, permission-denied, unauthenticated, not found, rate limited, source and contract errors,
 * and an invalid identifier (no request is made for it). Loading is `loading.tsx`.
 */
import Link from 'next/link';

import { DataFailure } from '@/components/data-state';
import { DiagnosticSessionBody } from '@/components/diagnostic-session-body';
import { StateSurface, StoreStateSurface } from '@/components/state-surface';
import type { FetchState } from '@/lib/api-response';
import type { DiagnosticSessionResponse } from '@/lib/api-contracts-diagnostic-session';

function Content({
  state,
  nowMs,
}: {
  state: FetchState<DiagnosticSessionResponse> | null;
  nowMs: number;
}) {
  if (state === null) {
    return (
      <StateSurface
        icon="bi bi-question-circle"
        title="Invalid session identifier"
        detail="The identifier in the address is not a diagnostic session id, so no request was made."
      />
    );
  }
  if (state.kind !== 'ok') return <DataFailure state={state} />;
  const { data } = state;
  if (data.state !== 'ok' || data.session === null) {
    return (
      <StoreStateSurface
        state={data.state === 'not-connected' ? 'not-connected' : 'unknown'}
        noun="diagnostic sessions"
        store="Diagnostic session store"
      />
    );
  }
  return <DiagnosticSessionBody session={data.session} nowMs={nowMs} />;
}

export function DiagnosticSessionPage({
  state,
  nowMs,
}: {
  state: FetchState<DiagnosticSessionResponse> | null;
  nowMs: number;
}) {
  return (
    <>
      <div className="page-intro d-flex align-items-center justify-content-between gap-3">
        <p className="text-body-secondary mb-0">
          A stored, read-only diagnostic session: a snapshot of the checks, the probable cause with
          its evidence, the explicit-topology path and the changes that may correlate. It never
          changes anything on the network, and all text below is displayed as data only.
        </p>
        <Link className="btn btn-outline-secondary btn-sm" href="/diagnostics">
          <i className="bi bi-arrow-left me-1" aria-hidden="true" />
          All diagnostics
        </Link>
      </div>
      <Content state={state} nowMs={nowMs} />
    </>
  );
}
