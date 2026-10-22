/**
 * Recent stored diagnostic sessions (S7 Step 4a/e): newest first, bounded and paged, each linking to
 * its read-only session page. Every state is explicit: not-connected and unknown stores, a valid
 * empty list, and permission/authentication/rate-limit/API errors. The list API reports no freshness,
 * so the page prints when it was retrieved instead of implying currency. Targets are untrusted text.
 */
import Link from 'next/link';
import { AppCard } from '@/components/app-card';

import { DataFailure } from '@/components/data-state';
import { StateSurface, StoreStateSurface } from '@/components/state-surface';
import type { FetchState } from '@/lib/api-response';
import type {
  DiagnosticSessionListResponse,
  DiagnosticSessionSummary,
} from '@/lib/api-contracts-diagnostic-session';
import { SESSION_LIST_PAGE_SIZE, sessionHref } from '@/lib/diagnostic-session-view';
import { confidenceLabel, faultDomainLabel } from '@/lib/diagnostic-view';
import { formatUtcTimestamp } from '@/lib/format-time';

function offsetHref(offset: number): string {
  return offset <= 0 ? '/diagnostics' : `/diagnostics?offset=${offset}`;
}

function Row({ row }: { row: DiagnosticSessionSummary }) {
  const href = sessionHref(row.id);
  const domain = faultDomainLabel(row.probable_fault_domain);
  return (
    <tr>
      <th scope="row" className="fw-semibold">
        {row.target}
      </th>
      <td className="small">{formatUtcTimestamp(row.completed_at)}</td>
      <td className="small">
        {domain ?? 'No probable cause'}{' '}
        <span className="badge text-bg-light border">{confidenceLabel(row.confidence)}</span>
      </td>
      <td className="text-end">
        {href !== null ? (
          <Link className="btn btn-outline-primary btn-sm" href={href}>
            Open session
            <span className="visually-hidden"> for {row.target}</span>
          </Link>
        ) : null}
      </td>
    </tr>
  );
}

function Pager({ data, offset }: { data: DiagnosticSessionListResponse; offset: number }) {
  const previous = offset > 0 ? offsetHref(offset - SESSION_LIST_PAGE_SIZE) : null;
  const next = data.next_offset === null ? null : offsetHref(data.next_offset);
  if (previous === null && next === null) return null;
  return (
    <nav className="d-flex justify-content-between p-3" aria-label="Session pages">
      {previous !== null ? (
        <Link className="btn btn-outline-secondary btn-sm" href={previous}>
          <i className="bi bi-chevron-left me-1" aria-hidden="true" />
          Previous
        </Link>
      ) : (
        <span />
      )}
      {next !== null ? (
        <Link className="btn btn-outline-secondary btn-sm" href={next}>
          Next
          <i className="bi bi-chevron-right ms-1" aria-hidden="true" />
        </Link>
      ) : null}
    </nav>
  );
}

function Body({ state, offset }: { state: FetchState<DiagnosticSessionListResponse>; offset: number }) {
  if (state.kind !== 'ok') {
    return (
      <div className="p-3">
        <DataFailure state={state} />
      </div>
    );
  }
  const { data } = state;
  if (data.state !== 'ok') {
    return (
      <StoreStateSurface
        state={data.state === 'not-connected' ? 'not-connected' : 'unknown'}
        noun="diagnostic sessions"
        store="Diagnostic session store"
      />
    );
  }
  if (data.sessions.length === 0) {
    return (
      <StateSurface
        icon="bi bi-inbox"
        title="No diagnostic sessions stored"
        detail="The store returned a valid empty page. Run a diagnostic to create one."
      />
    );
  }
  return (
    <>
      <div className="table-responsive">
        <table className="table table-sm align-middle mb-0">
          <thead>
            <tr>
              <th scope="col">Target</th>
              <th scope="col">Completed</th>
              <th scope="col">Probable cause</th>
              <th scope="col">
                <span className="visually-hidden">Open</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {data.sessions.map((row) => (
              <Row key={row.id} row={row} />
            ))}
          </tbody>
        </table>
      </div>
      <Pager data={data} offset={offset} />
    </>
  );
}

export function DiagnosticSessionList({
  state,
  offset,
  retrievedAt = new Date().toISOString(),
}: {
  state: FetchState<DiagnosticSessionListResponse>;
  offset: number;
  retrievedAt?: string;
}) {
  return (
    <AppCard
      className="operational-card mt-3"
      title="Recent sessions"
      icon="bi bi-clock-history"
      variant="outline"
      theme="secondary"
      bodyClass="p-0"
    >
      <Body state={state} offset={offset} />
      <p className="small text-body-secondary px-3 py-2 mb-0">
        Retrieved {formatUtcTimestamp(retrievedAt)}; the session API does not report a freshness
        value. Stored sessions are snapshots and cannot be changed.
      </p>
    </AppCard>
  );
}
