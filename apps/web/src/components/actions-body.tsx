/**
 * The action requests list for every outcome of the read: permission, unauthenticated, error,
 * not-connected, empty, filtered-empty and the data itself. Nothing here reads an API. Reasons and
 * targets are untrusted text rendered as text. Nothing is labelled "executed": a request has run
 * only when its state says so, and a dry run is labelled as one.
 */
import Link from 'next/link';
import { Table } from '@adminlte/react';
import { AppCard } from '@/components/app-card';
import type { TableColumn } from '@adminlte/react';

import { ActionStateBadge, RiskBadge } from '@/components/action-parts';
import { DataFailure } from '@/components/data-state';
import { Pager } from '@/components/pager';
import { StateSurface } from '@/components/state-surface';
import {
  actionHref,
  filterHref,
  listSurface,
  pageHrefs,
  shortId,
  statePresentation,
  type ActionsQuery,
} from '@/lib/actions-view';
import { REQUEST_STATES } from '@/lib/api-contracts-actions';
import type { ActionList, ActionRequest } from '@/lib/api-contracts-actions';
import type { FetchState } from '@/lib/api-response';
import { RelativeTime } from '@/components/relative-time';
import { formatUtcTimestamp } from '@/lib/format-time';

const columns: TableColumn<ActionRequest>[] = [
  {
    key: 'request',
    header: 'Request',
    render: (item) => (
      <div>
        <Link className="fw-semibold font-monospace" href={actionHref(item.id)}>
          {shortId(item.id)}
        </Link>
        <div className="small text-body-secondary">{item.action_type}</div>
      </div>
    ),
  },
  { key: 'target', header: 'Target', render: (item) => <span className="font-monospace text-break small">{item.target_id}</span> },
  { key: 'risk', header: 'Risk', render: (item) => <RiskBadge risk={item.risk} /> },
  { key: 'state', header: 'State', render: (item) => <ActionStateBadge state={item.state} mode={item.execution?.mode} /> },
  {
    key: 'approvals',
    header: 'Approvals',
    render: (item) => (
      <span>
        {item.approvals.length} of {item.approvals_required}
      </span>
    ),
  },
  {
    key: 'requester',
    header: 'Requested by',
    render: (item) => (
      <span className="text-break">
        {item.requester.id}
        {item.requester.kind !== 'human' ? <span className="text-body-secondary"> ({item.requester.kind})</span> : null}
      </span>
    ),
  },
  { key: 'created', header: 'Created', render: (item) => <RelativeTime className="small" value={item.created_at} /> },
];

function Chip({ href, current, children }: { href: string; current: boolean; children: React.ReactNode }) {
  return (
    <li className="list-inline-item">
      <Link
        className={`btn btn-sm ${current ? 'btn-primary' : 'btn-outline-secondary'}`}
        href={href}
        aria-current={current ? 'true' : undefined}
      >
        {children}
      </Link>
    </li>
  );
}

/** Filters as plain links: they live in the URL, need no script and are validated again server-side. */
export function ActionsFilters({ query }: { query: ActionsQuery }) {
  return (
    <nav className="mb-3" aria-label="Action request filters">
      <ul className="list-inline mb-0">
        <li className="list-inline-item small text-body-secondary">State:</li>
        <Chip href={filterHref(null)} current={query.state === null}>
          All states
        </Chip>
        {REQUEST_STATES.map((state) => (
          <Chip key={state} href={filterHref(state)} current={query.state === state}>
            {statePresentation(state).label}
          </Chip>
        ))}
      </ul>
    </nav>
  );
}

export function ActionsBody({ state, query }: { state: FetchState<ActionList>; query: ActionsQuery }) {
  const surface = listSurface(state, query);
  if (state.kind !== 'ok') {
    if (surface === 'permission') {
      return (
        <StateSurface
          icon="bi bi-shield-lock"
          title="Action requests are not available to your role"
          detail="Reading action requests needs the actions:read permission, which your role does not hold. Access is enforced by the Netsight API."
        />
      );
    }
    return <DataFailure state={state} />;
  }
  const { data } = state;
  if (surface === 'not-connected') {
    return (
      <StateSurface
        icon="bi bi-plug"
        title="The action engine is not enabled"
        detail="No requests are shown because controlled actions are off on this deployment. This is not the same as having none."
      />
    );
  }
  if (surface === 'empty') {
    return (
      <StateSurface
        icon="bi bi-inbox"
        title="No action requests"
        detail="Nothing has been proposed."
      />
    );
  }
  if (surface === 'filtered-empty') {
    return (
      <StateSurface
        icon="bi bi-funnel"
        title="No requests in this state"
        detail="Choose another state or show all states. Requests in other states may exist."
      />
    );
  }
  return (
    <AppCard
      title="Requests"
      icon="bi bi-shield-check"
      variant="outline"
      theme="primary"
      bodyClass="p-0"
      tools={
        <span className="small text-body-secondary">
          {data.total} {data.total === 1 ? 'request' : 'requests'} · as of {formatUtcTimestamp(data.generated_at)}
        </span>
      }
    >
      <Table columns={columns} data={data.items} emptyMessage="No requests" hover responsive rowKey={(item) => item.id} small striped />
      <Pager label="Action request pages" hrefs={pageHrefs(query, data.total, data.page_size)} />
    </AppCard>
  );
}
