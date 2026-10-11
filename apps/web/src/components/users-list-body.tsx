/**
 * The people list for every outcome of the read: permission, unauthenticated, error, not-connected,
 * unknown, empty, and the data itself with partial-evidence and stale notices. Nothing here reads an
 * API; it renders what the page fetched. A person is a row because evidence names them, never
 * because an address resembles them; presence is a basis ("No session evidence" is not "offline").
 * Names are untrusted source text rendered as text.
 */
import Link from 'next/link';
import { Card, Table } from '@adminlte/react';
import type { TableColumn } from '@adminlte/react';

import { DataFailure } from '@/components/data-state';
import { BasisBadge, SourceNotices } from '@/components/identity-parts';
import { Pager } from '@/components/pager';
import { StateSurface } from '@/components/state-surface';
import type { SourceStatus, UserListResponse, UserSummary } from '@/lib/api-contracts-identity';
import type { FetchState } from '@/lib/api-response';
import { formatUtcTimestamp } from '@/lib/format-time';
import { entityText, listSurface, pageHrefs } from '@/lib/identity-view';

const PRESENCE_TEXT = {
  observed: 'Current session',
  inferred: 'Possible session',
  unknown: 'No session evidence',
} as const;

const columns: TableColumn<UserSummary>[] = [
  {
    key: 'person',
    header: 'Person',
    render: (person) => (
      <Link
        className="fw-semibold"
        href={`/users/${encodeURIComponent(person.id)}`}
      >
        {entityText({ type: 'person', id: person.id, label: person.display_name })}
      </Link>
    ),
  },
  { key: 'accounts', header: 'Accounts', render: (person) => person.account_count },
  {
    key: 'assigned',
    header: 'Assigned devices',
    render: (person) => person.assigned_device_count,
  },
  { key: 'sessions', header: 'Current sessions', render: (person) => person.session_count },
  {
    key: 'presence',
    header: 'Presence',
    render: (person) => (
      <span>
        <BasisBadge basis={person.presence} />{' '}
        <span className="small text-body-secondary">{PRESENCE_TEXT[person.presence]}</span>
      </span>
    ),
  },
  {
    key: 'last',
    header: 'Last evidence',
    render: (person) =>
      person.last_evidence_at === null ? 'Not reported' : formatUtcTimestamp(person.last_evidence_at),
  },
];

function SourceLine({ sources }: { sources: readonly SourceStatus[] }) {
  if (sources.length === 0) return null;
  return (
    <p className="small text-body-secondary mt-2 mb-0">
      Evidence sources:{' '}
      {sources.map((item) => `${item.source} (${item.state.replace('-', ' ')})`).join(', ')}.
    </p>
  );
}

export function UsersListBody({
  state,
  page,
  pageSize,
}: {
  state: FetchState<UserListResponse>;
  page: number;
  pageSize: number;
}) {
  const surface = listSurface(state);
  if (state.kind !== 'ok') {
    if (surface === 'permission') {
      return (
        <StateSurface
          icon="bi bi-shield-lock"
          title="People are not available to your role"
          detail="Browsing people needs the users:read permission, which your role does not hold. Access is enforced by the Netsight API."
        />
      );
    }
    return <DataFailure state={state} />;
  }
  const { data } = state;
  if (surface === 'not-connected') {
    return (
      <div>
        <StateSurface
          icon="bi bi-plug"
          title="Identity sources not connected"
          detail="No people are shown because no evidence source is configured. This is not the same as having none, and Netsight does not guess who is on the network."
        />
        <SourceLine sources={data.sources} />
      </div>
    );
  }
  if (surface === 'unknown') {
    return (
      <div>
        <StateSurface
          icon="bi bi-question-circle"
          title="Identity state unknown"
          detail="The evidence sources are configured but could not be read. Nothing is estimated in their place."
        />
        <SourceLine sources={data.sources} />
      </div>
    );
  }
  if (surface === 'empty') {
    return (
      <div>
        <SourceNotices sources={data.sources} />
        <StateSurface
          icon="bi bi-people"
          title="No people found in the evidence"
          detail="The sources were read and name nobody in this window. That is not proof that nobody is on the network."
        />
      </div>
    );
  }
  return (
    <>
      <SourceNotices sources={data.sources} />
      <Card
        title="People known to the evidence"
        icon="bi bi-people"
        variant="outline"
        theme="primary"
        bodyClass="p-0"
        tools={
          <span className="small text-body-secondary" aria-live="polite">
            {data.total} {data.total === 1 ? 'person' : 'people'} · as of{' '}
            {formatUtcTimestamp(data.as_of)}
          </span>
        }
      >
        <p className="small text-body-secondary px-3 pt-2 mb-0">
          Evidence window {formatUtcTimestamp(data.window.from)} to {formatUtcTimestamp(data.window.to)}.
          Every person below is named by evidence; an address alone never makes a row.
        </p>
        <Table
          columns={columns}
          data={data.items}
          emptyMessage="No people"
          hover
          responsive
          rowKey={(person) => person.id}
          small
          striped
        />
        <Pager label="People pages" hrefs={pageHrefs(page, pageSize, data.total)} />
      </Card>
    </>
  );
}
