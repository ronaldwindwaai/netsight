/**
 * The unknown-device findings list for every outcome of the read: permission, unauthenticated, error,
 * not-connected, unknown, empty, filtered-empty and the data itself. Nothing here reads an API. The
 * endpoint values are untrusted telemetry text rendered as text. A proposed quarantine is labelled as
 * a recommendation that was not executed.
 */
import Link from 'next/link';
import { Table } from '@adminlte/react';
import { AppCard } from '@/components/app-card';
import type { TableColumn } from '@adminlte/react';

import { DataFailure } from '@/components/data-state';
import { Pager } from '@/components/pager';
import { StateSurface, StoreStateSurface } from '@/components/state-surface';
import { FindingStateBadge, ProposedBadge, SeverityBadge } from '@/components/unknown-device-parts';
import { FINDING_STATES, SEVERITIES } from '@/lib/api-contracts-unknown-devices';
import type { Severity, UnknownDeviceFinding, UnknownDeviceList } from '@/lib/api-contracts-unknown-devices';
import type { FetchState } from '@/lib/api-response';
import { formatUtcTimestamp } from '@/lib/format-time';
import {
  filtersInUse,
  findingHref,
  listSurface,
  pageHrefs,
  severityPresentation,
  statePresentation,
  type FindingsQuery,
} from '@/lib/unknown-device-view';

const NOT_SEEN = 'Not reported';

function Mono({ value }: { value: string | null }) {
  return value === null ? (
    <span className="text-body-secondary">{NOT_SEEN}</span>
  ) : (
    <span className="font-monospace text-break">{value}</span>
  );
}

const columns: TableColumn<UnknownDeviceFinding>[] = [
  {
    key: 'endpoint',
    header: 'Endpoint',
    render: (item) => (
      <div>
        <Link className="fw-semibold font-monospace text-break" href={findingHref(item.id)}>
          {item.endpoint.mac ?? item.endpoint.ip ?? item.endpoint.hostname ?? 'Unnamed endpoint'}
        </Link>
        {item.proposed_action !== null ? (
          <div className="mt-1">
            <ProposedBadge />
          </div>
        ) : null}
      </div>
    ),
  },
  { key: 'ip', header: 'IP address', render: (item) => <Mono value={item.endpoint.ip} /> },
  { key: 'host', header: 'Hostname', render: (item) => <Mono value={item.endpoint.hostname} /> },
  { key: 'state', header: 'State', render: (item) => <FindingStateBadge state={item.state} /> },
  { key: 'severity', header: 'Severity', render: (item) => <SeverityBadge severity={item.severity} /> },
  {
    key: 'assignee',
    header: 'Assignee',
    render: (item) =>
      item.assignee_id === null ? (
        <span className="text-body-secondary">Unassigned</span>
      ) : (
        <span className="text-break">{item.assignee_id}</span>
      ),
  },
  {
    key: 'seen',
    header: 'First / last seen',
    render: (item) => (
      <div className="small">
        <div>{formatUtcTimestamp(item.first_seen_at)}</div>
        <div className="text-body-secondary">
          {formatUtcTimestamp(item.last_seen_at)} · seen {item.seen_count}×
        </div>
      </div>
    ),
  },
];

function chipHref(query: FindingsQuery, patch: Partial<FindingsQuery>): string {
  const next = { ...query, ...patch };
  const search = new URLSearchParams();
  if (next.state === null) search.set('state', 'all');
  else if (next.state !== 'open') search.set('state', next.state);
  if (next.severity !== null) search.set('severity', next.severity);
  if (next.assigned !== null) search.set('assigned', String(next.assigned));
  const rest = search.toString();
  return rest === '' ? '/unknown-devices' : `/unknown-devices?${rest}`;
}

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
export function FindingsFilters({ query }: { query: FindingsQuery }) {
  const stateChips: Array<{ key: string; label: string; value: FindingsQuery['state'] }> = [
    { key: 'open', label: 'Open', value: 'open' },
    ...FINDING_STATES.map((value) => ({ key: value, label: statePresentation(value).label, value })),
    { key: 'all', label: 'All states', value: null },
  ];
  const severities: Array<Severity | null> = [null, ...SEVERITIES];
  const assignments = [
    { label: 'Any', value: null },
    { label: 'Assigned', value: true },
    { label: 'Unassigned', value: false },
  ];
  return (
    <nav className="mb-3" aria-label="Finding filters">
      <ul className="list-inline mb-1">
        <li className="list-inline-item small text-body-secondary">State:</li>
        {stateChips.map((chip) => (
          <Chip key={chip.key} href={chipHref(query, { state: chip.value })} current={query.state === chip.value}>
            {chip.label}
          </Chip>
        ))}
      </ul>
      <ul className="list-inline mb-1">
        <li className="list-inline-item small text-body-secondary">Severity:</li>
        {severities.map((value) => (
          <Chip key={value ?? 'any'} href={chipHref(query, { severity: value })} current={query.severity === value}>
            {value === null ? 'Any severity' : severityPresentation(value).label}
          </Chip>
        ))}
      </ul>
      <ul className="list-inline mb-0">
        <li className="list-inline-item small text-body-secondary">Assignment:</li>
        {assignments.map((chip) => (
          <Chip key={chip.label} href={chipHref(query, { assigned: chip.value })} current={query.assigned === chip.value}>
            {chip.label}
          </Chip>
        ))}
        {filtersInUse(query) ? (
          <li className="list-inline-item ms-2">
            <Link href="/unknown-devices">Clear filters</Link>
          </li>
        ) : null}
      </ul>
    </nav>
  );
}

export function UnknownDevicesBody({
  state,
  query,
}: {
  state: FetchState<UnknownDeviceList>;
  query: FindingsQuery;
}) {
  const surface = listSurface(state, query);
  if (state.kind !== 'ok') {
    if (surface === 'permission') {
      return (
        <StateSurface
          icon="bi bi-shield-lock"
          title="Unknown-device findings are not available to your role"
          detail="Reading finding rows needs the unknown-devices:read permission, which your role does not hold. Access is enforced by the Netsight API."
        />
      );
    }
    return <DataFailure state={state} />;
  }
  const { data } = state;
  if (surface === 'not-connected' || surface === 'unknown') {
    return <StoreStateSurface state={surface} noun="findings" store="Finding store" />;
  }
  if (surface === 'empty') {
    return (
      <StateSurface
        icon="bi bi-check2-circle"
        title="No unknown devices are open"
        detail="Nothing has been found that NetBox does not know. That reflects the sources read at the last scan; it is not proof that no unknown device is on the network."
      />
    );
  }
  if (surface === 'filtered-empty') {
    return (
      <StateSurface
        icon="bi bi-funnel"
        title="No findings match these filters"
        detail="Adjust or clear the filters. The finding store itself is not empty of other states."
      />
    );
  }
  return (
    <AppCard
      title="Findings"
      icon="bi bi-question-diamond"
      variant="outline"
      theme="primary"
      bodyClass="p-0"
      tools={
        <span className="small text-body-secondary">
          {data.total} {data.total === 1 ? 'match' : 'matches'} · as of {formatUtcTimestamp(data.generated_at)}
        </span>
      }
    >
      <Table
        columns={columns}
        data={data.items}
        emptyMessage="No findings"
        hover
        responsive
        rowKey={(item) => item.id}
        small
        striped
      />
      <Pager label="Finding pages" hrefs={pageHrefs(query, data.total)} />
    </AppCard>
  );
}
