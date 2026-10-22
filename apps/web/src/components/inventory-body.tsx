/**
 * The inventory list for every outcome of the read: permission, unauthenticated, error, not-connected,
 * unknown, empty, filtered-empty and the data itself (with a notice for every source that was not
 * read). Nothing here reads an API; it renders what the page fetched. NetBox is the authority for
 * intended state: without it there are no rows and no counts, and the page says so. Every name, role
 * and site is untrusted source text rendered as text.
 */
import Link from 'next/link';
import { Table } from '@adminlte/react';
import { AppCard } from '@/components/app-card';
import type { TableColumn } from '@adminlte/react';

import { DataFailure } from '@/components/data-state';
import { ClassBadge, FieldValue, ProvenanceBadge, ReconcileBadge } from '@/components/inventory-parts';
import { Pager } from '@/components/pager';
import { SourceLine, SourceNotices } from '@/components/source-notices';
import { StateSurface, StoreStateSurface } from '@/components/state-surface';
import { StatusBadge } from '@/components/status-badge';
import type { InventoryItem, InventoryList } from '@/lib/api-contracts-inventory';
import type { FetchState } from '@/lib/api-response';
import { formatUtcTimestamp } from '@/lib/format-time';
import {
  NOT_REPORTED,
  itemHref,
  listSurface,
  pageHrefs,
  type InventoryQuery,
} from '@/lib/inventory-view';

const columns: TableColumn<InventoryItem>[] = [
  {
    key: 'name',
    header: 'Asset',
    render: (item) => (
      <div>
        <Link className="fw-semibold text-break" href={itemHref(item.id)}>
          {item.name.value}
        </Link>{' '}
        <ProvenanceBadge provenance={item.name.provenance} />
        {item.name.provenance === 'conflict' ? (
          <div className="small text-body-secondary">
            NetBox: <span className="text-break">{item.name.netbox}</span> · Telemetry:{' '}
            <span className="text-break">{item.name.discovered}</span>
          </div>
        ) : null}
      </div>
    ),
  },
  {
    key: 'class',
    header: 'Class',
    render: (item) => <ClassBadge value={item.asset_class} />,
  },
  { key: 'site', header: 'Site', render: (item) => <FieldValue field={item.site} /> },
  { key: 'ip', header: 'IP address', render: (item) => <FieldValue field={item.ip_address} mono /> },
  { key: 'mac', header: 'MAC address', render: (item) => <FieldValue field={item.mac_address} mono /> },
  {
    key: 'status',
    header: 'Status',
    render: (item) => (
      <div>
        <div className="small">
          <span className="text-body-secondary">Intended: </span>
          {item.intended_status ?? NOT_REPORTED}
        </div>
        <div className="small">
          <span className="text-body-secondary">Observed: </span>
          {item.observed_status === null ? NOT_REPORTED : <StatusBadge status={item.observed_status} />}
        </div>
      </div>
    ),
  },
  { key: 'reconcile', header: 'Reconciliation', render: (item) => <ReconcileBadge status={item.reconcile.status} /> },
];

function Summary({ data }: { data: InventoryList }) {
  const summary = data.summary;
  if (summary === null) return null;
  return (
    <p className="small text-body-secondary mb-2" aria-live="polite">
      {summary.total} {summary.total === 1 ? 'asset' : 'assets'} in the inventory: {summary.known} in NetBox,{' '}
      {summary.unknown} seen by telemetry only. As of {formatUtcTimestamp(data.generated_at)}.
    </p>
  );
}

export function InventoryBody({
  state,
  query,
}: {
  state: FetchState<InventoryList>;
  query: InventoryQuery;
}) {
  const surface = listSurface(state, query);
  if (state.kind !== 'ok') {
    if (surface === 'permission') {
      return (
        <StateSurface
          icon="bi bi-shield-lock"
          title="The inventory is not available to your role"
          detail="Reading asset rows needs the inventory:read permission, which your role does not hold. Access is enforced by the Netsight API."
        />
      );
    }
    return <DataFailure state={state} />;
  }
  const { data } = state;
  if (surface === 'not-connected' || surface === 'unknown') {
    return (
      <div>
        <StoreStateSurface state={surface} noun="assets" store="NetBox" />
        <SourceLine sources={data.sources} formatTime={formatUtcTimestamp} />
      </div>
    );
  }
  if (surface === 'empty') {
    return (
      <div>
        <SourceNotices sources={data.sources} />
        <StateSurface
          icon="bi bi-boxes"
          title="NetBox and discovery list no assets"
          detail="The sources were read and report nothing. That is not proof that nothing is on the network."
        />
      </div>
    );
  }
  if (surface === 'filtered-empty') {
    return (
      <div>
        <SourceNotices sources={data.sources} />
        <StateSurface
          icon="bi bi-funnel"
          title="No assets match these filters"
          detail="Adjust or clear the filters. The inventory itself is not empty."
        />
      </div>
    );
  }
  return (
    <>
      <SourceNotices sources={data.sources} />
      <AppCard
        title="Assets"
        icon="bi bi-boxes"
        variant="outline"
        theme="primary"
        bodyClass="p-0"
        tools={
          <span className="small text-body-secondary">
            {data.total} {data.total === 1 ? 'match' : 'matches'}
          </span>
        }
      >
        <div className="px-3 pt-2">
          <Summary data={data} />
        </div>
        <Table
          columns={columns}
          data={data.items}
          emptyMessage="No assets"
          hover
          responsive
          rowKey={(item) => item.id}
          small
          striped
        />
        <Pager label="Inventory pages" hrefs={pageHrefs(query, data.total)} />
        <div className="px-3 pb-2">
          <SourceLine sources={data.sources} formatTime={formatUtcTimestamp} />
        </div>
      </AppCard>
    </>
  );
}
