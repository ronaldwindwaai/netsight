/**
 * IPAM for every outcome of each of its reads. The three lists (prefixes, VLANs, addresses) answer
 * independently, so a prefix list that could not be read leaves the VLANs visible. Utilisation is always
 * shown with its basis and as text as well as a bar; "unknown" is never drawn as empty. An address is
 * active, stale, unknown or reserved with the reason, and stale is only claimed when telemetry was
 * readable. All names, descriptions and addresses are untrusted source text rendered as text.
 */
import Link from 'next/link';
import { Badge, Table } from '@adminlte/react';
import { AppCard } from '@/components/app-card';
import type { TableColumn } from '@adminlte/react';
import type { ReactNode } from 'react';

import { DataFailure } from '@/components/data-state';
import { Pager } from '@/components/pager';
import { SourceNotices } from '@/components/source-notices';
import { StateSurface, StoreStateSurface } from '@/components/state-surface';
import type {
  IpamAddress,
  IpamAddressList,
  IpamPrefix,
  IpamPrefixList,
  IpamVlan,
  IpamVlanList,
} from '@/lib/api-contracts-ipam';
import { ACTIVITIES } from '@/lib/api-contracts-ipam';
import type { FetchState } from '@/lib/api-response';
import { formatUtcTimestamp } from '@/lib/format-time';
import { NOT_REPORTED, sourceLabel } from '@/lib/inventory-view';
import {
  DEFAULT_PAGE_SIZE,
  activityPresentation,
  basisShort,
  basisText,
  ipamHref,
  telemetryNotice,
  utilisationBarPercent,
  utilisationText,
  type IpamQuery,
} from '@/lib/ipam-view';

type ListState = 'ok' | 'not-connected' | 'unknown';

function FailureOrSurface<T extends { state: ListState }>({
  state,
  noun,
  permission,
  children,
}: {
  state: FetchState<T>;
  noun: string;
  permission: string;
  children: (data: T) => ReactNode;
}) {
  if (state.kind !== 'ok') {
    if (state.kind === 'forbidden') {
      return (
        <StateSurface
          icon="bi bi-shield-lock"
          title={`${noun} are not available to your role`}
          detail={`Reading ${noun.toLowerCase()} needs the ${permission} permission, which your role does not hold. Access is enforced by the Netsight API.`}
        />
      );
    }
    return <DataFailure state={state} />;
  }
  if (state.data.state !== 'ok') {
    return <StoreStateSurface state={state.data.state} noun={noun.toLowerCase()} store="NetBox" />;
  }
  return <>{children(state.data)}</>;
}

// --- prefixes ---------------------------------------------------------------------------------------------

function UtilisationCell({ prefix }: { prefix: IpamPrefix }) {
  const u = prefix.utilisation;
  const bar = utilisationBarPercent(u);
  return (
    <div style={{ minWidth: '11rem' }}>
      <div className="small">{utilisationText(u)}</div>
      {bar !== null ? (
        <div
          className="progress"
          role="progressbar"
          aria-label={`Utilisation of ${prefix.prefix}`}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={bar}
          style={{ height: '0.4rem' }}
        >
          <div className="progress-bar" style={{ width: `${bar}%` }} />
        </div>
      ) : null}
      <div className="small text-body-secondary" title={basisText(u.basis)}>
        Basis: {basisShort(u.basis)}
      </div>
      {u.reserved !== null && u.reserved > 0 ? (
        <div className="small text-body-secondary">{u.reserved} reserved, {u.free ?? NOT_REPORTED} free</div>
      ) : null}
    </div>
  );
}

function PrefixName({ prefix }: { prefix: IpamPrefix }) {
  return (
    <div style={{ paddingLeft: `${prefix.depth * 1.25}rem` }}>
      <span className="visually-hidden">Level {prefix.depth + 1}: </span>
      {prefix.depth > 0 ? <i className="bi bi-arrow-return-right me-1 text-body-secondary" aria-hidden="true" /> : null}
      <span className="fw-semibold font-monospace text-break">{prefix.prefix}</span>
      {prefix.vrf !== null ? <span className="small text-body-secondary"> · VRF {prefix.vrf}</span> : null}
      {prefix.description !== null ? <div className="small text-body-secondary text-break">{prefix.description}</div> : null}
      {prefix.reserved_ranges_total > 0 ? (
        <details className="small">
          <summary>
            {prefix.reserved_ranges_total} reserved {prefix.reserved_ranges_total === 1 ? 'range' : 'ranges'}
          </summary>
          <ul className="mb-0">
            {prefix.reserved_ranges.map((range) => (
              <li key={`${range.start}-${range.end}`} className="font-monospace">
                {range.start} – {range.end} ({range.size})
              </li>
            ))}
            {prefix.reserved_ranges_total > prefix.reserved_ranges.length ? (
              <li>and {prefix.reserved_ranges_total - prefix.reserved_ranges.length} more</li>
            ) : null}
          </ul>
        </details>
      ) : null}
    </div>
  );
}

const prefixColumns: TableColumn<IpamPrefix>[] = [
  { key: 'prefix', header: 'Prefix', render: (prefix) => <PrefixName prefix={prefix} /> },
  { key: 'utilisation', header: 'Utilisation', render: (prefix) => <UtilisationCell prefix={prefix} /> },
  { key: 'status', header: 'Status', render: (prefix) => prefix.status ?? NOT_REPORTED },
  { key: 'site', header: 'Site', render: (prefix) => <span className="text-break">{prefix.site ?? NOT_REPORTED}</span> },
  {
    key: 'vlan',
    header: 'VLAN',
    render: (prefix) =>
      prefix.vlan === null ? (
        <span className="text-body-secondary">None named</span>
      ) : (
        <span className="text-break">
          {prefix.vlan.vid} · {prefix.vlan.name}
        </span>
      ),
  },
  { key: 'role', header: 'Role', render: (prefix) => <span className="text-break">{prefix.role ?? NOT_REPORTED}</span> },
];

export function IpamPrefixesCard({ state, query }: { state: FetchState<IpamPrefixList>; query: IpamQuery }) {
  return (
    <section aria-labelledby="ipam-prefixes">
      <h2 className="h5" id="ipam-prefixes">
        Prefixes
      </h2>
      <FailureOrSurface state={state} noun="Prefixes" permission="ipam:read">
        {(data) =>
          data.total === 0 ? (
            <StateSurface
              icon="bi bi-diagram-2"
              title={query.family === null ? 'NetBox lists no prefixes' : 'No prefixes match this filter'}
              detail="The read succeeded and returned nothing. That is not the same as the source being unavailable."
            />
          ) : (
            <>
              <SourceNotices sources={data.sources} />
              <AppCard variant="outline" theme="primary" bodyClass="p-0">
                <div className="d-flex flex-wrap gap-2 p-3 pb-0" role="group" aria-label="Address family">
                  <Link aria-current={query.family === null ? 'true' : undefined} className={`btn btn-sm ${query.family === null ? 'btn-primary' : 'btn-outline-secondary'}`} href={ipamHref(query, { family: null, prefixesPage: 1 })}>
                    All
                  </Link>
                  <Link aria-current={query.family === '4' ? 'true' : undefined} className={`btn btn-sm ${query.family === '4' ? 'btn-primary' : 'btn-outline-secondary'}`} href={ipamHref(query, { family: '4', prefixesPage: 1 })}>
                    IPv4
                  </Link>
                  <Link aria-current={query.family === '6' ? 'true' : undefined} className={`btn btn-sm ${query.family === '6' ? 'btn-primary' : 'btn-outline-secondary'}`} href={ipamHref(query, { family: '6', prefixesPage: 1 })}>
                    IPv6
                  </Link>
                </div>
                <Table columns={prefixColumns} data={data.items} emptyMessage="No prefixes" hover responsive rowKey={(p) => p.id} small />
                <Pager label="Prefix pages" hrefs={pageLinks(data.total, query.prefixesPage, (page) => ipamHref(query, { prefixesPage: page }))} />
              </AppCard>
            </>
          )
        }
      </FailureOrSurface>
    </section>
  );
}

function pageLinks(total: number, page: number, href: (page: number) => string) {
  const last = Math.max(1, Math.ceil(total / DEFAULT_PAGE_SIZE));
  return { previous: page > 1 ? href(page - 1) : null, next: page < last ? href(page + 1) : null };
}

// --- VLANs --------------------------------------------------------------------------------------------------

const vlanColumns: TableColumn<IpamVlan>[] = [
  { key: 'vid', header: 'VLAN', render: (v) => <span className="font-monospace">{v.vid}</span> },
  { key: 'name', header: 'Name', render: (v) => <span className="text-break fw-semibold">{v.name}</span> },
  { key: 'site', header: 'Site', render: (v) => <span className="text-break">{v.site ?? NOT_REPORTED}</span> },
  { key: 'group', header: 'Group', render: (v) => <span className="text-break">{v.group ?? NOT_REPORTED}</span> },
  { key: 'status', header: 'Status', render: (v) => v.status ?? NOT_REPORTED },
  { key: 'prefixes', header: 'Prefixes naming it', render: (v) => (v.prefix_count === null ? NOT_REPORTED : v.prefix_count) },
];

export function IpamVlansCard({ state, query }: { state: FetchState<IpamVlanList>; query: IpamQuery }) {
  return (
    <section aria-labelledby="ipam-vlans">
      <h2 className="h5 mt-4" id="ipam-vlans">
        VLANs
      </h2>
      <FailureOrSurface state={state} noun="VLANs" permission="ipam:read">
        {(data) =>
          data.total === 0 ? (
            <StateSurface icon="bi bi-ethernet" title="NetBox lists no VLANs" detail="The read succeeded and returned nothing." />
          ) : (
            <AppCard variant="outline" theme="primary" bodyClass="p-0">
              <Table columns={vlanColumns} data={data.items} emptyMessage="No VLANs" hover responsive rowKey={(v) => v.id} small striped />
              <Pager label="VLAN pages" hrefs={pageLinks(data.total, query.vlansPage, (page) => ipamHref(query, { vlansPage: page }))} />
            </AppCard>
          )
        }
      </FailureOrSurface>
    </section>
  );
}

// --- addresses ----------------------------------------------------------------------------------------------

function ActivityBadge({ address }: { address: IpamAddress }) {
  const view = activityPresentation(address.activity);
  return (
    <span title={view.explanation}>
      <Badge theme={view.theme} pill>
        <i className={`bi ${view.icon} me-1`} aria-hidden="true" />
        {view.label}
      </Badge>
    </span>
  );
}

const addressColumns: TableColumn<IpamAddress>[] = [
  { key: 'address', header: 'Address', render: (a) => <span className="font-monospace text-break">{a.address}</span> },
  { key: 'activity', header: 'Activity', render: (a) => <ActivityBadge address={a} /> },
  {
    key: 'seen',
    header: 'Seen by',
    render: (a) =>
      a.seen_by.length === 0 ? (
        <span className="text-body-secondary">Not seen</span>
      ) : (
        <span>
          {a.seen_by.map((s) => sourceLabel(s)).join(', ')}
          {a.last_seen !== null ? <span className="small text-body-secondary"> · {formatUtcTimestamp(a.last_seen)}</span> : null}
        </span>
      ),
  },
  { key: 'source', header: 'In', render: (a) => (a.source === 'both' ? 'NetBox and telemetry' : a.source === 'netbox' ? 'NetBox only' : 'Telemetry only') },
  { key: 'status', header: 'NetBox status', render: (a) => a.status ?? NOT_REPORTED },
  { key: 'dns', header: 'DNS name', render: (a) => <span className="text-break">{a.dns_name ?? NOT_REPORTED}</span> },
];

export function IpamAddressesCard({ state, query }: { state: FetchState<IpamAddressList>; query: IpamQuery }) {
  return (
    <section aria-labelledby="ipam-addresses">
      <h2 className="h5 mt-4" id="ipam-addresses">
        IP usage
      </h2>
      <FailureOrSurface state={state} noun="Addresses" permission="ipam:read">
        {(data) => {
          const notice = telemetryNotice(data.telemetry);
          const counts = data.activity_counts;
          return (
            <>
              <SourceNotices sources={data.sources} />
              <div className={`alert ${notice.judged ? 'alert-info' : 'alert-warning'} py-2`} role="status">
                <i className="bi bi-info-circle me-1" aria-hidden="true" />
                {notice.text}
              </div>
              <div className="d-flex flex-wrap gap-2 mb-2" role="group" aria-label="Filter by activity">
                <Link aria-current={query.activity === null ? 'true' : undefined} className={`btn btn-sm ${query.activity === null ? 'btn-primary' : 'btn-outline-secondary'}`} href={ipamHref(query, { activity: null, addressesPage: 1 })}>
                  All
                </Link>
                {ACTIVITIES.map((activity) => (
                  <Link
                    key={activity}
                    aria-current={query.activity === activity ? 'true' : undefined}
                    className={`btn btn-sm ${query.activity === activity ? 'btn-primary' : 'btn-outline-secondary'}`}
                    href={ipamHref(query, { activity, addressesPage: 1 })}
                  >
                    {activityPresentation(activity).label}
                    {counts !== null ? ` (${counts[activity]})` : ''}
                  </Link>
                ))}
              </div>
              {data.total === 0 ? (
                <StateSurface
                  icon="bi bi-funnel"
                  title={query.activity === null ? 'No addresses' : 'No addresses match this filter'}
                  detail="The read succeeded and returned nothing for this view."
                />
              ) : (
                <AppCard variant="outline" theme="primary" bodyClass="p-0">
                  <Table columns={addressColumns} data={data.items} emptyMessage="No addresses" hover responsive rowKey={(a) => a.id} small striped />
                  <Pager label="Address pages" hrefs={pageLinks(data.total, query.addressesPage, (page) => ipamHref(query, { addressesPage: page }))} />
                </AppCard>
              )}
            </>
          );
        }}
      </FailureOrSurface>
    </section>
  );
}
