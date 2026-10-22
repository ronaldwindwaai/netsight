'use client';

import { useMemo, useRef } from 'react';
import Link from 'next/link';
import { AppCard } from '@/components/app-card';
import type { ReactNode } from 'react';

import { EmptyState } from '@/components/data-state';
import { ExportCsvButton } from '@/components/export-csv-button';
import { RelativeTime } from '@/components/relative-time';
import { useListUrlState } from '@/components/use-list-url-state';
import { FreshnessBadge, StatusBadge } from '@/components/status-badge';
import { DEVICE_STATUSES } from '@/lib/api-contracts';
import type { Device, DeviceStatus } from '@/lib/api-contracts';
import { PERSON_ID } from '@/lib/api-contracts-identity-core';
import { countByStatus, pageScopeNote, sortDevices } from '@/lib/device-view';
import { DEVICE_SORT_KEYS } from '@/lib/device-view';
import type { DeviceSortKey, SortState } from '@/lib/device-view';
import { pickAllowed, toggleSort } from '@/lib/list-url-state';
import type { ListSort, ListSpec } from '@/lib/list-url-state';

interface DeviceColumn {
  key: string;
  label: string;
  /** Present for sortable columns: the header then carries a sort button and aria-sort. */
  sortKey?: DeviceSortKey;
  render: (device: Device) => ReactNode;
}

function OwnerCell({ device }: { device: Device }) {
  const id = device.owner_identity_id;
  if (id === null) return <span className="text-body-secondary">Not tracked yet</span>;
  if (!PERSON_ID.test(id)) {
    return <span className="text-body-secondary">Not linked to a person</span>;
  }
  return (
    <Link href={`/users/${encodeURIComponent(id)}`}>
      <i className="bi bi-person me-1" aria-hidden="true" />
      Owner identity
    </Link>
  );
}

function SortButton({
  label,
  sortKey,
  sort,
  onSort,
}: {
  label: string;
  sortKey: DeviceSortKey;
  sort: SortState | null;
  onSort: (key: DeviceSortKey) => void;
}) {
  const active = sort !== null && sort.key === sortKey;
  const ascending = active && sort.direction === 'asc';
  const state = !active ? 'not sorted' : ascending ? 'ascending' : 'descending';
  const icon = !active ? 'bi-arrow-down-up' : ascending ? 'bi-sort-up' : 'bi-sort-down';
  return (
    <button
      aria-label={`Sort by ${label}, currently ${state}`}
      className="btn btn-link btn-sm p-0 fw-semibold text-decoration-none text-reset"
      onClick={() => onSort(sortKey)}
      type="button"
    >
      {label}
      <i className={`bi ${icon} ms-1 ${active ? '' : 'text-body-secondary'}`} aria-hidden="true" />
    </button>
  );
}

function ariaSort(column: DeviceColumn, sort: SortState | null): 'ascending' | 'descending' | 'none' | undefined {
  if (column.sortKey === undefined) return undefined;
  if (sort === null || sort.key !== column.sortKey) return 'none';
  return sort.direction === 'asc' ? 'ascending' : 'descending';
}

const COLUMNS: DeviceColumn[] = [
  { key: 'status', label: 'Status', sortKey: 'status', render: (d) => <StatusBadge status={d.status} /> },
  {
    key: 'name',
    label: 'Device',
    sortKey: 'name',
    render: (device) => (
      <div>
        <Link className="fw-semibold" href={`/devices/${encodeURIComponent(device.id)}`}>
          {device.name}
        </Link>
        <span className="d-block small text-body-secondary">
          {device.hostname ?? 'Hostname not tracked'}
        </span>
      </div>
    ),
  },
  { key: 'ip', label: 'IP address', sortKey: 'ip', render: (d) => d.ip_addresses[0] ?? 'Not tracked yet' },
  { key: 'type', label: 'Type', sortKey: 'type', render: (d) => d.type || 'Not tracked yet' },
  { key: 'site', label: 'Site', sortKey: 'site', render: (d) => d.site_id ?? 'Not tracked yet' },
  { key: 'owner', label: 'Owner', render: (d) => <OwnerCell device={d} /> },
  {
    key: 'freshness',
    label: 'Freshness',
    sortKey: 'freshness',
    render: (device) => (
      <div>
        <FreshnessBadge state={device.freshness.state} />
        <span className="d-block small text-body-secondary mt-1">
          {device.freshness.observed_at ? (
            <RelativeTime value={device.freshness.observed_at} />
          ) : (
            'Not tracked yet'
          )}
        </span>
      </div>
    ),
  },
];

function DeviceRows({
  rows,
  sort,
  onSort,
}: {
  rows: Device[];
  sort: SortState | null;
  onSort: (key: DeviceSortKey) => void;
}) {
  return (
    <div
      aria-label="Devices table (scrollable)"
      className="devices-scroll"
      role="region"
      tabIndex={0}
    >
      <table className="table table-sm table-hover table-striped mb-0">
        <caption className="visually-hidden">
          Canonical devices. Sorting and filters cover the loaded page only.
        </caption>
        <thead>
          <tr>
            {COLUMNS.map((column) => (
              <th aria-sort={ariaSort(column, sort)} key={column.key} scope="col">
                {column.sortKey === undefined ? (
                  column.label
                ) : (
                  <SortButton label={column.label} onSort={onSort} sort={sort} sortKey={column.sortKey} />
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((device) => (
            <tr key={device.id}>
              {COLUMNS.map((column) => (
                <td key={column.key}>{column.render(device)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function StatusChips({
  counts,
  active,
  onSelect,
}: {
  counts: Record<DeviceStatus, number>;
  active: DeviceStatus | 'all';
  onSelect: (status: DeviceStatus | 'all') => void;
}) {
  return (
    <div
      aria-label="Filter this page by status"
      className="d-flex flex-wrap gap-2 px-3 pt-3"
      role="group"
    >
      {DEVICE_STATUSES.map((item) => (
        <button
          aria-pressed={active === item}
          className={`btn btn-sm ${active === item ? 'btn-primary' : 'btn-outline-secondary'}`}
          disabled={counts[item] === 0 && active !== item}
          key={item}
          onClick={() => onSelect(active === item ? 'all' : item)}
          type="button"
        >
          {item} ({counts[item]})
        </button>
      ))}
    </div>
  );
}

/** The URL parser already limits sort keys to the spec; this narrows the type without a cast. */
function deviceSort(sort: ListSort | null): SortState | null {
  const key = pickAllowed(DEVICE_SORT_KEYS, sort?.key);
  return sort === null || key === null ? null : { key, direction: sort.direction };
}

function matchesQuery(device: Device, needle: string): boolean {
  if (needle.length === 0) return true;
  return [device.name, device.hostname, device.type, device.site_id, ...device.ip_addresses]
    .filter((value): value is string => Boolean(value))
    .some((value) => value.toLocaleLowerCase().includes(needle));
}

const LIST_SPEC = {
  filters: { status: DEVICE_STATUSES },
  sortKeys: DEVICE_SORT_KEYS,
} as const satisfies ListSpec;

const CSV_HEADERS = ['Status', 'Device', 'Hostname', 'IP addresses', 'Type', 'Site', 'Freshness', 'Observed at (UTC)'];

function csvRow(device: Device): string[] {
  return [
    device.status,
    device.name,
    device.hostname ?? '',
    device.ip_addresses.join(' '),
    device.type,
    device.site_id ?? '',
    device.freshness.state,
    device.freshness.observed_at ?? '',
  ];
}

export function DeviceTable({ devices, total }: { devices: Device[]; total: number }) {
  const { state, update, clear, isFiltering } = useListUrlState(LIST_SPEC);
  const query = state.q;
  const status: DeviceStatus | 'all' = pickAllowed(DEVICE_STATUSES, state.filters.status) ?? 'all';
  const sort = useMemo(() => deviceSort(state.sort), [state.sort]);

  const counts = useMemo(() => countByStatus(devices), [devices]);
  const rows = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    const matched = devices.filter(
      (device) => (status === 'all' || device.status === status) && matchesQuery(device, needle),
    );
    return sort === null ? matched : sortDevices(matched, sort.key, sort.direction);
  }, [devices, query, status, sort]);
  const searchRef = useRef<HTMLInputElement>(null);
  const csvRows = useMemo(() => rows.map(csvRow), [rows]);

  return (
    <AppCard
      title="Canonical devices"
      icon="bi bi-hdd-network"
      variant="outline"
      theme="primary"
      bodyClass="p-0"
      tools={
        <span className="d-inline-flex align-items-center gap-2">
          <span className="small text-body-secondary" aria-live="polite">
            {rows.length} shown / {total} total
          </span>
          <ExportCsvButton headers={CSV_HEADERS} label="devices" rows={csvRows} />
        </span>
      }
    >
      <StatusChips
        active={status}
        counts={counts}
        onSelect={(next) =>
          update({ filters: next === 'all' ? {} : { status: next } })
        }
      />
      <div className="device-filters border-bottom p-3">
        <div>
          <label className="form-label" htmlFor="device-search">
            Filter this page
          </label>
          <input
            className="form-control form-control-sm"
            id="device-search"
            ref={searchRef}
            maxLength={128}
            onChange={(event) => update({ q: event.target.value }, 'replace')}
            placeholder="Name, hostname, IP, type or site"
            type="search"
            value={query}
          />
        </div>
        <div className="d-flex align-items-end">
          <button
            className="btn btn-sm btn-outline-secondary"
            disabled={!isFiltering}
            onClick={() => {
              clear();
              // The button disables itself once nothing is filtered; keep keyboard focus alive.
              searchRef.current?.focus();
            }}
            type="button"
          >
            <i className="bi bi-x-circle me-1" aria-hidden="true" />
            Clear filters
          </button>
        </div>
      </div>
      <p className="small text-body-secondary px-3 pt-2 mb-0">
        {pageScopeNote(devices.length, total)}
      </p>
      {rows.length === 0 ? (
        <div className="p-3">
          <EmptyState filtered onClear={clear} />
        </div>
      ) : (
        <DeviceRows
          onSort={(key) => update({ sort: toggleSort(sort, key) })}
          rows={rows}
          sort={sort}
        />
      )}
    </AppCard>
  );
}
