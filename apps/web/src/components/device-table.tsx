'use client';

import { useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import { Card } from '@adminlte/react';
import type { ReactNode } from 'react';

import { EmptyState } from '@/components/data-state';
import { FreshnessBadge, StatusBadge } from '@/components/status-badge';
import { DEVICE_STATUSES } from '@/lib/api-contracts';
import type { Device, DeviceStatus } from '@/lib/api-contracts';
import { PERSON_ID } from '@/lib/api-contracts-identity-core';
import { countByStatus, nextSort, sortDevices } from '@/lib/device-view';
import type { DeviceSortKey, SortState } from '@/lib/device-view';

function observedAt(value: string | null): string {
  if (!value) return 'Not tracked yet';
  const date = new Date(value);
  return Number.isNaN(date.valueOf())
    ? 'Unknown'
    : `${new Intl.DateTimeFormat('en-GB', {
        dateStyle: 'medium',
        timeStyle: 'short',
        timeZone: 'UTC',
      }).format(date)} UTC`;
}

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
          {observedAt(device.freshness.observed_at)}
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

function matchesQuery(device: Device, needle: string): boolean {
  if (needle.length === 0) return true;
  return [device.name, device.hostname, device.type, device.site_id, ...device.ip_addresses]
    .filter((value): value is string => Boolean(value))
    .some((value) => value.toLocaleLowerCase().includes(needle));
}

export function DeviceTable({ devices, total }: { devices: Device[]; total: number }) {
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState<DeviceStatus | 'all'>('all');
  const [sort, setSort] = useState<SortState | null>(null);

  const counts = useMemo(() => countByStatus(devices), [devices]);
  const rows = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    const matched = devices.filter(
      (device) => (status === 'all' || device.status === status) && matchesQuery(device, needle),
    );
    return sort === null ? matched : sortDevices(matched, sort.key, sort.direction);
  }, [devices, query, status, sort]);
  const searchRef = useRef<HTMLInputElement>(null);
  const filtering = query.trim().length > 0 || status !== 'all';

  return (
    <Card
      title="Canonical devices"
      icon="bi bi-hdd-network"
      variant="outline"
      theme="primary"
      bodyClass="p-0"
      tools={
        <span className="small text-body-secondary" aria-live="polite">
          {rows.length} shown / {total} total
        </span>
      }
    >
      <StatusChips active={status} counts={counts} onSelect={setStatus} />
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
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Name, hostname, IP, type or site"
            type="search"
            value={query}
          />
        </div>
        <div className="d-flex align-items-end">
          <button
            className="btn btn-sm btn-outline-secondary"
            disabled={!filtering}
            onClick={() => {
              setQuery('');
              setStatus('all');
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
        Sorting and filters apply to the {devices.length} {devices.length === 1 ? 'device' : 'devices'} loaded on this
        page{total > devices.length ? `; use the page controls below for the other ${total - devices.length}.` : ' (all of them).'}
      </p>
      {rows.length === 0 ? (
        <div className="p-3">
          <EmptyState filtered />
        </div>
      ) : (
        <DeviceRows
          onSort={(key) => setSort((current) => nextSort(current, key))}
          rows={rows}
          sort={sort}
        />
      )}
    </Card>
  );
}
