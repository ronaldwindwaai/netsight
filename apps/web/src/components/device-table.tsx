'use client';

import { useMemo, useState } from 'react';
import Link from 'next/link';
import { Card, Table } from '@adminlte/react';
import type { TableColumn } from '@adminlte/react';

import { EmptyState } from '@/components/data-state';
import { FreshnessBadge, StatusBadge } from '@/components/status-badge';
import { DEVICE_STATUSES } from '@/lib/api-contracts';
import type { Device, DeviceStatus } from '@/lib/api-contracts';

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

const columns: TableColumn<Device>[] = [
  {
    key: 'status',
    header: 'Status',
    render: (device) => <StatusBadge status={device.status} />,
  },
  {
    key: 'name',
    header: 'Device',
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
  {
    key: 'ip_addresses',
    header: 'IP address',
    render: (device) => device.ip_addresses[0] ?? 'Not tracked yet',
  },
  {
    key: 'type',
    header: 'Type',
    render: (device) => device.type ?? 'Not tracked yet',
  },
  {
    key: 'site_id',
    header: 'Site',
    render: (device) => device.site_id ?? 'Not tracked yet',
  },
  {
    key: 'freshness',
    header: 'Freshness',
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

export function DeviceTable({ devices, total }: { devices: Device[]; total: number }) {
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState<DeviceStatus | 'all'>('all');

  const filtered = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    return devices.filter((device) => {
      const matchesStatus = status === 'all' || device.status === status;
      const matchesQuery =
        needle.length === 0 ||
        [device.name, device.hostname, ...device.ip_addresses]
          .filter((value): value is string => Boolean(value))
          .some((value) => value.toLocaleLowerCase().includes(needle));
      return matchesStatus && matchesQuery;
    });
  }, [devices, query, status]);

  return (
    <Card
      title="Canonical devices"
      icon="bi bi-hdd-network"
      variant="outline"
      theme="primary"
      bodyClass="p-0"
      tools={
        <span className="small text-body-secondary" aria-live="polite">
          {filtered.length} shown / {total} total
        </span>
      }
    >
      <div className="device-filters border-bottom p-3">
        <div>
          <label className="form-label" htmlFor="device-search">
            Filter loaded page
          </label>
          <input
            className="form-control form-control-sm"
            id="device-search"
            maxLength={128}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Hostname, name or IP on this page"
            type="search"
            value={query}
          />
        </div>
        <div>
          <label className="form-label" htmlFor="device-status">
            Page status
          </label>
          <select
            className="form-select form-select-sm"
            id="device-status"
            onChange={(event) => setStatus(event.target.value as DeviceStatus | 'all')}
            value={status}
          >
            <option value="all">All statuses</option>
            {DEVICE_STATUSES.map((item) => (
              <option key={item} value={item}>
                {item[0].toUpperCase() + item.slice(1)}
              </option>
            ))}
          </select>
        </div>
      </div>
      {filtered.length === 0 ? (
        <div className="p-3">
          <EmptyState filtered />
        </div>
      ) : (
        <Table
          columns={columns}
          data={filtered}
          emptyMessage="No devices"
          hover
          responsive
          rowKey={(device) => device.id}
          small
          striped
        />
      )}
    </Card>
  );
}
