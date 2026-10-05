'use client';

import { Table } from '@adminlte/react';
import type { TableColumn } from '@adminlte/react';

import { StatusBadge } from '@/components/status-badge';
import type { NetworkInterface } from '@/lib/api-contracts';
import { formatSpeed } from '@/lib/format-speed';

function text(value: string | null | undefined, fallback = 'Not reported'): string {
  return value && value.trim().length > 0 ? value : fallback;
}

const columns: TableColumn<NetworkInterface>[] = [
  {
    key: 'name',
    header: 'Interface',
    render: (item) => (
      <div>
        <span className="fw-semibold">{item.name}</span>
        {item.alias ? <span className="d-block small text-body-secondary">{item.alias}</span> : null}
      </div>
    ),
  },
  {
    key: 'index',
    header: 'IfIndex',
    render: (item) => (item.index === null ? 'Not reported' : String(item.index)),
  },
  {
    key: 'admin_status',
    header: 'Admin',
    render: (item) => (
      <span
        className={`badge ${item.admin_status === 'up' ? 'text-bg-success' : item.admin_status === 'down' ? 'text-bg-secondary' : 'text-bg-warning'}`}
      >
        {item.admin_status}
      </span>
    ),
  },
  {
    key: 'oper_status',
    header: 'Operational',
    render: (item) => (
      <span
        className={`badge ${item.oper_status === 'up' ? 'text-bg-success' : item.oper_status === 'down' ? 'text-bg-danger' : 'text-bg-warning'}`}
      >
        {item.oper_status}
      </span>
    ),
  },
  {
    key: 'status',
    header: 'Status',
    render: (item) => <StatusBadge status={item.status} />,
  },
  {
    key: 'speed_bps',
    header: 'Speed',
    render: (item) => formatSpeed(item.speed_bps),
  },
  {
    key: 'hardware_type',
    header: 'Type',
    render: (item) => text(item.hardware_type),
  },
];

export function InterfaceTable({
  interfaces,
  total,
}: {
  interfaces: NetworkInterface[];
  total: number;
}) {
  return (
    <div>
      <p className="small text-body-secondary">
        {total} interface{total === 1 ? '' : 's'} reported by the monitoring source.
      </p>
      <Table
        columns={columns}
        data={interfaces}
        emptyMessage="No interfaces"
        hover
        responsive
        rowKey={(item) => item.id}
        small
        striped
      />
    </div>
  );
}