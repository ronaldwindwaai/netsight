'use client';

import Link from 'next/link';
import { Badge, Card, Table } from '@adminlte/react';
import type { BootstrapTheme, TableColumn } from '@adminlte/react';

import type { Alert, AlertSeverity, AlertState } from '@/lib/api-contracts';

const SEVERITY_THEME: Record<AlertSeverity, BootstrapTheme> = {
  info: 'secondary',
  low: 'info',
  medium: 'warning',
  high: 'danger',
  critical: 'danger',
};

const STATE_THEME: Record<AlertState, BootstrapTheme> = {
  open: 'danger',
  acknowledged: 'warning',
  investigating: 'info',
  resolved: 'success',
  suppressed: 'secondary',
};

function label(value: string): string {
  return value.replaceAll('_', ' ').replace(/^./, (first) => first.toUpperCase());
}

function observedAt(value: string): string {
  return `${new Intl.DateTimeFormat('en-GB', {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'UTC',
  }).format(new Date(value))} UTC`;
}

const columns: TableColumn<Alert>[] = [
  {
    key: 'severity',
    header: 'Severity',
    render: (alert) => (
      <Badge theme={SEVERITY_THEME[alert.severity]} pill>
        <i className="bi bi-exclamation-circle-fill me-1" aria-hidden="true" />
        {label(alert.severity)}
      </Badge>
    ),
  },
  {
    key: 'title',
    header: 'Alert',
    render: (alert) => (
      <div>
        <span className="fw-semibold">{alert.title}</span>
        <code className="d-block small text-body-secondary mt-1">{alert.id}</code>
      </div>
    ),
  },
  {
    key: 'device_id',
    header: 'Device',
    render: (alert) =>
      alert.device_id ? (
        <Link href={`/devices/${encodeURIComponent(alert.device_id)}`}>Open device</Link>
      ) : (
        <span className="text-body-secondary">Not linked</span>
      ),
  },
  {
    key: 'state',
    header: 'State',
    render: (alert) => (
      <Badge theme={STATE_THEME[alert.state]} pill>
        {label(alert.state)}
      </Badge>
    ),
  },
  {
    key: 'observed_at',
    header: 'Observed',
    render: (alert) => observedAt(alert.observed_at),
  },
];

export function AlertTable({ alerts, total }: { alerts: Alert[]; total: number }) {
  return (
    <Card
      title="Canonical alerts"
      icon="bi bi-bell"
      variant="outline"
      theme="primary"
      bodyClass="p-0"
      tools={<span className="small text-body-secondary">{alerts.length} shown / {total} total</span>}
    >
      <Table
        columns={columns}
        data={alerts}
        emptyMessage="No alerts"
        hover
        responsive
        rowKey={(alert) => alert.id}
        small
        striped
      />
    </Card>
  );
}
