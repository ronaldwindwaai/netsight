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

const SEVERITY_ICON: Record<AlertSeverity, string> = {
  info: 'bi-info-circle-fill',
  low: 'bi-arrow-down-circle-fill',
  medium: 'bi-exclamation-circle-fill',
  high: 'bi-exclamation-triangle-fill',
  critical: 'bi-x-octagon-fill',
};

const STATE_VIEW: Record<AlertState, { icon: string; meaning: string }> = {
  open: { icon: 'bi-circle-fill', meaning: 'Active and nobody has taken it yet.' },
  acknowledged: { icon: 'bi-check-circle', meaning: 'Someone has seen it; it is still active.' },
  investigating: { icon: 'bi-search', meaning: 'Being investigated; it is still active.' },
  resolved: { icon: 'bi-check-circle-fill', meaning: 'The source reports it as cleared.' },
  suppressed: { icon: 'bi-bell-slash', meaning: 'Muted, for example by a maintenance window. It is not resolved.' },
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
        <i className={`bi ${SEVERITY_ICON[alert.severity]} me-1`} aria-hidden="true" />
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
      <div>
        <Badge theme={STATE_THEME[alert.state]} pill>
          <i className={`bi ${STATE_VIEW[alert.state].icon} me-1`} aria-hidden="true" />
          {label(alert.state)}
        </Badge>
        <span className="visually-hidden"> {STATE_VIEW[alert.state].meaning}</span>
      </div>
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
