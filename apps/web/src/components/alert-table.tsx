'use client';

import { useMemo } from 'react';
import Link from 'next/link';
import { Badge, Table } from '@adminlte/react';
import { AlertToolbar } from '@/components/alert-toolbar';
import { AppCard } from '@/components/app-card';
import { ExportCsvButton } from '@/components/export-csv-button';
import { RelativeTime } from '@/components/relative-time';
import { useListUrlState } from '@/components/use-list-url-state';
import type { BootstrapTheme, TableColumn } from '@adminlte/react';

import {
  ALERT_CSV_HEADERS,
  ALERT_LIST_SPEC,
  alertCsvRows,
  filterAlerts,
  sortAlerts,
} from '@/lib/alert-list-view';
import type { Alert, AlertSeverity, AlertState } from '@/lib/api-contracts';
import type { ListSort } from '@/lib/list-url-state';

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
    render: (alert) => <RelativeTime value={alert.observed_at} />,
  },
];

function sortToValue(sort: ListSort | null): string {
  return sort === null ? '' : `${sort.direction === 'desc' ? '-' : ''}${sort.key}`;
}

function valueToSort(value: string): ListSort | null {
  if (value === '') return null;
  return value.startsWith('-')
    ? { key: value.slice(1), direction: 'desc' }
    : { key: value, direction: 'asc' };
}

export function AlertTable({ alerts, total }: { alerts: Alert[]; total: number }) {
  const { state, update, clear, isFiltering } = useListUrlState(ALERT_LIST_SPEC);
  const severity = (state.filters.severity ?? null) as AlertSeverity | null;
  const alertState = (state.filters.state ?? null) as AlertState | null;
  const rows = useMemo(
    () => sortAlerts(filterAlerts(alerts, { q: state.q, severity, state: alertState }), state.sort),
    [alerts, state.q, severity, alertState, state.sort],
  );
  const csvRows = useMemo(() => alertCsvRows(rows), [rows]);

  return (
    <AppCard
      title="Canonical alerts"
      icon="bi bi-bell"
      variant="outline"
      theme="primary"
      bodyClass="p-0"
      tools={
        <span className="d-inline-flex align-items-center gap-2">
          <span className="small text-body-secondary" aria-live="polite">
            {rows.length} shown / {total} total
          </span>
          <ExportCsvButton headers={ALERT_CSV_HEADERS} label="alerts" rows={csvRows} />
        </span>
      }
    >
      <AlertToolbar
        filtering={isFiltering}
        onChange={(patch) => {
          if (patch.q !== undefined) return update({ q: patch.q }, 'replace');
          if (patch.sort !== undefined) return update({ sort: valueToSort(patch.sort) });
          const next = {
            severity: patch.severity ?? state.filters.severity ?? '',
            state: patch.state ?? state.filters.state ?? '',
          };
          return update({
            filters: Object.fromEntries(Object.entries(next).filter(([, value]) => value !== '')),
          });
        }}
        onClear={clear}
        values={{ q: state.q, severity: severity ?? '', state: alertState ?? '', sort: sortToValue(state.sort) }}
      />
      <p className="small text-body-secondary px-3 pt-2 mb-0">
        Filters and sorting apply to the {alerts.length} {alerts.length === 1 ? 'alert' : 'alerts'} loaded on this
        page.
      </p>
      {rows.length === 0 && alerts.length > 0 ? (
        <p className="text-center text-body-secondary py-4 mb-0">
          No alerts match these filters.{' '}
          <button className="btn btn-link btn-sm p-0 align-baseline" onClick={clear} type="button">
            Clear filters
          </button>
        </p>
      ) : (
        <Table
          columns={columns}
          data={rows}
          emptyMessage="No alerts"
          hover
          responsive
          rowKey={(alert) => alert.id}
          small
          striped
        />
      )}
    </AppCard>
  );
}
