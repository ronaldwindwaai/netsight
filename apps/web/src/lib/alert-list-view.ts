import { ALERT_SEVERITIES, ALERT_STATES } from './api-contracts.ts';
import type { Alert, AlertSeverity, AlertState } from './api-contracts.ts';
import type { ListSort, ListSpec } from './list-url-state.ts';

export const ALERT_LIST_SPEC = {
  filters: { severity: ALERT_SEVERITIES, state: ALERT_STATES },
  sortKeys: ['severity', 'state', 'observed', 'title'],
} as const satisfies ListSpec;

export const ALERT_CSV_HEADERS = ['Severity', 'State', 'Alert', 'Device', 'Alert ID', 'Observed at (UTC)'] as const;

export interface AlertFilter {
  readonly q: string;
  readonly severity: AlertSeverity | null;
  readonly state: AlertState | null;
}

export function filterAlerts(alerts: readonly Alert[], filter: AlertFilter): Alert[] {
  const needle = filter.q.trim().toLocaleLowerCase();
  return alerts.filter(
    (alert) =>
      (filter.severity === null || alert.severity === filter.severity) &&
      (filter.state === null || alert.state === filter.state) &&
      (needle.length === 0 ||
        alert.title.toLocaleLowerCase().includes(needle) ||
        alert.id.toLocaleLowerCase().includes(needle)),
  );
}

/** Ascending severity puts the most severe first, matching how the device status sort reads. */
const SEVERITY_RANK: Readonly<Record<AlertSeverity, number>> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function compare(a: Alert, b: Alert, key: string): number {
  switch (key) {
    case 'severity':
      return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    case 'state':
      return ALERT_STATES.indexOf(a.state) - ALERT_STATES.indexOf(b.state);
    case 'observed':
      return Date.parse(a.observed_at) - Date.parse(b.observed_at);
    default:
      return a.title.localeCompare(b.title, 'en', { numeric: true, sensitivity: 'base' });
  }
}

/** A new array; ties keep the order the API returned. */
export function sortAlerts(alerts: readonly Alert[], sort: ListSort | null): Alert[] {
  if (sort === null) return [...alerts];
  const sign = sort.direction === 'asc' ? 1 : -1;
  return alerts
    .map((alert, index) => ({ alert, index }))
    .sort((x, y) => sign * compare(x.alert, y.alert, sort.key) || x.index - y.index)
    .map((entry) => entry.alert);
}

export function alertCsvRows(alerts: readonly Alert[]): string[][] {
  return alerts.map((alert) => [
    alert.severity,
    alert.state,
    alert.title,
    alert.device_id ?? '',
    alert.id,
    alert.observed_at,
  ]);
}
