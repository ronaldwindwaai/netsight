import type { DeviceHealthSummary, DeviceStatus, FreshnessState } from '@/lib/api-contracts';

export type OverviewFetchKind =
  | 'ok'
  | 'unauthenticated'
  | 'forbidden'
  | 'not_found'
  | 'rate_limited'
  | 'invalid_source_data'
  | 'source_unavailable'
  | 'maintenance'
  | 'invalid_response'
  | 'error';

export interface HealthSummary {
  title: string;
  detail: string;
  progress: number | undefined;
  theme: 'success' | 'warning' | 'secondary';
}

export function deviceHealthSummary(data: DeviceHealthSummary | null): HealthSummary {
  if (data === null) {
    return {
      title: 'Unknown',
      detail: 'LibreNMS data unavailable',
      progress: undefined,
      theme: 'secondary',
    };
  }

  if (data.total === 0) {
    return {
      title: 'No devices',
      detail: 'Valid empty inventory',
      progress: 0,
      theme: 'secondary',
    };
  }

  const countByStatus = new Map(data.by_status.map((entry) => [entry.status, entry.count]));
  const healthy = countByStatus.get('healthy') ?? 0;
  const attention =
    (countByStatus.get('warning') ?? 0) +
    (countByStatus.get('degraded') ?? 0) +
    (countByStatus.get('critical') ?? 0) +
    (countByStatus.get('offline') ?? 0);
  const unscored = (countByStatus.get('unknown') ?? 0) + (countByStatus.get('maintenance') ?? 0);
  const fullyScored = unscored === 0;
  const progress = fullyScored ? Math.round((healthy / data.total) * 100) : undefined;

  return {
    title: progress === undefined ? `${healthy} healthy` : `${progress}%`,
    detail: `${attention} need attention · ${unscored} unscored`,
    progress,
    theme: attention > 0 ? 'warning' : fullyScored ? 'success' : 'secondary',
  };
}

export function sourceProvenance(
  kind: OverviewFetchKind,
  freshnessState?: FreshnessState,
): { label: string; tone: '' | 'is-connected' | 'is-caution' } {
  if (kind === 'ok') {
    const stateLabel = freshnessState ?? 'unknown';
    return {
      label: `LibreNMS ${stateLabel}`,
      tone: stateLabel === 'fresh' ? 'is-connected' : 'is-caution',
    };
  }

  const labels = {
    unauthenticated: 'Source status unknown · sign-in required',
    forbidden: 'Source status unknown · access restricted',
    not_found: 'Source status unknown · inventory endpoint missing',
    rate_limited: 'Source status unknown · request was rate limited',
    invalid_source_data: 'LibreNMS data rejected',
    source_unavailable: 'LibreNMS unavailable',
    maintenance: 'LibreNMS maintenance',
    invalid_response: 'Source status unknown · invalid API response',
    error: 'Source status unknown · Netsight API unavailable',
  } as const;
  return { label: labels[kind], tone: '' };
}

export interface StatusBreakdownRow {
  status: DeviceStatus;
  count: number;
  /** The device list filtered to this status; absent for a status with no devices. */
  href: string | null;
}

/** Most urgent first, matching the device table's status sort. */
const BREAKDOWN_ORDER: readonly DeviceStatus[] = [
  'critical',
  'offline',
  'degraded',
  'warning',
  'unknown',
  'maintenance',
  'healthy',
];

export function deviceStatusBreakdown(data: DeviceHealthSummary | null): StatusBreakdownRow[] {
  if (data === null || data.total === 0) return [];
  const counts = new Map(data.by_status.map((entry) => [entry.status, entry.count]));
  return BREAKDOWN_ORDER.map((status) => {
    const count = counts.get(status) ?? 0;
    return { status, count, href: count > 0 ? `/devices?status=${status}` : null };
  });
}
