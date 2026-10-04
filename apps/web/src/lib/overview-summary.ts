import type { DeviceListResponse, FreshnessState } from '@/lib/api-contracts';

export type OverviewFetchKind =
  | 'ok'
  | 'unauthenticated'
  | 'forbidden'
  | 'not_found'
  | 'invalid_source_data'
  | 'source_unavailable'
  | 'maintenance'
  | 'invalid_response'
  | 'error';

export interface DeviceHealthSummary {
  title: string;
  detail: string;
  progress: number | undefined;
  theme: 'success' | 'warning' | 'secondary';
}

export function deviceHealthSummary(data: DeviceListResponse | null): DeviceHealthSummary {
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

  const healthy = data.items.filter((device) => device.status === 'healthy').length;
  const attention = data.items.filter((device) =>
    ['warning', 'degraded', 'critical', 'offline'].includes(device.status),
  ).length;
  const unscored = data.items.filter((device) =>
    ['unknown', 'maintenance'].includes(device.status),
  ).length;
  const complete = data.items.length === data.total;
  const fullyScored = complete && unscored === 0;
  const progress = fullyScored ? Math.round((healthy / data.total) * 100) : undefined;

  return {
    title: progress === undefined ? `${healthy} healthy` : `${progress}%`,
    detail: complete
      ? `${attention} need attention · ${unscored} unscored`
      : `${data.items.length} of ${data.total} devices sampled`,
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
    invalid_source_data: 'LibreNMS data rejected',
    source_unavailable: 'LibreNMS unavailable',
    maintenance: 'LibreNMS maintenance',
    invalid_response: 'Source status unknown · invalid API response',
    error: 'Source status unknown · Netsight API unavailable',
  } as const;
  return { label: labels[kind], tone: '' };
}
