import { Badge } from '@adminlte/react';
import type { BootstrapTheme } from '@adminlte/react';

import type { DeviceStatus, FreshnessState } from '@/lib/api-contracts';

const STATUS_THEME: Record<DeviceStatus, BootstrapTheme> = {
  healthy: 'success',
  warning: 'warning',
  degraded: 'warning',
  critical: 'danger',
  offline: 'danger',
  unknown: 'secondary',
  maintenance: 'info',
};

const STATUS_ICON: Record<DeviceStatus, string> = {
  healthy: 'bi-check-circle-fill',
  warning: 'bi-exclamation-circle-fill',
  degraded: 'bi-exclamation-triangle-fill',
  critical: 'bi-x-octagon-fill',
  offline: 'bi-plug-fill',
  unknown: 'bi-question-circle-fill',
  maintenance: 'bi-tools',
};

export function StatusBadge({ status }: { status: DeviceStatus }) {
  return (
    <Badge theme={STATUS_THEME[status]} pill>
      <i className={`bi ${STATUS_ICON[status]} me-1`} aria-hidden="true" />
      {status}
    </Badge>
  );
}

export function FreshnessBadge({ state }: { state: FreshnessState }) {
  const theme: BootstrapTheme = state === 'fresh' ? 'success' : state === 'stale' ? 'warning' : 'secondary';
  return (
    <Badge theme={theme} pill>
      {state}
    </Badge>
  );
}
