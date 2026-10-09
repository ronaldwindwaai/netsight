import type { IncidentSeverity, IncidentState } from '@/lib/api-contracts-incident';
import { severityLabel, stateLabel } from '@/lib/incident-view';

// Colour is never the only signal: each badge carries an icon and the label text.
const SEVERITY_STYLE: Record<IncidentSeverity, { theme: string; icon: string }> = {
  critical: { theme: 'text-bg-danger', icon: 'bi-x-octagon-fill' },
  high: { theme: 'text-bg-warning', icon: 'bi-exclamation-triangle-fill' },
  medium: { theme: 'text-bg-info', icon: 'bi-exclamation-circle-fill' },
  low: { theme: 'text-bg-secondary', icon: 'bi-info-circle-fill' },
};

const STATE_STYLE: Record<IncidentState, { theme: string; icon: string }> = {
  open: { theme: 'text-bg-danger', icon: 'bi-circle-fill' },
  acknowledged: { theme: 'text-bg-warning', icon: 'bi-check-circle' },
  investigating: { theme: 'text-bg-info', icon: 'bi-search' },
  mitigated: { theme: 'text-bg-primary', icon: 'bi-shield-check' },
  resolved: { theme: 'text-bg-success', icon: 'bi-check-circle-fill' },
  closed: { theme: 'text-bg-secondary', icon: 'bi-archive' },
};

export function SeverityBadge({ severity }: { severity: IncidentSeverity }) {
  const style = SEVERITY_STYLE[severity];
  return (
    <span className={`badge ${style.theme}`}>
      <i className={`bi ${style.icon} me-1`} aria-hidden="true" />
      {severityLabel(severity)}
    </span>
  );
}

export function StateBadge({ state }: { state: IncidentState }) {
  const style = STATE_STYLE[state];
  return (
    <span className={`badge ${style.theme}`}>
      <i className={`bi ${style.icon} me-1`} aria-hidden="true" />
      {stateLabel(state)}
    </span>
  );
}
