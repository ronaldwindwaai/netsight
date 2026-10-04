import { Alert, Badge } from '@adminlte/react';
import type { BootstrapTheme } from '@adminlte/react';

import { DataFailure } from '@/components/data-state';
import type { FetchState } from '@/lib/api';
import type { SourceHealthResponse, SourceHealthStatus } from '@/lib/api-contracts';

interface HealthPresentation {
  title: string;
  description: string;
  label: string;
  icon: string;
  theme: BootstrapTheme;
}

const HEALTH_PRESENTATION: Record<SourceHealthStatus, HealthPresentation> = {
  success: {
    title: 'LibreNMS source reachable',
    description: 'LibreNMS responded to the latest read-only source health check.',
    label: 'Reachable',
    icon: 'bi bi-check-circle-fill',
    theme: 'success',
  },
  unavailable: {
    title: 'LibreNMS source unavailable',
    description:
      'The health check could not reach LibreNMS. Device results retain their own request and freshness state.',
    label: 'Not reachable',
    icon: 'bi bi-cloud-slash',
    theme: 'warning',
  },
  forbidden: {
    title: 'LibreNMS service access rejected',
    description:
      'LibreNMS rejected the server-side service request. No source credential was exposed to the browser.',
    label: 'Access rejected',
    icon: 'bi bi-shield-lock',
    theme: 'danger',
  },
  'invalid-source-data': {
    title: 'LibreNMS health data rejected',
    description:
      'The source returned health data that Netsight could not safely accept as current evidence.',
    label: 'Invalid data',
    icon: 'bi bi-database-x',
    theme: 'danger',
  },
};

function checkedAt(value: string): string {
  return `${new Intl.DateTimeFormat('en-GB', {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'UTC',
  }).format(new Date(value))} UTC`;
}

function latency(value: number | null): string {
  if (value === null) return 'Not measured';
  return `${new Intl.NumberFormat('en-GB', { maximumFractionDigits: 1 }).format(value)} ms`;
}

export function SourceHealth({ state }: { state: FetchState<SourceHealthResponse> }) {
  return (
    <section aria-labelledby="librenms-source-health-title">
      <h2 className="visually-hidden" id="librenms-source-health-title">
        LibreNMS source health
      </h2>
      {state.kind !== 'ok' ? (
        <DataFailure state={state} />
      ) : (
        <Alert
          icon={HEALTH_PRESENTATION[state.data.status].icon}
          theme={HEALTH_PRESENTATION[state.data.status].theme}
          title={HEALTH_PRESENTATION[state.data.status].title}
        >
          <div className="d-flex flex-wrap align-items-center justify-content-between gap-2">
            <span>{HEALTH_PRESENTATION[state.data.status].description}</span>
            <Badge theme={HEALTH_PRESENTATION[state.data.status].theme} pill>
              <i className={`${HEALTH_PRESENTATION[state.data.status].icon} me-1`} aria-hidden="true" />
              {HEALTH_PRESENTATION[state.data.status].label}
            </Badge>
          </div>
          <dl className="d-flex flex-wrap column-gap-4 row-gap-1 small mb-0 mt-2">
            <div>
              <dt className="d-inline me-1">Checked:</dt>
              <dd className="d-inline">{checkedAt(state.data.checked_at)}</dd>
            </div>
            <div>
              <dt className="d-inline me-1">Latency:</dt>
              <dd className="d-inline">{latency(state.data.latency_ms)}</dd>
            </div>
          </dl>
          <small className="d-block mt-2 text-body-secondary">
            Reference: <code>{state.correlationId}</code>
          </small>
        </Alert>
      )}
    </section>
  );
}
