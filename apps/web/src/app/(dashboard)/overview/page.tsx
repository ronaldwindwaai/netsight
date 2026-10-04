import Link from 'next/link';
import { AppContent, Card, InfoBox } from '@adminlte/react';

import { DataFailure, FreshnessNotice } from '@/components/data-state';
import { apiGet } from '@/lib/api';
import { parseOverviewResponse } from '@/lib/api-contracts';
import { deviceHealthSummary, sourceProvenance } from '@/lib/overview-summary';

function UnavailableSurface({
  icon,
  title,
  detail,
}: {
  icon: string;
  title: string;
  detail: string;
}) {
  return (
    <div className="unavailable-surface">
      <span className="unavailable-surface__icon" aria-hidden="true">
        <i className={`bi ${icon}`} />
      </span>
      <div>
        <h3 className="h6 mb-1">{title}</h3>
        <p className="mb-0 text-body-secondary">{detail}</p>
      </div>
    </div>
  );
}

export default async function OverviewPage() {
  const state = await apiGet('/api/v1/overview', parseOverviewResponse);
  const overview = state.kind === 'ok' ? state.data : null;
  const health = overview
    ? deviceHealthSummary(overview.devices)
    : deviceHealthSummary(null);
  const provenance = sourceProvenance(
    state.kind,
    state.kind === 'ok' ? state.data.devices.freshness.state : undefined,
  );

  return (
    <AppContent title="Network overview" breadcrumbs={[{ label: 'Overview' }]}>
      <div className="page-intro d-flex flex-wrap align-items-end justify-content-between gap-2">
        <div>
          <p className="text-body-secondary mb-0">
            Live operational evidence where sources are connected; unknown states stay visible.
          </p>
        </div>
        <span className="source-provenance">
          <span
            className={`source-provenance__dot ${provenance.tone}`}
            aria-hidden="true"
          />
          {provenance.label}
        </span>
      </div>

      {state.kind !== 'ok' ? <DataFailure state={state} /> : null}
      {state.kind === 'ok' ? (
        <FreshnessNotice freshness={state.data.devices.freshness} />
      ) : null}

      <section className="overview-kpi-grid" aria-label="Operational summary">
        <Link
          className={`overview-kpi-link ${health.progress === undefined ? 'overview-kpi--unknown' : ''}`}
          href="/devices"
          aria-label={`Network health: ${health.title}. ${health.detail}. Open device inventory.`}
        >
          <InfoBox
            icon="bi-heart-pulse"
            text="Network health"
            title={health.title}
            theme={health.theme}
            progress={health.progress ?? 0}
            progressText={health.detail}
          />
        </Link>
        <div className="overview-kpi--unknown">
          <InfoBox
            icon="bi-globe2"
            text="Internet"
            title="Not connected"
            theme="secondary"
            progress={0}
            progressText="WAN telemetry unavailable"
          />
        </div>
        <div className="overview-kpi--unknown">
          <InfoBox
            icon="bi-shield-exclamation"
            text="Security"
            title="Not connected"
            theme="secondary"
            progress={0}
            progressText="Security sources unavailable"
          />
        </div>
        <div className="overview-kpi--unknown">
          <InfoBox
            icon="bi-people"
            text="Users"
            title="Not connected"
            theme="secondary"
            progress={0}
            progressText="Identity telemetry unavailable"
          />
        </div>
      </section>

      <div className="row g-3 mb-3">
        <div className="col-xl-8 order-2 order-xl-1">
          <Card
            className="operational-card operational-card--primary"
            title="Live network map"
            icon="bi bi-diagram-3"
            variant="outline"
            theme="primary"
            tools={
              <span className="badge topology-source-badge">Topology source required</span>
            }
          >
            <UnavailableSurface
              icon="bi-bezier2"
              title="Topology is not yet connected"
              detail="Connect and reconcile a topology source before Netsight can draw network relationships."
            />
          </Card>
        </div>
        <div className="col-xl-4 order-1 order-xl-2">
          <Card
            className="operational-card operational-card--primary"
            title="Active incidents"
            icon="bi bi-exclamation-triangle"
            variant="outline"
            theme="secondary"
          >
            <UnavailableSurface
              icon="bi-inboxes"
              title="Incident service not connected"
              detail="No incident count is shown because the incident engine is not available in this slice."
            />
          </Card>
        </div>
      </div>

      <div className="row g-3">
        <div className="col-xl-6">
          <Card
            className="operational-card"
            title="Top bandwidth users"
            icon="bi bi-bar-chart-line"
            variant="outline"
            theme="primary"
          >
            <UnavailableSurface
              icon="bi-activity"
              title="Flow telemetry not connected"
              detail="Bandwidth rankings will appear only after an approved flow source is available."
            />
          </Card>
        </div>
        <div className="col-xl-6">
          <Card
            className="operational-card"
            title="Application mix"
            icon="bi bi-pie-chart"
            variant="outline"
            theme="primary"
          >
            <UnavailableSurface
              icon="bi-pie-chart"
              title="Application telemetry not connected"
              detail="Netsight will not estimate application usage without source evidence."
            />
          </Card>
        </div>
      </div>
    </AppContent>
  );
}
