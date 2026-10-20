import Link from 'next/link';
import { AppContent, Card, InfoBox } from '@adminlte/react';

import { DataFailure, FreshnessNotice } from '@/components/data-state';
import { OverviewIncidentsCard } from '@/components/overview-incidents-card';
import { OverviewInternetKpi } from '@/components/overview-internet-kpi';
import { OverviewApplicationMix, OverviewTopDestinations } from '@/components/overview-traffic-cards';
import { apiGet } from '@/lib/api';
import { parseOverviewResponse, parseSessionInfo } from '@/lib/api-contracts';
import { parseInternetResponse } from '@/lib/api-contracts-internet';
import { parseIncidentListResponse, parseIncidentSummaryListResponse } from '@/lib/api-contracts-incident-api';
import { incidentReadMode } from '@/lib/incident-view';
import {
  parseTrafficApplicationsResponse,
  parseTrafficDestinationsResponse,
} from '@/lib/api-contracts-traffic-explorer';
import { deviceHealthSummary, sourceProvenance } from '@/lib/overview-summary';
import { canReadTraffic, viewerFromSession } from '@/lib/viewer';

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

function fetchIncidents(mode: ReturnType<typeof incidentReadMode>) {
  if (mode === 'none') return Promise.resolve(null);
  return mode === 'summary'
    ? apiGet('/api/v1/incidents/summary?limit=50', parseIncidentSummaryListResponse)
    : apiGet('/api/v1/incidents?limit=50', parseIncidentListResponse);
}

export default async function OverviewPage() {
  const [state, internet, session] = await Promise.all([
    apiGet('/api/v1/overview', parseOverviewResponse),
    apiGet('/api/v1/internet', parseInternetResponse),
    apiGet('/api/v1/auth/session', parseSessionInfo),
  ]);
  // Traffic is fetched only for a role that holds the permission; the others see "Restricted"
  // rather than a refused request. When the session itself could not be read the API decides (its
  // refusal also renders as Restricted). The API enforces the same rules on its own.
  const viewer = viewerFromSession(session.kind === 'ok' ? session.data : null);
  const sessionUnread = session.kind !== 'ok';
  const incidentMode = incidentReadMode(session.kind === 'ok' ? session.data.permissions : null);
  const [incidents, destinations, applications] = await Promise.all([
    fetchIncidents(incidentMode),
    sessionUnread || canReadTraffic(viewer)
      ? apiGet('/api/v1/traffic/destinations?preset=24h&limit=5', parseTrafficDestinationsResponse)
      : null,
    sessionUnread || canReadTraffic(viewer)
      ? apiGet('/api/v1/traffic/applications?preset=24h&limit=6', parseTrafficApplicationsResponse)
      : null,
  ]);
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
        <OverviewInternetKpi state={internet} />
        <Link className="overview-kpi-link overview-kpi--unknown" href="/security" aria-label="Security: not summarised on the overview. Open security events.">
          <InfoBox
            icon="bi-shield-exclamation"
            text="Security"
            title="Not summarised"
            theme="secondary"
            progress={0}
            progressText="Open security events"
          />
        </Link>
        <Link className="overview-kpi-link overview-kpi--unknown" href="/users" aria-label="Users: not summarised on the overview. Open users.">
          <InfoBox
            icon="bi-people"
            text="Users"
            title="Not summarised"
            theme="secondary"
            progress={0}
            progressText="Open users"
          />
        </Link>
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
              <Link className="btn btn-sm btn-outline-primary" href="/network/map">
                Open network map
              </Link>
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
          <OverviewIncidentsCard state={incidents} />
        </div>
      </div>

      <div className="row g-3">
        <div className="col-xl-6">
          <OverviewTopDestinations state={destinations} />
        </div>
        <div className="col-xl-6">
          <OverviewApplicationMix state={applications} />
        </div>
      </div>
    </AppContent>
  );
}
