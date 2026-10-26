import Link from 'next/link';
import { AppCard } from '@/components/app-card';
import { AppContent } from '@/components/app-content';

import { DataFailure, FreshnessNotice } from '@/components/data-state';
import { FirstRunChecklist } from '@/components/first-run-checklist';
import { OverviewKpiLink } from '@/components/overview-kpi-link';
import { OverviewRefresh } from '@/components/overview-refresh';
import { OverviewStatusStrip } from '@/components/overview-status-strip';
import { OverviewIncidentsCard } from '@/components/overview-incidents-card';
import { OverviewInternetKpi } from '@/components/overview-internet-kpi';
import { OverviewApplicationMix, OverviewTopDestinations } from '@/components/overview-traffic-cards';
import { TopologyView } from '@/components/topology-graph';
import { apiGet } from '@/lib/api';
import { parseOverviewResponse, parseSessionInfo, parseTopologyResponse } from '@/lib/api-contracts';
import { parseSecurityEventsResponse } from '@/lib/api-contracts-security';
import { parseUsersAggregateResponse } from '@/lib/api-contracts-users';
import { parseInternetResponse } from '@/lib/api-contracts-internet';
import { parseIncidentListResponse, parseIncidentSummaryListResponse } from '@/lib/api-contracts-incident-api';
import { firstRunChecklist } from '@/lib/first-run';
import { overviewIncidentRequest } from '@/lib/overview-incidents';
import { overviewTopology } from '@/lib/overview-topology';
import {
  parseTrafficApplicationsResponse,
  parseTrafficDestinationsResponse,
} from '@/lib/api-contracts-traffic-explorer';
import { deviceHealthSummary, sourceProvenance } from '@/lib/overview-summary';
import {
  overviewSecurityRequest,
  overviewUsersAccess,
  overviewUsersRequest,
  securityTile,
  usersTile,
} from '@/lib/overview-tiles';
import { canReadTraffic, viewerFromSession } from '@/lib/viewer';

export const metadata = { title: 'Network overview' };

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

function fetchIncidents(permissions: readonly string[] | null) {
  const request = overviewIncidentRequest(permissions);
  if (request === null) return Promise.resolve(null);
  return request.kind === 'summary'
    ? apiGet(request.path, parseIncidentSummaryListResponse)
    : apiGet(request.path, parseIncidentListResponse);
}

export default async function OverviewPage() {
  const updatedAt = new Date().toISOString();
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
  const permissions = session.kind === 'ok' ? session.data.permissions : null;
  const securityPath = overviewSecurityRequest(permissions);
  const usersPath = overviewUsersRequest(permissions);
  const usersAccess = overviewUsersAccess(permissions);
  const [incidents, security, users, topologyState] = await Promise.all([
    fetchIncidents(permissions),
    securityPath === null ? null : apiGet(securityPath, parseSecurityEventsResponse),
    usersPath === null ? null : apiGet(usersPath, parseUsersAggregateResponse),
    apiGet('/api/v1/topology', parseTopologyResponse),
  ]);
  // One after the other: the API admits a single heavy flow read per account at a time, so two
  // concurrent reads would always refuse the second (429 TRAFFIC_CONCURRENCY).
  const readsTraffic = sessionUnread || canReadTraffic(viewer);
  const destinations = readsTraffic
    ? await apiGet('/api/v1/traffic/destinations?preset=24h&limit=5', parseTrafficDestinationsResponse)
    : null;
  const applications = readsTraffic
    ? await apiGet('/api/v1/traffic/applications?preset=24h&limit=6', parseTrafficApplicationsResponse)
    : null;
  const topologyCard = overviewTopology(topologyState);
  const overview = state.kind === 'ok' ? state.data : null;
  const firstRun = firstRunChecklist({
    devices: state,
    security,
    traffic: destinations,
    internet,
  });
  const health = overview
    ? deviceHealthSummary(overview.devices)
    : firstRun.show
      ? { ...deviceHealthSummary(null), title: 'Not connected', detail: 'Connect LibreNMS (see the checklist)' }
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
        <div className="d-flex flex-wrap align-items-center gap-3">
          <OverviewRefresh updatedAt={updatedAt} />
          <span className="source-provenance">
            <span
              className={`source-provenance__dot ${provenance.tone}`}
              aria-hidden="true"
            />
            {provenance.label}
          </span>
        </div>
      </div>

      <FirstRunChecklist checklist={firstRun} />
      {state.kind !== 'ok' && !firstRun.show ? <DataFailure state={state} /> : null}
      {state.kind === 'ok' ? (
        <FreshnessNotice freshness={state.data.devices.freshness} />
      ) : null}

      <section className="overview-kpi-grid" aria-label="Operational summary">
        <OverviewKpiLink
          href="/devices"
          icon="bi-heart-pulse"
          label="Network health"
          value={health.title}
          detail={health.detail}
          theme={health.theme}
          progress={health.progress}
        />
        <OverviewInternetKpi state={internet} />
        <OverviewKpiLink
          href={security === null ? undefined : '/security'}
          icon="bi-shield-exclamation"
          label="Security"
          {...securityTile(security)}
        />
        <OverviewKpiLink
          href={usersAccess === 'none' ? undefined : '/users'}
          icon="bi-people"
          label="Users"
          {...usersTile(usersAccess === 'per-person' ? 'per-person' : users)}
        />
      </section>

      <OverviewStatusStrip summary={overview ? overview.devices : null} />

      <div className="row g-3 mb-3">
        <div className="col-xl-8 order-2 order-xl-1">
          <AppCard
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
            {topologyCard.kind === 'graph' ? (
              <TopologyView topology={topologyCard.topology} focus={null} />
            ) : (
              <UnavailableSurface
                icon="bi-bezier2"
                title={topologyCard.title}
                detail={topologyCard.detail}
              />
            )}
          </AppCard>
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
