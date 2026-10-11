import { AppContent } from '@adminlte/react';

import { OverviewApplicationMix, OverviewTopTalkers } from '@/components/overview-traffic-cards';
import { TimeRangePicker } from '@/components/time-range-picker';
import { TrafficAccessDenied } from '@/components/traffic-access-denied';
import { TrafficBars } from '@/components/traffic-bars';
import { TrafficNav } from '@/components/traffic-nav';
import { TrafficPanel } from '@/components/traffic-panel';
import { StateSurface } from '@/components/state-surface';
import { TrafficGate } from '@/components/traffic-surface';
import { apiGet } from '@/lib/api';
import { parseSessionInfo, parseTrafficTopResponse } from '@/lib/api-contracts';
import { parseTrafficApplicationsResponse } from '@/lib/api-contracts-traffic-explorer';
import {
  MAX_WINDOW_DAYS,
  applicationsPath,
  resolveTrafficWindow,
} from '@/lib/traffic-view';
import { canReadTraffic, canReadTrafficDetail, viewerFromSession } from '@/lib/viewer';

type Params = { preset?: string | string[]; from?: string | string[]; to?: string | string[] };

export default async function TrafficPage({ searchParams }: { searchParams: Promise<Params> }) {
  const params = await searchParams;
  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const viewer = viewerFromSession(sessionState.kind === 'ok' ? sessionState.data : null);
  const crumbs = [{ label: 'Overview', href: '/overview' }, { label: 'Traffic' }];

  if (!canReadTraffic(viewer)) {
    // No traffic permission (Technician, today): no controls and no API call to be refused.
    return (
      <AppContent title="Traffic intelligence" breadcrumbs={crumbs}>
        <TrafficAccessDenied />
      </AppContent>
    );
  }

  const window = resolveTrafficWindow(params, new Date(), MAX_WINDOW_DAYS);
  const detail = canReadTrafficDetail(viewer);
  const [talkers, destinations, applications] = await Promise.all([
    detail ? apiGet(`/api/v1/traffic/top-talkers?${window.query}&limit=10`, parseTrafficTopResponse) : null,
    apiGet(`/api/v1/traffic/top-destinations?${window.query}&limit=10`, parseTrafficTopResponse),
    apiGet(applicationsPath(window, 6), parseTrafficApplicationsResponse),
  ]);

  return (
    <AppContent title="Traffic intelligence" breadcrumbs={crumbs}>
      <div className="page-intro">
        <p className="text-body-secondary mb-2">
          Read-only flow evidence from the connected source. Empty, unknown and not-connected are
          shown distinctly: Netsight never estimates traffic. Showing {window.label.toLowerCase()}.
        </p>
        <TimeRangePicker section="overview" window={window} maxDays={MAX_WINDOW_DAYS} />
      </div>
      <TrafficNav active="overview" window={window} />

      <div className="row g-3 mb-3">
        <div className="col-xl-6">
          <OverviewTopTalkers state={talkers} window={window} />
        </div>
        <div className="col-xl-6">
          <TrafficPanel title="Top destinations" icon="bi-globe2">
            <TrafficGate state={destinations} noun="destinations" permission="traffic:read">
              {(data) =>
                data.items.length === 0 ? (
                  <StateSurface
                    icon="bi bi-inboxes"
                    title="No traffic in this window"
                    detail="The flow source reported a valid empty result for the selected time range."
                  />
                ) : (
                  <TrafficBars items={data.items} />
                )
              }
            </TrafficGate>
          </TrafficPanel>
        </div>
      </div>
      <div className="row g-3">
        <div className="col-xl-6">
          <OverviewApplicationMix state={applications} window={window} />
        </div>
      </div>
    </AppContent>
  );
}
