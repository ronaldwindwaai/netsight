import { AppContent } from '@/components/app-content';

import { OverviewApplicationMix, OverviewTopDestinations } from '@/components/overview-traffic-cards';
import { RelatedViews } from '@/components/related-views';
import { TimeRangePicker } from '@/components/time-range-picker';
import { TrafficAccessDenied } from '@/components/traffic-access-denied';
import { TrafficNav } from '@/components/traffic-nav';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import {
  parseTrafficApplicationsResponse,
  parseTrafficDestinationsResponse,
} from '@/lib/api-contracts-traffic-explorer';
import {
  MAX_WINDOW_DAYS,
  applicationsPath,
  destinationsPath,
  resolveTrafficWindow,
} from '@/lib/traffic-view';
import { canReadTraffic, viewerFromSession } from '@/lib/viewer';

export const metadata = { title: 'Traffic intelligence' };

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
  const [destinations, applications] = await Promise.all([
    apiGet(destinationsPath(window, 10), parseTrafficDestinationsResponse),
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

      <div className="row g-3">
        <div className="col-xl-6">
          <OverviewTopDestinations state={destinations} window={window} />
        </div>
        <div className="col-xl-6">
          <OverviewApplicationMix state={applications} window={window} />
        </div>
      </div>

      <RelatedViews
        views={[
          { label: 'Security events', href: '/security', hint: 'Detections from the connected security sources' },
          { label: 'Internet / WAN', href: '/internet', hint: 'Link status, quality and availability' },
          { label: 'Users & Identity', href: '/users', hint: 'Who is on the network, according to evidence' },
        ]}
      />
    </AppContent>
  );
}
