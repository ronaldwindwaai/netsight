import { AppContent } from '@adminlte/react';

import { DestinationsBody } from '@/components/destinations-body';
import { TimeRangePicker } from '@/components/time-range-picker';
import { TrafficAccessDenied } from '@/components/traffic-access-denied';
import { TrafficNav } from '@/components/traffic-nav';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import { parseTrafficDestinationsResponse } from '@/lib/api-contracts-traffic-explorer';
import {
  DEFAULT_LIST_LIMIT,
  MAX_WINDOW_DAYS,
  destinationsPath,
  resolveTrafficWindow,
} from '@/lib/traffic-view';
import { canReadTraffic, viewerFromSession } from '@/lib/viewer';

type Params = { preset?: string | string[]; from?: string | string[]; to?: string | string[] };

export default async function DestinationsPage({ searchParams }: { searchParams: Promise<Params> }) {
  const params = await searchParams;
  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const viewer = viewerFromSession(sessionState.kind === 'ok' ? sessionState.data : null);
  const crumbs = [
    { label: 'Overview', href: '/overview' },
    { label: 'Traffic', href: '/traffic' },
    { label: 'Destinations' },
  ];

  if (!canReadTraffic(viewer)) {
    return (
      <AppContent title="Destinations" breadcrumbs={crumbs}>
        <TrafficAccessDenied />
      </AppContent>
    );
  }

  const window = resolveTrafficWindow(params, new Date(), MAX_WINDOW_DAYS);
  const state = await apiGet(destinationsPath(window, DEFAULT_LIST_LIMIT), parseTrafficDestinationsResponse);

  return (
    <AppContent title="Destinations" breadcrumbs={crumbs}>
      <div className="page-intro">
        <p className="text-body-secondary mb-2">
          Where traffic goes, with the domain, ASN and country the flow source reports. Reputation
          comes only from the operator allow and deny lists; without them it is Unknown. Metadata
          only: encrypted content is never visible here. Showing {window.label.toLowerCase()}.
        </p>
        <TimeRangePicker section="destinations" window={window} maxDays={MAX_WINDOW_DAYS} />
      </div>
      <TrafficNav active="destinations" window={window} />
      <DestinationsBody state={state} />
    </AppContent>
  );
}
