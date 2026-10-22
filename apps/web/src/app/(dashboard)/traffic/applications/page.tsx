import { AppContent } from '@/components/app-content';

import { ApplicationsBody } from '@/components/applications-body';
import { TimeRangePicker } from '@/components/time-range-picker';
import { TrafficAccessDenied } from '@/components/traffic-access-denied';
import { TrafficNav } from '@/components/traffic-nav';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import { parseTrafficApplicationsResponse } from '@/lib/api-contracts-traffic-explorer';
import {
  DEFAULT_LIST_LIMIT,
  MAX_WINDOW_DAYS,
  applicationsPath,
  resolveTrafficWindow,
} from '@/lib/traffic-view';
import { canReadTraffic, viewerFromSession } from '@/lib/viewer';

export const metadata = { title: 'Applications' };

type Params = { preset?: string | string[]; from?: string | string[]; to?: string | string[] };

export default async function ApplicationsPage({ searchParams }: { searchParams: Promise<Params> }) {
  const params = await searchParams;
  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const viewer = viewerFromSession(sessionState.kind === 'ok' ? sessionState.data : null);
  const crumbs = [
    { label: 'Overview', href: '/overview' },
    { label: 'Traffic', href: '/traffic' },
    { label: 'Applications' },
  ];

  if (!canReadTraffic(viewer)) {
    return (
      <AppContent title="Applications" breadcrumbs={crumbs}>
        <TrafficAccessDenied />
      </AppContent>
    );
  }

  const window = resolveTrafficWindow(params, new Date(), MAX_WINDOW_DAYS);
  const state = await apiGet(applicationsPath(window, DEFAULT_LIST_LIMIT), parseTrafficApplicationsResponse);

  return (
    <AppContent title="Applications" breadcrumbs={crumbs}>
      <div className="page-intro">
        <p className="text-body-secondary mb-2">
          Applications as the flow source labels them, with volume and trend. Approval and risk come
          only from the operator traffic policy; without one they are Unknown. Netsight does not infer
          an application from a port. Showing {window.label.toLowerCase()}.
        </p>
        <TimeRangePicker section="applications" window={window} maxDays={MAX_WINDOW_DAYS} />
      </div>
      <TrafficNav active="applications" window={window} />
      <ApplicationsBody state={state} window={window} />
    </AppContent>
  );
}
