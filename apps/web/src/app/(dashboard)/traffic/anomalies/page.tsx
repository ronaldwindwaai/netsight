import { AppContent } from '@/components/app-content';

import { AnomaliesBody } from '@/components/anomalies-body';
import { TimeRangePicker } from '@/components/time-range-picker';
import { TrafficAccessDenied } from '@/components/traffic-access-denied';
import { TrafficNav } from '@/components/traffic-nav';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import { parseTrafficAnomaliesResponse } from '@/lib/api-contracts-traffic-explorer';
import {
  MAX_BASELINE_WINDOW_DAYS,
  anomaliesPath,
  resolveTrafficWindow,
} from '@/lib/traffic-view';
import { canReadTraffic, canReadTrafficDetail, viewerFromSession } from '@/lib/viewer';

export const metadata = { title: 'Traffic anomalies' };

type Params = { preset?: string | string[]; from?: string | string[]; to?: string | string[] };

export default async function AnomaliesPage({ searchParams }: { searchParams: Promise<Params> }) {
  const params = await searchParams;
  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const viewer = viewerFromSession(sessionState.kind === 'ok' ? sessionState.data : null);
  const crumbs = [
    { label: 'Overview', href: '/overview' },
    { label: 'Traffic', href: '/traffic' },
    { label: 'Anomalies' },
  ];

  if (!canReadTraffic(viewer)) {
    return (
      <AppContent title="Anomalies" breadcrumbs={crumbs}>
        <TrafficAccessDenied />
      </AppContent>
    );
  }

  // The baseline surface judges whole hours and accepts at most a week.
  const window = resolveTrafficWindow(params, new Date(), MAX_BASELINE_WINDOW_DAYS);
  const state = await apiGet(anomaliesPath(window), parseTrafficAnomaliesResponse);

  return (
    <AppContent title="Anomalies" breadcrumbs={crumbs}>
      <div className="page-intro">
        <p className="text-body-secondary mb-2">
          Hours that differ from the same hour in prior weeks, compared with a documented, repeatable
          rule. A flag is evidence for a person to look at, not a verdict. Complete hours only; at
          most seven days. Showing {window.label.toLowerCase()}.
        </p>
        <TimeRangePicker section="anomalies" window={window} maxDays={MAX_BASELINE_WINDOW_DAYS} />
      </div>
      <TrafficNav active="anomalies" window={window} />
      <AnomaliesBody state={state} window={window} detail={canReadTrafficDetail(viewer)} />
    </AppContent>
  );
}
