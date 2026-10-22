import { AppContent } from '@/components/app-content';

import { ALERTS_VIEW, RelatedViews } from '@/components/related-views';
import { InternetSlaPanel } from '@/components/internet-sla-panel';
import { InternetStatusBody } from '@/components/internet-status-body';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import { parseInternetResponse, parseSlaResponse } from '@/lib/api-contracts-internet';
import { monthOptions, requestedMonth, slaPath } from '@/lib/internet-view';
import { canExportInternet, viewerFromSession } from '@/lib/viewer';

export default async function InternetPage({
  searchParams,
}: {
  searchParams: Promise<{ month?: string | string[] }>;
}) {
  const now = new Date();
  // The month is validated against the supported range before it reaches the API path.
  const { month, adjusted } = requestedMonth((await searchParams).month, now);
  const [status, sla, session] = await Promise.all([
    apiGet('/api/v1/internet', parseInternetResponse),
    apiGet(slaPath(month), parseSlaResponse),
    apiGet('/api/v1/auth/session', parseSessionInfo),
  ]);
  const viewer = viewerFromSession(session.kind === 'ok' ? session.data : null);

  return (
    <AppContent
      title="Internet / WAN"
      breadcrumbs={[{ label: 'Overview', href: '/overview' }, { label: 'Internet' }]}
    >
      <div className="page-intro">
        <p className="text-body-secondary mb-0">
          Read-only WAN evidence: interface metrics from LibreNMS and latency, jitter, loss and
          availability computed from stored probe samples. Every value comes from a source or is
          shown as not reported; a missing source is never shown as a healthy link.
        </p>
      </div>

      <InternetStatusBody state={status} />

      <InternetSlaPanel
        state={sla}
        month={month}
        months={monthOptions(now)}
        adjusted={adjusted}
        canExport={canExportInternet(viewer)}
      />

      <RelatedViews
        views={[
          { label: 'Traffic overview', href: '/traffic', hint: 'Top destinations and applications' },
          ALERTS_VIEW,
          { label: 'Diagnostics', href: '/diagnostics', hint: 'Run read-only checks to explain a problem' },
        ]}
      />
    </AppContent>
  );
}
