import { Suspense } from 'react';
import { AppCard } from '@/components/app-card';
import { AppContent } from '@/components/app-content';
import { RetryButton } from '@/components/retry-button';

import { PageControls } from '@/components/page-controls';
import { AlertTable } from '@/components/alert-table';
import { AlertRulesCard, MaintenanceWindowsCard } from '@/components/alerting-sections';
import { DataFailure, FreshnessNotice, LoadingState } from '@/components/data-state';
import { apiGet } from '@/lib/api';
import { parseAlertList, parseSessionInfo } from '@/lib/api-contracts';
import { parseAlertRuleListResponse, parseMaintenanceWindowListResponse } from '@/lib/api-contracts-alert-rule-api';
import { alertingListPath, parseAlertingOffsets } from '@/lib/alerting-view';
import { formatUtcTimestamp } from '@/lib/format-time';
import type { RawQuery } from '@/lib/incident-view';
import { parsePageParams } from '@/lib/page-state';
import { preferredPageSize } from '@/lib/preferred-page-size';
import { viewerFromSession } from '@/lib/viewer';

export const metadata = { title: 'Alerts' };

export default async function AlertsPage({
  searchParams,
}: {
  searchParams: Promise<RawQuery>;
}) {
  const query = await searchParams;
  const { page, pageSize } = parsePageParams(query, await preferredPageSize());
  const offsets = parseAlertingOffsets(query);
  const nowMs = new Date().getTime();
  const [rules, windows, sessionState] = await Promise.all([
    apiGet(alertingListPath('rules', offsets.rules), parseAlertRuleListResponse),
    apiGet(alertingListPath('windows', offsets.windows), parseMaintenanceWindowListResponse),
    apiGet('/api/v1/auth/session', parseSessionInfo),
  ]);
  const viewer = sessionState.kind === 'ok' ? viewerFromSession(sessionState.data) : null;
  const paging = { offsets, alertsPage: page };
  const state = await apiGet(
    `/api/v1/alerts?page=${page}&page_size=${pageSize}`,
    parseAlertList,
  );
  const retrievedAt = formatUtcTimestamp(new Date().toISOString());

  return (
    <AppContent title="Alerts" breadcrumbs={[{ label: 'Overview', href: '/overview' }, { label: 'Alerts' }]}>
      <div className="page-intro">
        <p className="text-body-secondary mb-0">
          Read-only alerts mapped from LibreNMS, plus the alert rules and maintenance windows
          held by Netsight, which you can change as far as your role permits. Rule and window
          names, labels and reasons are operator-entered text and are displayed as data only.
        </p>
      </div>

      <h2 className="h5">Source alerts</h2>
      {state.kind !== 'ok' ? (
        <DataFailure state={state} />
      ) : (
        <>
          <FreshnessNotice freshness={state.data.freshness} />
          {state.data.items.length === 0 && state.data.total === 0 ? (
            <AppCard className="text-center" bodyClass="py-5">
              <i className="bi bi-bell-slash fs-2 text-body-secondary" aria-hidden="true" />
              <h2 className="h5 mt-3">No active source alerts</h2>
              <p className="text-body-secondary">
                LibreNMS returned a valid empty alert collection.
              </p>
              <RetryButton label="Refresh" />
            </AppCard>
          ) : (
            <>
              <Suspense fallback={<LoadingState label="Loading alerts" />}>
                <AlertTable alerts={state.data.items} total={state.data.total} />
              </Suspense>
              <PageControls
                count={state.data.items.length}
                label="Alert pages"
                noun="alerts"
                page={state.data.page}
                pageSize={state.data.page_size}
                total={state.data.total}
              />
            </>
          )}
        </>
      )}

      <div className="mt-4">
        <AlertRulesCard state={rules} paging={paging} retrievedAt={retrievedAt} viewer={viewer} />
        <MaintenanceWindowsCard
          state={windows}
          paging={paging}
          nowMs={nowMs}
          retrievedAt={retrievedAt}
          viewer={viewer}
        />
      </div>
    </AppContent>
  );
}
