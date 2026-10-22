import Link from 'next/link';
import { AppCard } from '@/components/app-card';
import { AppContent } from '@/components/app-content';

import { AlertTable } from '@/components/alert-table';
import { AlertRulesCard, MaintenanceWindowsCard } from '@/components/alerting-sections';
import { DataFailure, FreshnessNotice } from '@/components/data-state';
import { apiGet } from '@/lib/api';
import { parseAlertList, parseSessionInfo } from '@/lib/api-contracts';
import { parseAlertRuleListResponse, parseMaintenanceWindowListResponse } from '@/lib/api-contracts-alert-rule-api';
import { alertingListPath, parseAlertingOffsets } from '@/lib/alerting-view';
import { formatUtcTimestamp } from '@/lib/format-time';
import type { RawQuery } from '@/lib/incident-view';
import { viewerFromSession } from '@/lib/viewer';

const PAGE_SIZE = 50;

function requestedPage(value: string | string[] | undefined): number {
  const raw = Array.isArray(value) ? value[0] : value;
  if (!raw || !/^\d+$/.test(raw)) return 1;
  const parsed = Number(raw);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : 1;
}

export default async function AlertsPage({
  searchParams,
}: {
  searchParams: Promise<RawQuery>;
}) {
  const query = await searchParams;
  const page = requestedPage(query.page);
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
    `/api/v1/alerts?page=${page}&page_size=${PAGE_SIZE}`,
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
              <p className="mb-0 text-body-secondary">
                LibreNMS returned a valid empty alert collection.
              </p>
            </AppCard>
          ) : (
            <>
              <AlertTable alerts={state.data.items} total={state.data.total} />
              <nav
                className="d-flex align-items-center justify-content-between mt-3"
                aria-label="Alert pages"
              >
                <Link
                  aria-disabled={state.data.page <= 1}
                  className={`btn btn-outline-secondary btn-sm ${state.data.page <= 1 ? 'disabled' : ''}`}
                  href={`/alerts?page=${Math.max(1, state.data.page - 1)}`}
                  tabIndex={state.data.page <= 1 ? -1 : undefined}
                >
                  <i className="bi bi-chevron-left me-1" aria-hidden="true" />
                  Previous
                </Link>
                <span className="small text-body-secondary">
                  Page {state.data.page} of{' '}
                  {Math.max(1, Math.ceil(state.data.total / state.data.page_size))}
                </span>
                <Link
                  aria-disabled={state.data.page * state.data.page_size >= state.data.total}
                  className={`btn btn-outline-secondary btn-sm ${
                    state.data.page * state.data.page_size >= state.data.total ? 'disabled' : ''
                  }`}
                  href={`/alerts?page=${state.data.page + 1}`}
                  tabIndex={
                    state.data.page * state.data.page_size >= state.data.total ? -1 : undefined
                  }
                >
                  Next
                  <i className="bi bi-chevron-right ms-1" aria-hidden="true" />
                </Link>
              </nav>
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
