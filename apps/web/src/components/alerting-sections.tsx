import type { ReactNode } from 'react';
import { AppCard } from '@/components/app-card';

import { AlertRulesTable } from '@/components/alert-rules-table';
import { DataFailure } from '@/components/data-state';
import { MaintenanceWindowsTable } from '@/components/maintenance-windows-table';
import { Pager } from '@/components/pager';
import { StateSurface, StoreStateSurface } from '@/components/state-surface';
import { NewRuleButton, NewWindowButton } from '@/components/alerting-write-controls';
import type { FetchState } from '@/lib/api';
import type {
  AlertRuleListResponse,
  MaintenanceWindowListResponse,
} from '@/lib/api-contracts-alert-rule-api';
import { alertingPageHrefs, windowCounts } from '@/lib/alerting-view';
import type { AlertingOffsets } from '@/lib/alerting-view';
import { formatUtcTimestamp } from '@/lib/format-time';
import type { Viewer } from '@/lib/incident-actions';

interface PagingContext {
  offsets: AlertingOffsets;
  alertsPage: number;
}

function Failure<T>({ state }: { state: Exclude<FetchState<T>, { kind: 'ok' }> }) {
  return (
    <div className="p-3" aria-live="polite">
      <DataFailure state={state} />
    </div>
  );
}

function RulesBody({
  state,
  paging,
  retrievedAt,
  viewer,
}: {
  state: FetchState<AlertRuleListResponse>;
  paging: PagingContext;
  retrievedAt: string;
  viewer: Viewer | null;
}): ReactNode {
  if (state.kind !== 'ok') return <Failure state={state} />;
  const response = state.data;
  if (response.state !== 'ok') {
    return <StoreStateSurface state={response.state} noun="alert rules" store="Alert rule store" />;
  }
  if (response.rules.length === 0) {
    return (
      <StateSurface
        icon="bi bi-bell-slash"
        title="No alert rules"
        detail="The alert rule store returned a valid empty result for this page."
      />
    );
  }
  return (
    <>
      <p className="small text-body-secondary px-3 pt-3 mb-2">
        {response.rules.length} rule{response.rules.length === 1 ? '' : 's'} listed on this page.
        Status and approval are as recorded by the API; only an approved, active rule is evaluated.
        Retrieved {retrievedAt}; the alert-rule API does not report a freshness value.
      </p>
      <AlertRulesTable rules={response.rules} viewer={viewer} />
      <Pager
        label="Alert rule pages"
        hrefs={alertingPageHrefs(
          'rules',
          paging.offsets,
          response.limit,
          response.next_offset,
          paging.alertsPage,
        )}
      />
    </>
  );
}

function WindowsBody({
  state,
  paging,
  nowMs,
  retrievedAt,
  viewer,
}: {
  state: FetchState<MaintenanceWindowListResponse>;
  paging: PagingContext;
  nowMs: number;
  retrievedAt: string;
  viewer: Viewer | null;
}): ReactNode {
  if (state.kind !== 'ok') return <Failure state={state} />;
  const response = state.data;
  if (response.state !== 'ok') {
    return (
      <StoreStateSurface
        state={response.state}
        noun="maintenance windows"
        store="Maintenance window store"
      />
    );
  }
  if (response.windows.length === 0) {
    return (
      <StateSurface
        icon="bi bi-calendar-x"
        title="No maintenance windows"
        detail="The store returned a valid empty result for this page."
      />
    );
  }
  const counts = windowCounts(response.windows, nowMs);
  return (
    <>
      <p className="small text-body-secondary px-3 pt-3 mb-2">
        Of the {counts.listed} listed window{counts.listed === 1 ? '' : 's'}: {counts.active} active
        now, {counts.upcoming} upcoming, {counts.ended} ended, {counts.cancelled} cancelled
        {counts.unknown > 0 ? `, ${counts.unknown} unknown` : ''}. Phase is evaluated at{' '}
        {formatUtcTimestamp(new Date(nowMs).toISOString())}. Retrieved {retrievedAt}; the
        maintenance-window API does not report a freshness value.
      </p>
      <MaintenanceWindowsTable windows={response.windows} nowMs={nowMs} viewer={viewer} />
      <Pager
        label="Maintenance window pages"
        hrefs={alertingPageHrefs(
          'windows',
          paging.offsets,
          response.limit,
          response.next_offset,
          paging.alertsPage,
        )}
      />
    </>
  );
}

export function AlertRulesCard(props: {
  state: FetchState<AlertRuleListResponse>;
  paging: PagingContext;
  retrievedAt: string;
  viewer: Viewer | null;
}) {
  return (
    <AppCard
      className="operational-card"
      title="Alert rules"
      icon="bi bi-sliders"
      variant="outline"
      theme="primary"
      bodyClass="p-0"
    >
      <div className="p-3 border-bottom">
        <NewRuleButton viewer={props.viewer} />
      </div>
      <RulesBody
        state={props.state}
        paging={props.paging}
        retrievedAt={props.retrievedAt}
        viewer={props.viewer}
      />
    </AppCard>
  );
}

export function MaintenanceWindowsCard(props: {
  state: FetchState<MaintenanceWindowListResponse>;
  paging: PagingContext;
  nowMs: number;
  retrievedAt: string;
  viewer: Viewer | null;
}) {
  return (
    <AppCard
      className="operational-card"
      title="Maintenance windows"
      icon="bi bi-tools"
      variant="outline"
      theme="info"
      bodyClass="p-0"
    >
      <div className="p-3 border-bottom">
        <NewWindowButton viewer={props.viewer} />
      </div>
      <WindowsBody
        state={props.state}
        paging={props.paging}
        nowMs={props.nowMs}
        retrievedAt={props.retrievedAt}
        viewer={props.viewer}
      />
    </AppCard>
  );
}
