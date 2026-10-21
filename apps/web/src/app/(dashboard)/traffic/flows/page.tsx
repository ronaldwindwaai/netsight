import { AppContent } from '@adminlte/react';

import { AppliedFilters } from '@/components/applied-filters';
import { ExplorerFilterForm } from '@/components/explorer-filter-form';
import { FlowExplorerBody } from '@/components/flow-explorer-body';
import { RelatedViews } from '@/components/related-views';
import { TimeRangePicker } from '@/components/time-range-picker';
import { TrafficAccessDenied } from '@/components/traffic-access-denied';
import { TrafficNav } from '@/components/traffic-nav';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import { parseTrafficFlowsResponse } from '@/lib/api-contracts-traffic-explorer';
import {
  DEFAULT_FLOW_LIMIT,
  MAX_WINDOW_DAYS,
  flowsPath,
  parseExplorerFilters,
  resolveTrafficWindow,
  flowsDrillHref,
} from '@/lib/traffic-view';
import {
  canReadInventory,
  canReadPeople,
  canReadTraffic,
  canReadTrafficDetail,
  viewerFromSession,
} from '@/lib/viewer';

type Params = Record<string, string | string[] | undefined>;

export default async function FlowExplorerPage({ searchParams }: { searchParams: Promise<Params> }) {
  const params = await searchParams;
  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const viewer = viewerFromSession(sessionState.kind === 'ok' ? sessionState.data : null);
  const crumbs = [
    { label: 'Overview', href: '/overview' },
    { label: 'Traffic', href: '/traffic' },
    { label: 'Flow Explorer' },
  ];

  if (!canReadTraffic(viewer)) {
    return (
      <AppContent title="Flow Explorer" breadcrumbs={crumbs}>
        <TrafficAccessDenied />
      </AppContent>
    );
  }

  const detail = canReadTrafficDetail(viewer);
  const window = resolveTrafficWindow(params, new Date(), MAX_WINDOW_DAYS);
  // Filters are validated against the same allow-list the API enforces before they can reach a path.
  const filters = parseExplorerFilters(params, { detail });
  const state = await apiGet(
    flowsPath(window, filters.values, DEFAULT_FLOW_LIMIT),
    parseTrafficFlowsResponse,
  );
  const filtered = Object.keys(filters.values).length > 0;

  return (
    <AppContent title="Flow Explorer" breadcrumbs={crumbs}>
      <div className="page-intro">
        <p className="text-body-secondary mb-2">
          Filter flows and see volume, timeline, application mix and destinations for the whole
          filtered window. Who is behind an address is shown only through the identity service, with
          its basis (observed, inferred or unknown); an address alone is never an identity. Reads
          that name people are audited. Showing {window.label.toLowerCase()}.
        </p>
        <TimeRangePicker
          section="flows"
          window={window}
          maxDays={MAX_WINDOW_DAYS}
          filters={filters.values}
        />
      </div>
      <TrafficNav active="flows" window={window} />
      <ExplorerFilterForm
        window={window}
        values={filters.values}
        refused={filters.refused}
        detail={detail}
      />
      <AppliedFilters window={window} values={filters.values} />
      <FlowExplorerBody
        state={state}
        filtered={filtered}
        linkTo={
          detail
            ? (extra) => flowsDrillHref(window, { ...filters.values, ...extra }, { detail })
            : undefined
        }
        access={{ people: canReadPeople(viewer), devices: canReadInventory(viewer) }}
      />
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
