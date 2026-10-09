import type { ReactNode } from 'react';
import { AppContent, Card } from '@adminlte/react';

import { DataFailure } from '@/components/data-state';
import { IncidentFiltersForm } from '@/components/incident-filters';
import { IncidentListTable } from '@/components/incident-list-table';
import { Pager } from '@/components/pager';
import { StateSurface, StoreStateSurface } from '@/components/state-surface';
import { apiGet } from '@/lib/api';
import type { FetchState } from '@/lib/api';
import { parseIncidentListResponse } from '@/lib/api-contracts-incident-api';
import type { IncidentListResponse } from '@/lib/api-contracts-incident-api';
import { formatUtcTimestamp } from '@/lib/format-time';
import {
  DEFAULT_INCIDENT_PAGE_SIZE,
  SEVERITY_DISPLAY_ORDER,
  incidentCounts,
  incidentListPath,
  incidentPageHrefs,
  parseIncidentFilters,
  severityLabel,
} from '@/lib/incident-view';
import type { IncidentFilters, RawQuery } from '@/lib/incident-view';

function CountsStrip({ response }: { response: IncidentListResponse }) {
  const counts = incidentCounts(response.incidents);
  return (
    <section className="px-3 pt-3" aria-label="Severity counts of the listed incidents">
      <div className="row g-2 mb-2">
        {SEVERITY_DISPLAY_ORDER.map((severity) => (
          <div className="col-6 col-md-3" key={severity}>
            <div className="border rounded p-2 text-center">
              <div className="fs-4 fw-semibold">{counts.bySeverity[severity]}</div>
              <div className="small text-body-secondary">{severityLabel(severity)}</div>
            </div>
          </div>
        ))}
      </div>
      <p className="small text-body-secondary mb-2">
        Counts are of the {counts.listed} listed incident{counts.listed === 1 ? '' : 's'} on this
        page only, not a total across all pages.
      </p>
    </section>
  );
}

function ListBody({
  state,
  filters,
}: {
  state: FetchState<IncidentListResponse>;
  filters: IncidentFilters;
}): ReactNode {
  if (state.kind !== 'ok') {
    return (
      <div className="p-3" aria-live="polite">
        <DataFailure state={state} />
      </div>
    );
  }
  const response = state.data;
  if (response.state !== 'ok') {
    return (
      <StoreStateSurface state={response.state} noun="incidents" store="Incident store" />
    );
  }
  const filtered =
    filters.state !== null || filters.severity !== null || filters.assigneeId !== null;
  if (response.incidents.length === 0) {
    return (
      <StateSurface
        icon="bi bi-inbox"
        title={filtered ? 'No incidents match these filters' : 'No incidents'}
        detail={
          filtered
            ? 'The incident store returned a valid empty result for the selected filters or page.'
            : 'The incident store returned a valid empty result. This is not proof that nothing happened outside the sources Netsight reads.'
        }
      />
    );
  }
  return (
    <>
      <CountsStrip response={response} />
      <IncidentListTable incidents={response.incidents} />
      <Pager
        label="Incident pages"
        hrefs={incidentPageHrefs(filters, response.limit || DEFAULT_INCIDENT_PAGE_SIZE, response.next_offset)}
      />
    </>
  );
}

export default async function IncidentsPage({
  searchParams,
}: {
  searchParams: Promise<RawQuery>;
}) {
  const filters = parseIncidentFilters(await searchParams);
  const state = await apiGet(incidentListPath(filters), parseIncidentListResponse);
  const retrievedAt = formatUtcTimestamp(new Date().toISOString());

  return (
    <AppContent
      title="Incidents"
      breadcrumbs={[{ label: 'Overview', href: '/overview' }, { label: 'Incidents' }]}
    >
      <div className="page-intro d-flex flex-wrap align-items-end justify-content-between gap-2">
        <p className="text-body-secondary mb-0">
          Read-only incident list, newest first. Titles and assignees are operator-entered text and
          are displayed as data only. Retrieved {retrievedAt}; the incident API does not report a
          freshness value.
        </p>
      </div>

      <IncidentFiltersForm filters={filters} />

      <Card
        className="operational-card"
        title="Incidents"
        icon="bi bi-exclamation-triangle"
        variant="outline"
        theme="primary"
        bodyClass="p-0"
      >
        <ListBody state={state} filters={filters} />
      </Card>
    </AppContent>
  );
}
