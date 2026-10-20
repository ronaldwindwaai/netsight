import Link from 'next/link';
import { Card } from '@adminlte/react';

import type { FetchState } from '@/lib/api-response';
import type {
  IncidentListResponse,
  IncidentSummaryListResponse,
} from '@/lib/api-contracts-incident-api';
import { SEVERITY_DISPLAY_ORDER, incidentCounts } from '@/lib/incident-view';

import { StateSurface, StoreStateSurface } from './state-surface';

type IncidentsState = FetchState<IncidentListResponse | IncidentSummaryListResponse> | null;

const ACTIVE_STATES = new Set(['open', 'acknowledged', 'investigating', 'mitigated']);

function OpenLink() {
  return (
    <Link className="btn btn-sm btn-outline-primary" href="/incidents">
      Open incidents
      <i className="bi bi-arrow-right ms-1" aria-hidden="true" />
    </Link>
  );
}

function Body({ state }: { state: IncidentsState }) {
  if (state === null) {
    return (
      <StateSurface
        icon="bi bi-shield-lock"
        title="Restricted"
        detail="Your role does not include incident access (incidents:read-summary or incidents:read)."
      />
    );
  }
  if (state.kind !== 'ok') {
    return (
      <StateSurface
        icon="bi bi-question-circle"
        title="Incidents could not be read"
        detail="The incident API did not answer. No count is shown and nothing is estimated."
      />
    );
  }
  const response = state.data;
  if (response.state !== 'ok') {
    return <StoreStateSurface state={response.state} noun="incidents" store="Incident store" />;
  }
  if (response.incidents.length === 0) {
    return (
      <StateSurface
        icon="bi bi-inbox"
        title="No incidents listed"
        detail="The incident store returned a valid empty list. This is not proof that nothing happened outside the sources Netsight reads."
      />
    );
  }
  const active = response.incidents.filter((incident) => ACTIVE_STATES.has(incident.state));
  const counts = incidentCounts(active);
  const severities = SEVERITY_DISPLAY_ORDER.filter((severity) => counts.bySeverity[severity] > 0);
  return (
    <div>
      <p className="h3 mb-1">{active.length} active</p>
      <p className="small text-body-secondary mb-2">
        of the {response.incidents.length} listed
        {response.next_offset === null
          ? ''
          : '; more incidents exist beyond this page, so this is not a total'}
        .
      </p>
      {severities.length > 0 ? (
        <p className="small mb-0">{severities.map((s) => `${counts.bySeverity[s]} ${s}`).join(' · ')}</p>
      ) : null}
    </div>
  );
}

/** Overview card for incidents: reads the same API as /incidents and labels every count as "listed". */
export function OverviewIncidentsCard({ state }: { state: IncidentsState }) {
  return (
    <section aria-label="Active incidents">
      <Card
        className="operational-card operational-card--primary"
        title="Active incidents"
        icon="bi bi-exclamation-triangle"
        variant="outline"
        theme="secondary"
        tools={<OpenLink />}
      >
        <Body state={state} />
      </Card>
    </section>
  );
}
