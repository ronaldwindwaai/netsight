import type { ReactNode } from 'react';
import Link from 'next/link';
import { AppContent, Card } from '@adminlte/react';

import { DataFailure } from '@/components/data-state';
import {
  IncidentEvidence,
  IncidentSummary,
  ResolutionBlock,
} from '@/components/incident-detail-view';
import { IncidentRelatedLinks } from '@/components/incident-related-links';
import { IncidentActionsPanel } from '@/components/incident-actions-panel';
import { IncidentTimeline } from '@/components/incident-timeline';
import { StateSurface, StoreStateSurface } from '@/components/state-surface';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import type { FetchState } from '@/lib/api';
import {
  parseIncidentDetailResponse,
  parseIncidentTimelineResponse,
} from '@/lib/api-contracts-incident-api';
import type {
  IncidentDetailResponse,
  IncidentTimelineResponse,
} from '@/lib/api-contracts-incident-api';
import { formatUtcTimestamp } from '@/lib/format-time';
import {
  incidentDetailHref,
  incidentDetailPath,
  incidentReadMode,
  parseTimelineCursor,
  timelinePath,
} from '@/lib/incident-view';
import type { Viewer } from '@/lib/incident-actions';
import { viewerFromSession } from '@/lib/viewer';

function TimelineBody({
  state,
  incidentId,
}: {
  state: FetchState<IncidentTimelineResponse>;
  incidentId: string;
}): ReactNode {
  if (state.kind !== 'ok') {
    return (
      <div className="p-3" aria-live="polite">
        <DataFailure state={state} />
      </div>
    );
  }
  const timeline = state.data;
  if (timeline.state !== 'ok') {
    return <StoreStateSurface state={timeline.state} noun="timeline events" store="Incident store" />;
  }
  if (timeline.events.length === 0) {
    return (
      <StateSurface
        icon="bi bi-clock-history"
        title={timeline.after_seq > 0 ? 'No further timeline events' : 'No timeline events'}
        detail="The incident store returned a valid empty timeline page."
      />
    );
  }
  const next =
    timeline.next_after_seq === null ? null : incidentDetailHref(incidentId, timeline.next_after_seq);
  const start = timeline.after_seq > 0 ? incidentDetailHref(incidentId, 0) : null;
  return (
    <>
      <IncidentTimeline events={timeline.events} />
      {start || next ? (
        <nav className="d-flex justify-content-between p-3" aria-label="Timeline pages">
          {start ? (
            <Link className="btn btn-outline-secondary btn-sm" href={start}>
              <i className="bi bi-skip-start me-1" aria-hidden="true" />
              Back to start
            </Link>
          ) : (
            <span />
          )}
          {next ? (
            <Link className="btn btn-outline-secondary btn-sm" href={next}>
              Later events
              <i className="bi bi-chevron-right ms-1" aria-hidden="true" />
            </Link>
          ) : null}
        </nav>
      ) : null}
    </>
  );
}

function DetailBody({
  state,
  timeline,
  incidentId,
  viewer,
}: {
  state: FetchState<IncidentDetailResponse>;
  timeline: FetchState<IncidentTimelineResponse> | null;
  incidentId: string;
  viewer: Viewer | null;
}): ReactNode {
  if (state.kind !== 'ok') return <DataFailure state={state} />;
  const { incident } = state.data;
  if (state.data.state !== 'ok' || incident === null) {
    return (
      <Card className="operational-card" bodyClass="p-0">
        <StoreStateSurface
          state={state.data.state === 'ok' ? 'unknown' : state.data.state}
          noun="this incident"
          store="Incident store"
        />
      </Card>
    );
  }
  return (
    <>
      <Card className="operational-card" title="Summary" variant="outline" theme="primary">
        <IncidentSummary incident={incident} />
        <div className="mt-3">
          <IncidentRelatedLinks permissions={viewer === null ? [] : viewer.permissions} />
        </div>
        <div className="mt-3">
          <IncidentActionsPanel
            incident={{ id: incident.id, state: incident.state, assignee_id: incident.assignee_id }}
            viewer={viewer}
            currentPath={incidentDetailHref(incidentId, 0) ?? '/incidents'}
          />
        </div>
      </Card>
      {incident.resolution ? (
        <Card className="operational-card" title="Resolution" variant="outline" theme="success">
          <ResolutionBlock resolution={incident.resolution} />
        </Card>
      ) : null}
      <Card className="operational-card" title="Evidence" variant="outline" theme="secondary">
        <IncidentEvidence evidenceIds={incident.evidence_ids} />
      </Card>
      <Card
        className="operational-card"
        title="Timeline"
        icon="bi bi-clock-history"
        variant="outline"
        theme="secondary"
        bodyClass="p-0"
      >
        {timeline === null ? null : <TimelineBody state={timeline} incidentId={incidentId} />}
      </Card>
    </>
  );
}

export default async function IncidentDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ incidentId: string }>;
  searchParams: Promise<{ after_seq?: string | string[] }>;
}) {
  const { incidentId } = await params;
  const afterSeq = parseTimelineCursor((await searchParams).after_seq);
  const detailPath = incidentDetailPath(incidentId);
  const eventsPath = timelinePath(incidentId, afterSeq);

  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const viewer = sessionState.kind === 'ok' ? viewerFromSession(sessionState.data) : null;
  const mode = incidentReadMode(viewer === null ? null : viewer.permissions);

  const [detail, timeline] =
    detailPath === null || eventsPath === null || mode !== 'full'
      ? [null, null]
      : await Promise.all([
          apiGet(detailPath, parseIncidentDetailResponse),
          apiGet(eventsPath, parseIncidentTimelineResponse),
        ]);

  const title = detail?.kind === 'ok' && detail.data.incident ? detail.data.incident.title : 'Incident';
  const retrievedAt = formatUtcTimestamp(new Date().toISOString());

  return (
    <AppContent
      title={title}
      breadcrumbs={[
        { label: 'Overview', href: '/overview' },
        { label: 'Incidents', href: '/incidents' },
        { label: 'Incident' },
      ]}
    >
      <div className="page-intro d-flex align-items-center justify-content-between gap-3">
        <p className="text-body-secondary mb-0">
          Incident record and append-only timeline. Actions are limited to what your role permits
          and every change is audited. All text below is operator-entered and displayed as data
          only. Retrieved {retrievedAt}; the incident API does not report a freshness value.
        </p>
        <Link className="btn btn-outline-secondary btn-sm" href="/incidents">
          <i className="bi bi-arrow-left me-1" aria-hidden="true" />
          All incidents
        </Link>
      </div>

      {mode !== 'full' ? (
        <Card className="operational-card" bodyClass="p-0">
          <StateSurface
            icon="bi bi-shield-lock"
            title={mode === 'summary' ? 'Summary view only' : 'Permission denied'}
            detail={
              mode === 'summary'
                ? 'Your role can see incident summaries in the incident list, not the full record, evidence or timeline.'
                : 'Your role does not include incident access. Access is enforced by the Netsight API.'
            }
          />
        </Card>
      ) : detail === null ? (
        <Card className="operational-card" bodyClass="p-0">
          <StateSurface
            icon="bi bi-question-circle"
            title="Invalid incident identifier"
            detail="The identifier in the address does not match the incident id format, so no request was made."
          />
        </Card>
      ) : (
        <DetailBody state={detail} timeline={timeline} incidentId={incidentId} viewer={viewer} />
      )}
    </AppContent>
  );
}
