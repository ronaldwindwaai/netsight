import Link from 'next/link';
import type { ReactNode } from 'react';

import { CohortNotice } from '@/components/cohort-notice';
import { DataFailure, FreshnessNotice } from '@/components/data-state';
import { StateSurface } from '@/components/state-surface';
import { TrafficBars } from '@/components/traffic-bars';
import { TrafficPanel } from '@/components/traffic-panel';
import type {
  TrafficApplicationsResponse,
  TrafficDestinationsResponse,
} from '@/lib/api-contracts-traffic-explorer';
import type { FetchState } from '@/lib/api-response';
import { resolveTrafficWindow, trafficHref, withheldRowText } from '@/lib/traffic-view';
import type { TrafficWindow } from '@/lib/traffic-view';

// The overview shows the last 24 hours; the links open the same window on the detail pages.
const OVERVIEW_WINDOW = resolveTrafficWindow({ preset: '24h' }, new Date(0), 31);

function Restricted({ permission, what }: { permission: string; what: string }) {
  return (
    <StateSurface
      icon="bi bi-lock"
      title="Restricted"
      detail={`${what} needs the ${permission} permission, which your role does not hold.`}
    />
  );
}

function Failure<T>({ state }: { state: Exclude<FetchState<T>, { kind: 'ok' }> }) {
  return <DataFailure state={state} />;
}

function Card({ title, icon, children }: { title: string; icon: string; children: ReactNode }) {
  return (
    <TrafficPanel title={title} icon={icon}>
      {children}
    </TrafficPanel>
  );
}

/**
 * Top destinations on the overview, from `/traffic/destinations` (the one list route that applies the
 * small-cohort rule). Destinations a small group reached are listed by address with their figures
 * withheld, and destinations inside the organisation are not listed to the aggregate tier. `null` means
 * the viewer does not hold traffic:read, which is shown as Restricted rather than as an empty ranking.
 */
export function OverviewTopDestinations({
  state,
  window = OVERVIEW_WINDOW,
}: {
  state: FetchState<TrafficDestinationsResponse> | null;
  window?: TrafficWindow;
}) {
  const title = 'Top destinations';
  const icon = 'bi-globe2';
  if (state === null || state.kind === 'forbidden') {
    return (
      <Card title={title} icon={icon}>
        <Restricted permission="traffic:read" what="Ranking destinations" />
      </Card>
    );
  }
  if (state.kind !== 'ok') {
    return (
      <Card title={title} icon={icon}>
        <Failure state={state} />
      </Card>
    );
  }
  const { data } = state;
  if (data.state === 'not-connected') {
    return (
      <Card title={title} icon={icon}>
        <StateSurface
          icon="bi bi-activity"
          title="Flow telemetry not connected"
          detail="Destination rankings will appear only after an approved flow source is available."
        />
      </Card>
    );
  }
  if (data.state === 'unknown') {
    return (
      <Card title={title} icon={icon}>
        <StateSurface
          icon="bi bi-question-circle"
          title="Traffic state unknown"
          detail="A flow source is configured but its current state could not be confirmed. Nothing is estimated in its place."
        />
      </Card>
    );
  }
  return (
    <Card title={title} icon={icon}>
      <FreshnessNotice freshness={data.freshness} />
      <CohortNotice cohort={data.cohort} noun="destinations" />
      {data.items.length === 0 ? (
        <StateSurface
          icon="bi bi-inboxes"
          title="No traffic in this window"
          detail={`The flow source reported a valid empty result for ${window.label.toLowerCase()}.`}
        />
      ) : (
        <>
          <TrafficBars
            items={data.items.map((item) => ({
              rank: item.rank,
              label: item.address,
              bytes: item.bytes,
              share: item.share,
            }))}
            withheldText={withheldRowText(data.cohort)}
          />
          <p className="small text-body-secondary mt-2 mb-1">
            Destination addresses ranked by bytes in {window.label.toLowerCase()}.
          </p>
        </>
      )}
      <Link className="small" href={trafficHref('destinations', window)}>
        All destinations
      </Link>
    </Card>
  );
}

/**
 * Application mix on the overview, from the source-reported application field only. `null` means the
 * viewer does not hold traffic:read.
 */
export function OverviewApplicationMix({
  state,
  window = OVERVIEW_WINDOW,
}: {
  state: FetchState<TrafficApplicationsResponse> | null;
  window?: TrafficWindow;
}) {
  const title = 'Application mix';
  const icon = 'bi-pie-chart';
  if (state === null || state.kind === 'forbidden') {
    return (
      <Card title={title} icon={icon}>
        <Restricted permission="traffic:read" what="The application mix" />
      </Card>
    );
  }
  if (state.kind !== 'ok') {
    return (
      <Card title={title} icon={icon}>
        <Failure state={state} />
      </Card>
    );
  }
  const { data } = state;
  let body: ReactNode;
  if (data.state === 'not-connected') {
    body = (
      <StateSurface
        icon="bi bi-pie-chart"
        title="Application telemetry not connected"
        detail="Netsight will not estimate application usage without source evidence."
      />
    );
  } else if (data.state === 'unknown') {
    body =
      data.unsupported.length > 0 ? (
        <StateSurface
          icon="bi bi-question-circle"
          title="The flow source does not report applications"
          detail="No application breakdown can be shown. Nothing is guessed from ports or destinations."
        />
      ) : (
        <StateSurface
          icon="bi bi-question-circle"
          title="Traffic state unknown"
          detail="A flow source is configured but its current state could not be confirmed. Nothing is estimated in its place."
        />
      );
  } else if (data.items.length === 0) {
    body = (
      <StateSurface
        icon="bi bi-inboxes"
        title="No applications in this window"
        detail={`The flow source reported a valid empty result for ${window.label.toLowerCase()}.`}
      />
    );
  } else {
    body = (
      <>
        <FreshnessNotice freshness={data.freshness} />
        <TrafficBars
          items={data.items.map((item) => ({
            rank: item.rank,
            label: item.application,
            bytes: item.bytes,
            share: item.share,
          }))}
          withheldText={withheldRowText(data.cohort)}
        />
        <p className="small text-body-secondary mt-2 mb-1">
          Each bar is the share of all bytes in {window.label.toLowerCase()}, as the flow source reports
          them.
        </p>
      </>
    );
  }
  return (
    <Card title={title} icon={icon}>
      {body}
      <Link className="small" href={trafficHref('applications', window)}>
        All applications
      </Link>
    </Card>
  );
}
