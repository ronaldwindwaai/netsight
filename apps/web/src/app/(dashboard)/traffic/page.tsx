import type { ReactNode } from 'react';
import Link from 'next/link';
import { AppContent, Card } from '@adminlte/react';

import { DataFailure, FreshnessNotice } from '@/components/data-state';
import { TrafficBars } from '@/components/traffic-bars';
import { TrafficFlowsTable } from '@/components/traffic-flows-table';
import { apiGet } from '@/lib/api';
import type { FetchState } from '@/lib/api';
import {
  parseTrafficFlowsResponse,
  parseTrafficTopResponse,
} from '@/lib/api-contracts';
import type {
  TrafficFlowsResponse,
  TrafficItem,
  TrafficPreset,
  TrafficTopResponse,
} from '@/lib/api-contracts';
import { applicationMix } from '@/lib/traffic-summary';

const PRESETS: ReadonlyArray<{ id: TrafficPreset; label: string }> = [
  { id: '1h', label: 'Last hour' },
  { id: '6h', label: 'Last 6 hours' },
  { id: '24h', label: 'Last 24 hours' },
  { id: '7d', label: 'Last 7 days' },
];

const PRESET_IDS = PRESETS.map((preset) => preset.id);

function requestedPreset(raw: string | string[] | undefined): TrafficPreset {
  const value = Array.isArray(raw) ? raw[0] : raw;
  return PRESET_IDS.includes(value as TrafficPreset) ? (value as TrafficPreset) : '24h';
}

function TimeRangePicker({ selected }: { selected: TrafficPreset }) {
  return (
    <div className="btn-group btn-group-sm" role="group" aria-label="Traffic time range">
      {PRESETS.map((preset) => {
        const active = preset.id === selected;
        return (
          <Link
            key={preset.id}
            href={`/traffic?preset=${preset.id}`}
            className={`btn btn-outline-secondary${active ? ' active' : ''}`}
            aria-current={active ? 'true' : undefined}
          >
            {preset.label}
          </Link>
        );
      })}
    </div>
  );
}

function StateSurface({ icon, title, detail }: { icon: string; title: string; detail: string }) {
  return (
    <div className="traffic-state text-center">
      <i className={`${icon} fs-2 text-body-secondary`} aria-hidden="true" />
      <p className="fw-semibold mb-1 mt-3">{title}</p>
      <p className="small text-body-secondary mb-0">{detail}</p>
    </div>
  );
}

const NOT_CONNECTED = (
  <StateSurface
    icon="bi bi-bezier2"
    title="Flow source not connected"
    detail="Connect an approved flow source (Akvorado/ClickHouse) before Netsight can rank bandwidth use."
  />
);

const UNKNOWN = (
  <StateSurface
    icon="bi bi-question-circle"
    title="Traffic state unknown"
    detail="A flow source is configured but its current state could not be confirmed. Nothing is estimated in its place."
  />
);

const EMPTY_WINDOW = (
  <StateSurface
    icon="bi bi-inboxes"
    title="No traffic in this window"
    detail="The flow source reported a valid empty result for the selected time range."
  />
);

type TrafficResponseState = TrafficTopResponse['state'];

/**
 * The three traffic reads share one source, so when every read agrees the page
 * can show one source-level surface instead of repeating the same notice. Any
 * disagreement or request failure returns null so each panel reports itself.
 */
function sharedSourceState(
  ...states: Array<FetchState<TrafficTopResponse> | FetchState<TrafficFlowsResponse>>
): TrafficResponseState | null {
  const resolved: TrafficResponseState[] = [];
  for (const state of states) {
    if (state.kind !== 'ok') return null;
    resolved.push(state.data.state);
  }
  return resolved.length > 0 && resolved.every((value) => value === resolved[0])
    ? resolved[0]
    : null;
}

function TopPanel({
  title,
  icon,
  state,
}: {
  title: string;
  icon: string;
  state: FetchState<TrafficTopResponse>;
}) {
  let body: ReactNode;
  if (state.kind !== 'ok') {
    body = <DataFailure state={state} />;
  } else if (state.data.state === 'not-connected') {
    body = NOT_CONNECTED;
  } else if (state.data.state === 'unknown') {
    body = UNKNOWN;
  } else if (state.data.items.length === 0) {
    body = EMPTY_WINDOW;
  } else {
    body = (
      <>
        <FreshnessNotice freshness={state.data.freshness} />
        <TrafficBars items={state.data.items} />
      </>
    );
  }

  return (
    <Card
      className="operational-card"
      title={title}
      icon={icon}
      variant="outline"
      theme="primary"
      bodyClass="pt-2"
    >
      {body}
    </Card>
  );
}

function ApplicationsCard({ state }: { state: FetchState<TrafficFlowsResponse> }) {
  let body: ReactNode;

  if (state.kind !== 'ok') {
    body = <DataFailure state={state} />;
  } else if (state.data.state === 'not-connected') {
    body = NOT_CONNECTED;
  } else if (state.data.state === 'unknown') {
    body = UNKNOWN;
  } else if (state.data.flows.length === 0) {
    body = EMPTY_WINDOW;
  } else {
    const items: TrafficItem[] = applicationMix(state.data.flows).map((entry, index) => ({
      rank: index + 1,
      subject_kind: 'application',
      subject_id: null,
      label: entry.application,
      bytes: entry.bytes,
      packets: null,
      share: entry.share,
    }));

    body =
      items.length === 0 ? (
        <StateSurface
          icon="bi bi-question-circle"
          title="No application metadata"
          detail="The listed high-volume flows carry no application field, so no application mix can be shown."
        />
      ) : (
        <>
          <p className="small text-body-secondary mb-2">
            Share of bytes across the {state.data.flows.length} listed high-volume flows, not the
            full window.
          </p>
          <TrafficBars items={items} />
        </>
      );
  }

  return (
    <Card
      className="operational-card"
      title="Top applications"
      icon="bi bi-pie-chart"
      variant="outline"
      theme="secondary"
      bodyClass="pt-2"
    >
      {body}
    </Card>
  );
}

function FlowsCard({ state }: { state: FetchState<TrafficFlowsResponse> }) {
  let body: ReactNode;

  if (state.kind !== 'ok') {
    body = (
      <div className="p-3">
        <DataFailure state={state} />
      </div>
    );
  } else if (state.data.state === 'not-connected') {
    body = NOT_CONNECTED;
  } else if (state.data.state === 'unknown') {
    body = UNKNOWN;
  } else if (state.data.flows.length === 0) {
    body = EMPTY_WINDOW;
  } else {
    body = (
      <>
        <div className="px-3 pt-3">
          <FreshnessNotice freshness={state.data.freshness} />
        </div>
        <TrafficFlowsTable flows={state.data.flows} />
      </>
    );
  }

  return (
    <Card
      className="operational-card"
      title="Recent high-volume flows"
      icon="bi bi-list-columns"
      variant="outline"
      theme="primary"
      bodyClass="p-0"
    >
      {body}
    </Card>
  );
}

export default async function TrafficPage({
  searchParams,
}: {
  searchParams: Promise<{ preset?: string | string[] }>;
}) {
  const preset = requestedPreset((await searchParams).preset);
  const query = `preset=${preset}`;
  const [talkersState, destinationsState, flowsState] = await Promise.all([
    apiGet(`/api/v1/traffic/top-talkers?${query}&limit=10`, parseTrafficTopResponse),
    apiGet(`/api/v1/traffic/top-destinations?${query}&limit=10`, parseTrafficTopResponse),
    apiGet(`/api/v1/traffic/flows?${query}&limit=50`, parseTrafficFlowsResponse),
  ]);
  const shared = sharedSourceState(talkersState, destinationsState, flowsState);

  return (
    <AppContent
      title="Traffic intelligence"
      breadcrumbs={[{ label: 'Overview', href: '/overview' }, { label: 'Traffic' }]}
    >
      <div className="page-intro d-flex flex-wrap align-items-end justify-content-between gap-2">
        <p className="text-body-secondary mb-0">
          Read-only flow evidence from the connected source. Empty, unknown and not-connected are
          shown distinctly — Netsight never estimates traffic.
        </p>
        <TimeRangePicker selected={preset} />
      </div>

      {shared === 'not-connected' || shared === 'unknown' ? (
        <Card
          className="operational-card operational-card--primary"
          title="Bandwidth ranking"
          icon="bi bi-bar-chart-line"
          variant="outline"
          theme="primary"
          bodyClass="pt-2"
        >
          {shared === 'not-connected' ? NOT_CONNECTED : UNKNOWN}
        </Card>
      ) : (
        <>
          <div className="row g-3">
            <div className="col-xl-6">
              <TopPanel title="Top users / devices" icon="bi bi-people" state={talkersState} />
            </div>
            <div className="col-xl-6">
              <TopPanel title="Top destinations" icon="bi bi-globe2" state={destinationsState} />
            </div>
          </div>

          <div className="row g-3">
            <div className="col-xl-5">
              <ApplicationsCard state={flowsState} />
            </div>
            <div className="col-xl-7">
              <FlowsCard state={flowsState} />
            </div>
          </div>
        </>
      )}
    </AppContent>
  );
}