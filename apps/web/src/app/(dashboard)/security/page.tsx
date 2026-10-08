import type { ReactNode } from 'react';
import Link from 'next/link';
import { AppContent, Card } from '@adminlte/react';

import { DataFailure, FreshnessNotice } from '@/components/data-state';
import { SecurityEventsTable } from '@/components/security-events-table';
import { apiGet } from '@/lib/api';
import type { FetchState } from '@/lib/api';
import { ALERT_SEVERITIES } from '@/lib/api-contracts';
import type { AlertSeverity, TrafficPreset } from '@/lib/api-contracts';
import { parseSecurityEventsResponse } from '@/lib/api-contracts-security';
import type { SecurityEventsResponse } from '@/lib/api-contracts-security';
import { severityCounts } from '@/lib/security-summary';

const PRESETS: ReadonlyArray<{ id: TrafficPreset; label: string }> = [
  { id: '1h', label: 'Last hour' },
  { id: '6h', label: 'Last 6 hours' },
  { id: '24h', label: 'Last 24 hours' },
  { id: '7d', label: 'Last 7 days' },
];

const PRESET_IDS = PRESETS.map((preset) => preset.id);
const EVENT_LIMIT = 100;

const SEVERITY_ORDER: readonly AlertSeverity[] = [...ALERT_SEVERITIES].reverse();

function requestedPreset(raw: string | string[] | undefined): TrafficPreset {
  const value = Array.isArray(raw) ? raw[0] : raw;
  return PRESET_IDS.includes(value as TrafficPreset) ? (value as TrafficPreset) : '24h';
}

function TimeRangePicker({ selected }: { selected: TrafficPreset }) {
  return (
    <div className="btn-group btn-group-sm" role="group" aria-label="Security time range">
      {PRESETS.map((preset) => {
        const active = preset.id === selected;
        return (
          <Link
            key={preset.id}
            href={`/security?preset=${preset.id}`}
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
    icon="bi bi-shield-slash"
    title="Security source not connected"
    detail="Connect an approved security source (Wazuh indexer, including Suricata alerts) before Netsight can show security events."
  />
);

const UNKNOWN = (
  <StateSurface
    icon="bi bi-question-circle"
    title="Security state unknown"
    detail="A security source is configured but its current state could not be confirmed. Nothing is estimated in its place."
  />
);

const EMPTY_WINDOW = (
  <StateSurface
    icon="bi bi-shield-check"
    title="No security events in this window"
    detail="The security source reported a valid empty result for the selected time range. This is not proof that nothing happened outside the sources Netsight reads."
  />
);

function SeverityStrip({ response }: { response: SecurityEventsResponse }) {
  const counts = severityCounts(response.events);
  return (
    <>
      <div className="row g-2 mb-2">
        {SEVERITY_ORDER.map((severity) => (
          <div className="col-6 col-md" key={severity}>
            <div className="border rounded p-2 text-center">
              <div className="fs-4 fw-semibold">{counts[severity]}</div>
              <div className="small text-body-secondary text-capitalize">{severity}</div>
            </div>
          </div>
        ))}
      </div>
      <p className="small text-body-secondary mb-2">
        Counts cover the {response.events.length} most recent events listed below, not the full
        window.
      </p>
    </>
  );
}

function EventsBody({ state }: { state: FetchState<SecurityEventsResponse> }): ReactNode {
  if (state.kind !== 'ok') {
    return (
      <div className="p-3">
        <DataFailure state={state} />
      </div>
    );
  }
  if (state.data.state === 'not-connected') return NOT_CONNECTED;
  if (state.data.state === 'unknown') return UNKNOWN;
  if (state.data.events.length === 0) return EMPTY_WINDOW;
  return (
    <>
      <div className="px-3 pt-3">
        <FreshnessNotice freshness={state.data.freshness} />
        <SeverityStrip response={state.data} />
      </div>
      <SecurityEventsTable events={state.data.events} />
    </>
  );
}

export default async function SecurityPage({
  searchParams,
}: {
  searchParams: Promise<{ preset?: string | string[] }>;
}) {
  const preset = requestedPreset((await searchParams).preset);
  const state = await apiGet(
    `/api/v1/security/events?preset=${preset}&limit=${EVENT_LIMIT}`,
    parseSecurityEventsResponse,
  );

  return (
    <AppContent
      title="Security centre"
      breadcrumbs={[{ label: 'Overview', href: '/overview' }, { label: 'Security' }]}
    >
      <div className="page-intro d-flex flex-wrap align-items-end justify-content-between gap-2">
        <p className="text-body-secondary mb-0">
          Read-only security events from the connected sources. Empty, unknown and not-connected
          are shown distinctly — alert text is untrusted telemetry and is displayed as data only.
        </p>
        <TimeRangePicker selected={preset} />
      </div>

      <Card
        className="operational-card"
        title="Security events"
        icon="bi bi-shield-exclamation"
        variant="outline"
        theme="primary"
        bodyClass="p-0"
      >
        <EventsBody state={state} />
      </Card>
    </AppContent>
  );
}
