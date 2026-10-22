import Link from 'next/link';
import { Card } from '@adminlte/react';
import { AppContent } from '@/components/app-content';

import { ALERTS_VIEW, RelatedViews } from '@/components/related-views';
import { SecurityBody } from '@/components/security-body';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import type { TrafficPreset } from '@/lib/api-contracts';
import { parseSecurityEventsResponse } from '@/lib/api-contracts-security';
import { aroundInstantFlowsHref } from '@/lib/traffic-view';
import { canReadTrafficDetail, viewerFromSession } from '@/lib/viewer';

const PRESETS: ReadonlyArray<{ id: TrafficPreset; label: string }> = [
  { id: '1h', label: 'Last hour' },
  { id: '6h', label: 'Last 6 hours' },
  { id: '24h', label: 'Last 24 hours' },
  { id: '7d', label: 'Last 7 days' },
];

const PRESET_IDS = PRESETS.map((preset) => preset.id);
const EVENT_LIMIT = 100;
/** Flows are shown this many minutes either side of an event, not for the page's window. */
const EVENT_FLOW_MINUTES = 30;

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

export default async function SecurityPage({
  searchParams,
}: {
  searchParams: Promise<{ preset?: string | string[] }>;
}) {
  const preset = requestedPreset((await searchParams).preset);
  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const viewer = viewerFromSession(sessionState.kind === 'ok' ? sessionState.data : null);
  const detail = canReadTrafficDetail(viewer);
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
        <SecurityBody
          state={state}
          limit={EVENT_LIMIT}
          flowsHref={
            detail
              ? (ip, at) => aroundInstantFlowsHref(at, EVENT_FLOW_MINUTES, { source_ip: ip }, { detail })
              : undefined
          }
        />
      </Card>

      <RelatedViews
        views={[
          ALERTS_VIEW,
          { label: 'Incidents', href: '/incidents', hint: 'Correlated incidents and their timelines' },
          { label: 'Flow Explorer', href: `/traffic/flows?preset=${preset}`, hint: 'Flow evidence for the same window' },
          { label: 'Traffic anomalies', href: `/traffic/anomalies?preset=${preset}`, hint: 'Hours that differ from their baseline' },
        ]}
      />
    </AppContent>
  );
}
