import { DataFailure, FreshnessNotice } from '@/components/data-state';
import { SecurityEventsTable } from '@/components/security-events-table';
import type { FlowsHref } from '@/components/security-events-table';
import { StateSurface } from '@/components/state-surface';
import { ALERT_SEVERITIES } from '@/lib/api-contracts';
import type { AlertSeverity } from '@/lib/api-contracts';
import type { SecurityEventsResponse } from '@/lib/api-contracts-security';
import type { FetchState } from '@/lib/api';
import { formatUtcTimestamp } from '@/lib/format-time';
import { severityCounts } from '@/lib/security-summary';

const SEVERITY_ORDER: readonly AlertSeverity[] = [...ALERT_SEVERITIES].reverse();

function SeverityStrip({ response }: { response: SecurityEventsResponse }) {
  const counts = severityCounts(response.events);
  return (
    <section aria-label="Severity of the listed events">
      <dl className="row g-2 mb-2">
        {SEVERITY_ORDER.map((severity) => (
          <div className="col-6 col-md" key={severity}>
            <div className="border rounded p-2 text-center d-flex flex-column-reverse">
              <dd className="fs-4 fw-semibold mb-0">{counts[severity]}</dd>
              <dt className="small text-body-secondary text-capitalize fw-normal">{severity}</dt>
            </div>
          </div>
        ))}
      </dl>
    </section>
  );
}

/** States the exact UTC window and whether the list is cut off, so counts are never read as totals. */
function WindowSummary({ response, limit }: { response: SecurityEventsResponse; limit: number }) {
  const { from, to } = response.time_range;
  const capped = response.events.length >= limit;
  return (
    <div className="small text-body-secondary mb-2">
      <p className="mb-1">
        Window {formatUtcTimestamp(from)} to {formatUtcTimestamp(to)} (UTC).{' '}
        {response.events.length.toLocaleString('en-GB')} events listed
        {capped ? `, the most the page reads (${limit}).` : '.'}
      </p>
      <p className="mb-0">
        {capped
          ? 'The window may hold more events than are listed, so the severity counts are not totals for the window.'
          : 'Severity counts cover exactly the events listed below; the source reported no more in this window.'}
      </p>
    </div>
  );
}

/**
 * Every outcome of the security events read. Empty, not-connected and unknown read differently, a
 * failed read is never shown as an empty list, and signature and address text is untrusted
 * telemetry rendered as data.
 */
export function SecurityBody({
  state,
  limit,
  flowsHref,
}: {
  state: FetchState<SecurityEventsResponse>;
  limit: number;
  flowsHref?: FlowsHref;
}) {
  if (state.kind !== 'ok') {
    return (
      <div className="p-3">
        <DataFailure state={state} />
      </div>
    );
  }
  const { data } = state;
  if (data.state === 'not-connected') {
    return (
      <StateSurface
        icon="bi bi-shield-slash"
        title="Security source not connected"
        detail="Connect an approved security source (Wazuh indexer, including Suricata alerts) before Netsight can show security events."
      />
    );
  }
  if (data.state === 'unknown') {
    return (
      <StateSurface
        icon="bi bi-question-circle"
        title="Security state unknown"
        detail="A security source is configured but its current state could not be confirmed. Nothing is estimated in its place."
      />
    );
  }
  if (data.events.length === 0) {
    return (
      <>
        <div className="px-3 pt-3">
          <FreshnessNotice freshness={data.freshness} />
        </div>
        <StateSurface
          icon="bi bi-shield-check"
          title="No security events in this window"
          detail="The security source reported a valid empty result for the selected time range. This is not proof that nothing happened outside the sources Netsight reads."
        />
      </>
    );
  }
  return (
    <>
      <div className="px-3 pt-3">
        <FreshnessNotice freshness={data.freshness} />
        <WindowSummary response={data} limit={limit} />
        <SeverityStrip response={data} />
      </div>
      <SecurityEventsTable events={data.events} flowsHref={flowsHref} />
    </>
  );
}
