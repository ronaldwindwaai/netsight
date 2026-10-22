/**
 * Monthly SLA for provider disputes: figures computed by the API from stored probe samples, a
 * month picker (server-bounded to the supported months, plain GET form, no script) and a
 * read-only evidence export (a link: GET only, nothing is changed). A gap in sampling is
 * "Unknown", never up and never down; a missing value is "Not reported".
 */
import { AppCard } from '@/components/app-card';

import { DataFailure } from '@/components/data-state';
import { StateSurface } from '@/components/state-surface';
import type { FetchState } from '@/lib/api-response';
import type { SlaLink, SlaResponse } from '@/lib/api-contracts-internet';
import { formatUtcTimestamp } from '@/lib/format-time';
import { NOT_REPORTED, exportHref, formatDuration, formatPercent } from '@/lib/internet-view';

export interface SlaPanelProps {
  state: FetchState<SlaResponse>;
  month: string;
  months: readonly string[];
  /** True when the requested month was outside the supported range and was replaced. */
  adjusted: boolean;
  /** The viewer holds internet:export (advisory: the API enforces it). */
  canExport: boolean;
  monthAction?: '/internet' | '/reports/wan-sla';
}

function MonthPicker({ month, months, action }: { month: string; months: readonly string[]; action: '/internet' | '/reports/wan-sla' }) {
  return (
    <form method="get" action={action} className="d-flex flex-wrap align-items-end gap-2">
      <div>
        <label htmlFor="sla-month" className="form-label small mb-1">
          SLA month (UTC)
        </label>
        <select id="sla-month" name="month" className="form-select form-select-sm" defaultValue={month}>
          {months.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      </div>
      <button type="submit" className="btn btn-sm btn-outline-primary">
        Show month
      </button>
    </form>
  );
}

function ExportControls({ month, canExport }: { month: string; canExport: boolean }) {
  if (!canExport) {
    return (
      <p className="small text-body-secondary mb-0">
        <i className="bi bi-lock me-1" aria-hidden="true" />
        Evidence export needs the internet:export permission, which your role does not hold.
      </p>
    );
  }
  return (
    <div className="d-flex flex-wrap align-items-center gap-2">
      <span className="small text-body-secondary">Evidence for {month} (read-only download):</span>
      <a className="btn btn-sm btn-outline-secondary" href={exportHref(month, 'csv')}>
        <i className="bi bi-filetype-csv me-1" aria-hidden="true" />
        Download CSV
      </a>
      <a className="btn btn-sm btn-outline-secondary" href={exportHref(month, 'json')}>
        <i className="bi bi-filetype-json me-1" aria-hidden="true" />
        Download JSON
      </a>
    </div>
  );
}

function violationText(link: SlaLink): string {
  if (link.uptime_target_pct === null) return 'No uptime target configured';
  if (link.uptime_pct === null) return `Target ${formatPercent(link.uptime_target_pct)}; no known time`;
  if (link.violations.length === 0) return `Meets ${formatPercent(link.uptime_target_pct)} target`;
  return link.violations
    .map(
      (violation) =>
        `Below target ${formatPercent(violation.target_pct)} (actual ${formatPercent(violation.actual_pct)})`,
    )
    .join('; ');
}

function SlaRow({ link }: { link: SlaLink }) {
  if (link.state !== 'ok') {
    return (
      <tr>
        <th scope="row">{link.name}</th>
        <td colSpan={7}>
          <i className="bi bi-question-circle me-1" aria-hidden="true" />
          {link.state === 'unknown'
            ? 'Unknown: the sample store could not be read for this link.'
            : 'Not connected.'}
        </td>
      </tr>
    );
  }
  const breached = link.violations.length > 0;
  return (
    <tr>
      <th scope="row">{link.name}</th>
      <td className="text-end">{formatPercent(link.uptime_pct)}</td>
      <td className="text-end">{formatDuration(link.down_seconds)}</td>
      <td className="text-end">{formatDuration(link.degraded_seconds)}</td>
      <td className="text-end">{formatDuration(link.unknown_seconds)}</td>
      <td className="text-end">
        {link.outage_count === null
          ? NOT_REPORTED
          : `${link.outage_count}${
              link.outage_count > 0
                ? ` (longest ${formatDuration(link.longest_outage_seconds)})`
                : ''
            }`}
      </td>
      <td className="text-end">{formatPercent(link.coverage_pct)}</td>
      <td>
        <i
          className={`bi ${breached ? 'bi-x-octagon-fill text-danger' : 'bi-dash-circle text-body-secondary'} me-1`}
          aria-hidden="true"
        />
        {violationText(link)}
      </td>
    </tr>
  );
}

function TruncationNotice({ links }: { links: readonly SlaLink[] }) {
  const cut = links.filter((link) => link.windows_truncated === true);
  if (cut.length === 0) return null;
  return (
    <div className="px-3" role="alert">
      {cut.map((link) => (
        <p key={link.link_id} className="small text-warning-emphasis mb-1">
          <i className="bi bi-exclamation-triangle me-1" aria-hidden="true" />
          {link.name}: the evidence export lists only the first windows of this month, so it is
          incomplete; the figures above are complete.
        </p>
      ))}
    </div>
  );
}

function SlaTable({ data }: { data: SlaResponse }) {
  const justStarted = data.period_start !== null && data.period_start === data.period_end;
  return (
    <>
      <p className="small text-body-secondary px-3 pt-3 mb-2">
        Period {data.period_start === null ? '' : formatUtcTimestamp(data.period_start)} to{' '}
        {data.period_end === null ? '' : formatUtcTimestamp(data.period_end)}. Retrieved{' '}
        {formatUtcTimestamp(data.generated_at)}.
      </p>
      {justStarted ? (
        <p className="small text-body-secondary px-3 mb-2" role="status">
          The month has only just started: no time has elapsed, so there is nothing to report yet
          (this is not a perfect month).
        </p>
      ) : null}
      <div className="table-responsive">
        <table className="table table-sm align-middle mb-0">
          <caption className="visually-hidden">Monthly SLA figures per WAN link</caption>
          <thead>
            <tr>
              <th scope="col">Link</th>
              <th scope="col" className="text-end">Uptime</th>
              <th scope="col" className="text-end">Down</th>
              <th scope="col" className="text-end">Degraded</th>
              <th scope="col" className="text-end">Unknown (no samples)</th>
              <th scope="col" className="text-end">Outages</th>
              <th scope="col" className="text-end">Time sampled</th>
              <th scope="col">Violations</th>
            </tr>
          </thead>
          <tbody>
            {data.links.map((link) => (
              <SlaRow key={link.link_id} link={link} />
            ))}
          </tbody>
        </table>
      </div>
      <TruncationNotice links={data.links} />
      <p className="small text-body-secondary px-3 py-2 mb-0">
        Uptime counts degraded time as reachable and is taken over sampled time only. Time without a
        probe round is unknown, not up and not down.
      </p>
    </>
  );
}

function SlaBody({ state }: { state: FetchState<SlaResponse> }) {
  if (state.kind === 'forbidden') {
    return (
      <StateSurface
        icon="bi bi-shield-lock"
        title="SLA figures are not available to your role"
        detail="Reading the Internet surface needs the internet:read permission. Access is enforced by the Netsight API."
      />
    );
  }
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
        icon="bi bi-plug"
        title="Probe sample store not connected"
        detail="No WAN link is declared or no sample store is configured, so no SLA can be computed. This is not the same as a perfect month."
      />
    );
  }
  if (data.state === 'unknown') {
    return (
      <StateSurface
        icon="bi bi-question-circle"
        title="SLA state unknown"
        detail="The WAN declaration or the sample store could not be read. Nothing is estimated in its place."
      />
    );
  }
  if (data.links.length === 0) {
    return (
      <StateSurface
        icon="bi bi-inboxes"
        title="No WAN links in this month"
        detail="The API returned no links for the selected month."
      />
    );
  }
  return <SlaTable data={data} />;
}

export function InternetSlaPanel({ state, month, months, adjusted, canExport, monthAction = "/internet" }: SlaPanelProps) {
  const exportable = state.kind === 'ok' && state.data.state === 'ok' && state.data.links.length > 0;
  return (
    <AppCard
      className="operational-card"
      title="Monthly SLA and provider evidence"
      icon="bi bi-file-earmark-bar-graph"
      variant="outline"
      theme="primary"
      bodyClass="p-0"
    >
      <div className="d-flex flex-wrap justify-content-between align-items-end gap-3 p-3 border-bottom">
        <MonthPicker month={month} months={months} action={monthAction} />
        {exportable ? <ExportControls month={month} canExport={canExport} /> : null}
      </div>
      {adjusted ? (
        <p className="small text-warning-emphasis px-3 pt-2 mb-0" role="status">
          <i className="bi bi-info-circle me-1" aria-hidden="true" />
          The requested month is outside the supported range (the current month and the 24 before
          it), so the current month is shown.
        </p>
      ) : null}
      <SlaBody state={state} />
    </AppCard>
  );
}
