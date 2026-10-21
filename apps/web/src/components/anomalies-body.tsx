import Link from 'next/link';

import { CohortNotice } from '@/components/cohort-notice';
import { FreshnessNotice } from '@/components/data-state';
import { StatusWord } from '@/components/traffic-status';
import { TrafficGate } from '@/components/traffic-surface';
import type {
  Anomaly,
  AnomalyContext,
  BaselineMethod,
  FirstSeen,
  TrafficAnomaliesResponse,
} from '@/lib/api-contracts-traffic-explorer';
import type { FetchState } from '@/lib/api-response';
import type { TrafficWindow } from '@/lib/traffic-view';
import { formatBytes } from '@/lib/format-bytes';
import { formatUtcTimestamp } from '@/lib/format-time';
import {
  anomalyHeadline,
  contextText,
  evaluationNotice,
  formatRatio,
  flowsDrillHref,
  formatSignedBytes,
  hourFlowsHref,
  historyNotice,
  patternLabel,
  seriesWithheldNotice,
  workingHoursText,
  daylightSavingNotice,
} from '@/lib/traffic-view';

const MIB = 1024 * 1024;

function mebibytes(bytes: number): string {
  return `${Number((bytes / MIB).toFixed(1))} MiB`;
}

function MethodPanel({ method, hours }: { method: BaselineMethod; hours: string }) {
  return (
    <section
      aria-label="How hours are compared"
      className="card card-outline card-secondary operational-card mb-3"
    >
      <div className="card-body small">
        <p className="mb-1">
          Each hour is compared with the same hour of the week in the {method.weeks} prior weeks,
          using the median and the median absolute deviation. At least {method.min_weeks} comparable
          weeks are needed; otherwise the hour is not judged. An hour is flagged when it is at least{' '}
          {method.threshold} robust deviations from its median <em>and</em> differs by at least{' '}
          {mebibytes(method.min_difference_bytes)}.
        </p>
        <p className="mb-1">
          No machine learning is used: the result can be recomputed by hand from the figures shown. A
          flagged hour is evidence, not a verdict.
        </p>
        <p className="mb-0 text-body-secondary">{hours}</p>
      </div>
    </section>
  );
}

function Context({ context, direction }: { context: AnomalyContext; direction: Anomaly['direction'] }) {
  return (
    <div className="small">
      <p className="mb-1">{contextText(context)}</p>
      {context.common_legitimate_patterns.length > 0 ? (
        <p className="mb-1 text-body-secondary">
          Common legitimate causes:{' '}
          {context.common_legitimate_patterns.map((pattern) => patternLabel(pattern)).join(', ')}.
        </p>
      ) : null}
      {direction === 'below' ? (
        <p className="mb-0 text-body-secondary">
          A drop may also be flow loss or an exporter outage, not only less use.
        </p>
      ) : null}
    </div>
  );
}

function AnomalyFlowsLink({ item, detail }: { item: Anomaly; detail: boolean }) {
  const forApplication = item.subject.kind === 'application';
  // An application anomaly without a name cannot be narrowed, so it offers no link rather than
  // a link that opens every flow in the hour.
  if (forApplication && item.subject.label === null) return null;
  const filters = forApplication ? { application: item.subject.label ?? '' } : {};
  const href = hourFlowsHref(item.bucket_start, item.bucket_end, filters, { detail });
  if (href === null) return null;
  return (
    <p className="small mt-2 mb-0">
      <Link href={href}>
        <i className="bi bi-search me-1" aria-hidden="true" />
        Inspect the flows in this hour
        {item.subject.kind === 'application' ? ' for this application' : ''}
      </Link>
    </p>
  );
}

function AnomalyCard({ item, detail }: { item: Anomaly; detail: boolean }) {
  const stat = (label: string, value: string) => (
    <div className="col-6 col-md-3">
      <dt className="small text-body-secondary fw-normal">{label}</dt>
      <dd className="mb-1">{value}</dd>
    </div>
  );
  return (
    <article className="border rounded p-3 mb-3">
      <div className="d-flex flex-wrap align-items-start justify-content-between gap-2">
        <h4 className="h6 mb-1">{anomalyHeadline(item)}</h4>
        <StatusWord
          label={`${item.confidence[0].toUpperCase()}${item.confidence.slice(1)} confidence`}
          icon="bi-bar-chart"
          theme="secondary"
        />
      </div>
      <p className="small text-body-secondary mb-2">
        Hour starting {formatUtcTimestamp(item.bucket_start)}
      </p>
      <dl className="row mb-2">
        {stat('Observed', formatBytes(item.observed))}
        {stat(`Baseline (median of ${item.baseline_samples} weeks)`, formatBytes(item.baseline))}
        {stat('Difference', formatSignedBytes(item.difference))}
        {stat('Ratio', formatRatio(item.ratio))}
      </dl>
      <Context context={item.context} direction={item.direction} />
      <AnomalyFlowsLink item={item} detail={detail} />
    </article>
  );
}

function FirstSeenSubject({
  row,
  window,
  detail,
}: {
  row: FirstSeen;
  window: TrafficWindow | undefined;
  detail: boolean;
}) {
  const isAsn = row.kind === 'first-seen-asn';
  const value = isAsn ? row.asn : row.address;
  const label = isAsn ? `AS${row.asn}` : (row.address ?? 'Address not reported');
  const filter = isAsn ? { asn: String(row.asn) } : { destination_ip: row.address ?? '' };
  const href =
    window === undefined || value === null ? null : flowsDrillHref(window, filter, { detail });
  return href === null ? (
    <span className="fw-semibold">{label}</span>
  ) : (
    <Link className="fw-semibold" href={href} title="Show the flows for this subject">
      {label}
    </Link>
  );
}

function FirstSeenTable({
  rows,
  window,
  detail,
}: {
  rows: readonly FirstSeen[];
  window: TrafficWindow | undefined;
  detail: boolean;
}) {
  return (
    <div className="table-responsive">
      <table className="table table-sm table-striped mb-0">
        <caption className="visually-hidden">
          Destinations and ASNs first seen in this window, as context
        </caption>
        <thead>
          <tr>
            <th scope="col">Kind</th>
            <th scope="col">Subject</th>
            <th scope="col">First seen</th>
            <th scope="col">Volume</th>
            <th scope="col">Context</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={`${index}:${row.kind}:${row.asn ?? ''}:${row.address ?? ''}`}>
              <td>{row.kind === 'first-seen-asn' ? 'First-seen ASN' : 'First-seen destination'}</td>
              <td>
                {row.kind === 'first-seen-asn' ? (
                  <FirstSeenSubject row={row} window={window} detail={detail} />
                ) : (
                  <>
                    <FirstSeenSubject row={row} window={window} detail={detail} />
                    {row.domain !== null ? (
                      <span className="d-block small text-body-secondary">{row.domain}</span>
                    ) : null}
                    {row.asn !== null ? (
                      <span className="d-block small text-body-secondary">AS{row.asn}</span>
                    ) : null}
                  </>
                )}
              </td>
              <td className="text-nowrap">{formatUtcTimestamp(row.first_seen)}</td>
              <td>{formatBytes(row.bytes)}</td>
              <td className="small">
                {contextText(row.context)}
                {row.context.common_legitimate_patterns.length > 0 ? (
                  <span className="d-block text-body-secondary">
                    Common legitimate causes:{' '}
                    {row.context.common_legitimate_patterns.map((pattern) => patternLabel(pattern)).join(', ')}.
                  </span>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * Deterministic baseline comparison. An insufficient baseline or a window without data is a result
 * of its own and is never reported as "nothing happened"; working hours are context, not a finding;
 * the arithmetic behind every flag is on the card.
 */
export function AnomaliesBody({
  state,
  window,
  detail = false,
}: {
  state: FetchState<TrafficAnomaliesResponse>;
  /** When given, first-seen subjects link to the Flow Explorer for that window. */
  window?: TrafficWindow;
  /** Whether the viewer holds traffic:read-detail (address filters are refused without it). */
  detail?: boolean;
}) {
  return (
    <TrafficGate state={state} noun="baselines" permission="traffic:read">
      {(data) => {
        const notice = evaluationNotice(data.evaluation, data.method);
        const history = historyNotice(data.first_seen_status);
        const withheld = seriesWithheldNotice(data.evaluation.series_withheld, data.cohort.minimum);
        const dst = daylightSavingNotice(data.evaluation.daylight_saving, data.working_hours.timezone);
        const judged = data.evaluation.status === 'evaluated' || data.evaluation.status === 'partial';
        return (
          <>
            <FreshnessNotice freshness={data.freshness} />
            <MethodPanel method={data.method} hours={workingHoursText(data.working_hours)} />
            {notice !== '' ? <p className="small mb-3">{notice}</p> : null}
            {withheld !== '' ? (
              <div role="status" aria-label="Series withheld" className="alert alert-info small py-2">
                <i className="bi bi-people me-1" aria-hidden="true" />
                <span>{withheld}</span>
              </div>
            ) : null}
            {dst !== '' ? (
              <p role="note" aria-label="Daylight saving" className="small text-body-secondary">
                {dst}
              </p>
            ) : null}
            {data.evaluation.application_series === 'not-reported' ? (
              <p className="small text-body-secondary">
                Application series were not evaluated because the flow source does not report
                applications; only total traffic was judged.
              </p>
            ) : null}
            <section aria-label="Anomalies" className="mb-3">
              <h3 className="h6">Hours that differ from their baseline</h3>
              {data.anomalies.length > 0 ? (
                <>
                  <p className="small text-body-secondary">
                    {data.anomalies.length} of {data.evaluation.anomalies_total} anomalies listed
                    (strongest first).
                  </p>
                  {data.anomalies.map((item, index) => (
                    <AnomalyCard
                      key={`${index}:${item.bucket_start}:${item.subject.label ?? 'total'}`}
                      item={item}
                      detail={detail}
                    />
                  ))}
                </>
              ) : judged ? (
                <p className="text-body-secondary">
                  No hour deviated from its baseline in the hours that could be judged.
                </p>
              ) : null}
            </section>
            <section aria-label="First seen" className="mb-3">
              <h3 className="h6">First seen in this window (context, not a finding)</h3>
              {history !== '' ? (
                <p className="small text-body-secondary">{history}</p>
              ) : (
                <>
                  <CohortNotice cohort={data.cohort} noun="first-seen entries" />
                  {data.first_seen.length > 0 ? (
                    <FirstSeenTable rows={data.first_seen} window={window} detail={detail} />
                  ) : data.cohort.state === 'too-few-sources' ? null : (
                    <p className="text-body-secondary">
                      Nothing new was first seen among the highest-volume destinations and ASNs.
                    </p>
                  )}
                </>
              )}
            </section>
          </>
        );
      }}
    </TrafficGate>
  );
}
