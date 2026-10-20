import Link from 'next/link';

import { CohortNotice } from '@/components/cohort-notice';
import { FreshnessNotice } from '@/components/data-state';
import { StateSurface } from '@/components/state-surface';
import { StatusWord } from '@/components/traffic-status';
import { TrafficGate } from '@/components/traffic-surface';
import type {
  ApplicationRow,
  CohortStatus,
  TrafficApplicationsResponse,
} from '@/lib/api-contracts-traffic-explorer';
import type { FetchState } from '@/lib/api-response';
import type { TrafficWindow } from '@/lib/traffic-view';
import { formatBytes, formatShare } from '@/lib/format-bytes';
import {
  UNKNOWN,
  approvalPresentation,
  flowsDrillHref,
  policyNotice,
  riskPresentation,
  trendPresentation,
  withheldCountText,
  withheldRowText,
} from '@/lib/traffic-view';

function count(value: number | null, cohort: CohortStatus): string {
  return value === null ? withheldCountText(cohort) : value.toLocaleString('en-GB');
}

function WithheldRow({ item, cohort }: { item: ApplicationRow; cohort: CohortStatus }) {
  const reason = withheldRowText(cohort);
  return (
    <tr className="text-body-secondary" data-visibility="withheld">
      <td>
        <span className="fw-semibold">{item.application}</span>
        <span className="d-block small">{item.category ?? 'Category not reported'}</span>
      </td>
      <td colSpan={4}>{reason}</td>
      <td>
        <StatusWord {...riskPresentation(item.risk)} />
      </td>
      <td>
        <StatusWord {...approvalPresentation(item.approval)} />
      </td>
    </tr>
  );
}

function AppName({ item, drill }: { item: ApplicationRow; drill: string | null }) {
  return drill === null ? (
    <span className="fw-semibold">{item.application}</span>
  ) : (
    <Link className="fw-semibold" href={drill} title="Show the flows for this application">
      {item.application}
    </Link>
  );
}

function Row({
  item,
  cohort,
  drill,
}: {
  item: ApplicationRow;
  cohort: CohortStatus;
  drill: string | null;
}) {
  if (item.visibility === 'withheld' || item.bytes === null) {
    return <WithheldRow item={item} cohort={cohort} />;
  }
  const trend = trendPresentation(item.trend);
  return (
    <tr>
      <td>
        <AppName item={item} drill={drill} />
        <span className="d-block small text-body-secondary">
          {item.category ?? 'Category not reported'}
        </span>
      </td>
      <td>
        <span className="fw-semibold">{formatBytes(item.bytes)}</span>
        <span className="d-block small text-body-secondary">{formatShare(item.share)}</span>
      </td>
      <td>{count(item.endpoints, cohort)}</td>
      <td>{item.users === null ? UNKNOWN : count(item.users, cohort)}</td>
      <td>
        <StatusWord label={trend.text} icon={trend.icon} theme={trend.theme} />
      </td>
      <td>
        <StatusWord {...riskPresentation(item.risk)} />
      </td>
      <td>
        <StatusWord {...approvalPresentation(item.approval)} />
      </td>
    </tr>
  );
}

/**
 * Applications by volume. Names and categories are source-reported text and are rendered as text.
 * Risk and approval come only from the operator policy file: without one they are Unknown, and the
 * page says so. Users are Unknown because counting people needs per-flow identity attribution.
 */
export function ApplicationsBody({
  state,
  window,
}: {
  state: FetchState<TrafficApplicationsResponse>;
  /** When given, application names link to the Flow Explorer for that application and window. */
  window?: TrafficWindow;
}) {
  return (
    <TrafficGate
      state={state}
      noun="applications"
      permission="traffic:read"
      unknownDetail={(data) =>
        data.unsupported.length > 0
          ? {
              title: 'The flow source does not report applications',
              detail:
                'The flow table has no application field, so no application breakdown can be shown. Nothing is guessed from ports or destinations.',
            }
          : null
      }
    >
      {(data) => {
        const notice = policyNotice(data.policy.state, 'approval and risk');
        return (
          <>
            <FreshnessNotice freshness={data.freshness} />
            {notice !== '' ? <p className="small text-body-secondary">{notice}</p> : null}
            <CohortNotice cohort={data.cohort} noun="endpoint counts" />
            {data.items.length === 0 ? (
              <StateSurface
                icon="bi bi-inboxes"
                title="No applications in this window"
                detail="The flow source reported a valid empty result for this window. This is not proof that nothing was used."
              />
            ) : (
              <section
                aria-label="Applications"
                className="card card-outline card-primary operational-card"
              >
                <div className="table-responsive">
                  <table className="table table-sm table-striped table-hover mb-0">
                    <caption className="visually-hidden">
                      Applications by volume for the selected window
                    </caption>
                    <thead>
                      <tr>
                        <th scope="col">Application</th>
                        <th scope="col">Volume</th>
                        <th scope="col">Endpoints (internal)</th>
                        <th scope="col">Users</th>
                        <th scope="col">Trend</th>
                        <th scope="col">Risk</th>
                        <th scope="col">Approval</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.items.map((item) => (
                        <Row
                          key={`${item.rank}:${item.application}`}
                          item={item}
                          cohort={data.cohort}
                          drill={
                            window === undefined
                              ? null
                              : flowsDrillHref(window, { application: item.application }, { detail: false })
                          }
                        />
                      ))}
                    </tbody>
                  </table>
                </div>
                <ul className="small text-body-secondary px-3 py-2 mb-0">
                  <li>
                    Endpoints are the distinct internal endpoints (the inside of each flow) seen
                    using the application: not people, and not inventory devices. An application
                    that fewer endpoints than the minimum used is listed by name only.
                  </li>
                  <li>
                    Users are Unknown here: counting people needs per-flow identity attribution,
                    which this page does not do.
                  </li>
                  <li>
                    {data.previous_range === null
                      ? 'No previous window was compared (windows over 7 days have no trend), so every trend is Unknown.'
                      : 'Trend is compared with the preceding window of equal length; flat is within 10%.'}
                  </li>
                  <li>Volume is summed as the flow source stores it; nothing is extrapolated.</li>
                </ul>
              </section>
            )}
          </>
        );
      }}
    </TrafficGate>
  );
}
