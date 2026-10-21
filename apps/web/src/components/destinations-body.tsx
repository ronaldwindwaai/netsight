import Link from 'next/link';

import { CohortNotice } from '@/components/cohort-notice';
import { ExportCsvButton } from '@/components/export-csv-button';
import { FreshnessNotice } from '@/components/data-state';
import { StateSurface } from '@/components/state-surface';
import { StatusWord } from '@/components/traffic-status';
import { TrafficGate } from '@/components/traffic-surface';
import type {
  CohortStatus,
  DestinationRow,
  TrafficDestinationsResponse,
} from '@/lib/api-contracts-traffic-explorer';
import { DESTINATION_CSV_HEADERS, destinationCsvRows } from '@/lib/traffic-csv';
import type { FetchState } from '@/lib/api-response';
import type { FilterValues, TrafficWindow } from '@/lib/traffic-view';
import { formatBytes, formatShare } from '@/lib/format-bytes';
import { formatUtcTimestamp } from '@/lib/format-time';
import {
  NOT_REPORTED,
  UNKNOWN,
  destinationScopeText,
  flowsDrillHref,
  policyNotice,
  reputationPresentation,
  withheldCountText,
  withheldRowText,
} from '@/lib/traffic-view';

function count(value: number | null, cohort: CohortStatus): string {
  return value === null ? withheldCountText(cohort) : value.toLocaleString('en-GB');
}

function WithheldRow({ item, cohort }: { item: DestinationRow; cohort: CohortStatus }) {
  return (
    <tr className="text-body-secondary" data-visibility="withheld">
      <td>
        <span className="fw-semibold">{item.address}</span>
      </td>
      <td colSpan={7}>{withheldRowText(cohort)}</td>
      <td>
        <StatusWord {...reputationPresentation(item.reputation)} />
      </td>
    </tr>
  );
}

/** Plain text, or a link to the Flow Explorer narrowed by one filter when that is allowed. */
function Drill({
  window,
  detail,
  filter,
  title,
  children,
}: {
  window: TrafficWindow | undefined;
  detail: boolean;
  filter: FilterValues;
  title: string;
  children: string;
}) {
  const href = window === undefined ? null : flowsDrillHref(window, filter, { detail });
  if (href === null) return <>{children}</>;
  return (
    <Link href={href} title={title}>
      {children}
    </Link>
  );
}

function Row({
  item,
  cohort,
  window,
  detail,
}: {
  item: DestinationRow;
  cohort: CohortStatus;
  window: TrafficWindow | undefined;
  detail: boolean;
}) {
  if (item.visibility === 'withheld' || item.bytes === null || item.last_seen === null) {
    return <WithheldRow item={item} cohort={cohort} />;
  }
  return (
    <tr>
      <td>
        <span className="fw-semibold">
          <Drill
            window={window}
            detail={detail}
            filter={{ destination_ip: item.address }}
            title="Show the flows to this destination"
          >
            {item.address}
          </Drill>
        </span>
        <span className="d-block small text-body-secondary">{item.domain ?? 'Domain not reported'}</span>
        {item.scope === 'internal' ? (
          <span className="badge text-bg-secondary">{destinationScopeText(item.scope)}</span>
        ) : null}
      </td>
      <td>
        {item.asn === null ? (
          NOT_REPORTED
        ) : (
          <Drill
            window={window}
            detail={detail}
            filter={{ asn: String(item.asn) }}
            title="Show the flows to this ASN"
          >
            {`AS${item.asn}`}
          </Drill>
        )}
      </td>
      <td>
        {item.country === null ? (
          NOT_REPORTED
        ) : (
          <Drill
            window={window}
            detail={detail}
            filter={{ country: item.country }}
            title="Show the flows to this country"
          >
            {item.country}
          </Drill>
        )}
      </td>
      <td className="text-nowrap">
        {item.first_seen === null ? NOT_REPORTED : formatUtcTimestamp(item.first_seen)}
      </td>
      <td className="text-nowrap">{formatUtcTimestamp(item.last_seen)}</td>
      <td>{count(item.endpoints, cohort)}</td>
      <td>{item.users === null ? UNKNOWN : count(item.users, cohort)}</td>
      <td>
        <span className="fw-semibold">{formatBytes(item.bytes)}</span>
        <span className="d-block small text-body-secondary">{formatShare(item.share)}</span>
      </td>
      <td>
        <StatusWord {...reputationPresentation(item.reputation)} />
      </td>
    </tr>
  );
}

/**
 * Destinations by volume. Domain, ASN and country are source-reported (a domain from reverse DNS is
 * controlled by whoever owns the address) and are rendered as text. Reputation comes only from the
 * operator allow and deny lists, never from a source guess. First seen is bounded by a stated
 * look-back and is not the destination's history.
 */
export function DestinationsBody({
  state,
  window,
  detail = false,
}: {
  state: FetchState<TrafficDestinationsResponse>;
  /** When given, addresses, ASNs and countries link to the Flow Explorer for that window. */
  window?: TrafficWindow;
  /** Whether the viewer holds traffic:read-detail (address filters are refused without it). */
  detail?: boolean;
}) {
  return (
    <TrafficGate state={state} noun="destinations" permission="traffic:read">
      {(data) => {
        const notice = policyNotice(data.policy.state, 'reputation');
        return (
          <>
            <FreshnessNotice freshness={data.freshness} />
            {notice !== '' ? <p className="small text-body-secondary">{notice}</p> : null}
            <CohortNotice cohort={data.cohort} noun="endpoint counts" />
            {data.items.length === 0 ? (
              <StateSurface
                icon="bi bi-inboxes"
                title="No destinations in this window"
                detail="The flow source reported a valid empty result for this window. This is not proof that nothing was contacted."
              />
            ) : (
              <section
                aria-label="Destinations"
                className="card card-outline card-primary operational-card"
              >
                <div className="d-flex justify-content-end p-2 border-bottom">
                  <ExportCsvButton
                    headers={DESTINATION_CSV_HEADERS}
                    label="traffic-destinations"
                    rows={destinationCsvRows(data.items)}
                  />
                </div>
                <div className="table-responsive">
                  <table className="table table-sm table-striped table-hover mb-0">
                    <caption className="visually-hidden">
                      Destinations by volume for the selected window
                    </caption>
                    <thead>
                      <tr>
                        <th scope="col">Destination</th>
                        <th scope="col">ASN</th>
                        <th scope="col">Location</th>
                        <th scope="col">First seen</th>
                        <th scope="col">Last seen</th>
                        <th scope="col">Endpoints</th>
                        <th scope="col">Users</th>
                        <th scope="col">Volume</th>
                        <th scope="col">Reputation</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.items.map((item) => (
                        <Row
                          key={`${item.rank}:${item.address}`}
                          item={item}
                          cohort={data.cohort}
                          window={window}
                          detail={detail}
                        />
                      ))}
                    </tbody>
                  </table>
                </div>
                <ul className="small text-body-secondary px-3 py-2 mb-0">
                  <li>
                    {data.first_seen_since === null
                      ? 'First seen was not determined for this read.'
                      : `First seen is the earliest time seen since ${formatUtcTimestamp(data.first_seen_since)} (a bounded look-back), not the destination's full history.`}
                  </li>
                  <li>
                    Reputation comes only from the operator allow and deny lists in the traffic
                    policy; a hostname can deny but never allow, because reverse DNS is controlled by
                    the address owner.
                  </li>
                  <li>
                    Endpoints are distinct internal endpoints. Users are Unknown: counting people
                    needs per-flow identity attribution, which this page does not do. A destination
                    that fewer endpoints than the minimum reached is listed by address only.
                  </li>
                  <li>
                    {data.cohort.state === 'not-applied'
                      ? 'Destinations inside the organisation are listed and labelled; they are not shown to roles without the detail permission.'
                      : 'Destinations inside the organisation are not listed to your role.'}
                  </li>
                </ul>
              </section>
            )}
          </>
        );
      }}
    </TrafficGate>
  );
}
