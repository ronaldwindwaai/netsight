import Link from 'next/link';

import { BasisBadge } from '@/components/identity-parts';
import { TrafficPanel } from '@/components/traffic-panel';
import type {
  ApplicationMix,
  AttributionStatus,
  DestinationShare,
  FlowAggregations,
  FlowDirection,
  TimelineBucket,
  TrafficFlow,
  Volume,
} from '@/lib/api-contracts-traffic-explorer';
import { formatBytes, formatShare } from '@/lib/format-bytes';
import type { FilterValues } from '@/lib/traffic-view';
import { formatUtcTimestamp } from '@/lib/format-time';
import {
  NOT_REPORTED,
  WITHHELD_ITEM,
  attributionPresentation,
  destinationScopeText,
} from '@/lib/traffic-view';

const DIRECTION: Record<FlowDirection, { label: string; theme: string }> = {
  inbound: { label: 'Inbound', theme: 'text-bg-info' },
  outbound: { label: 'Outbound', theme: 'text-bg-primary' },
  internal: { label: 'Internal', theme: 'text-bg-secondary' },
  unknown: { label: 'Direction unknown', theme: 'text-bg-secondary' },
};

function reported(value: string | null): string {
  return value !== null && value.trim().length > 0 ? value : NOT_REPORTED;
}

/** Who is behind the source address, with the basis as a word and an icon, never as bare fact. */
export function AttributionCell({
  flow,
  status,
}: {
  flow: TrafficFlow;
  status: AttributionStatus;
}) {
  const view = attributionPresentation(flow.attribution, status);
  return (
    <div className="flow-attribution">
      <span className={view.kind === 'person' ? 'fw-semibold' : 'fst-italic'}>
        {view.personId !== null ? (
          <Link href={`/users/${encodeURIComponent(view.personId)}`}>{view.headline}</Link>
        ) : (
          view.headline
        )}
      </span>
      {view.basis !== null ? (
        <>
          {' '}
          <BasisBadge basis={view.basis} />
          {view.confidence !== '' ? (
            <span className="small text-body-secondary"> · confidence {view.confidence}</span>
          ) : null}
        </>
      ) : null}
      {view.device !== null ? (
        <span className="d-block small text-body-secondary">
          Device{' '}
          {view.deviceId !== null ? (
            <Link href={`/devices/${encodeURIComponent(view.deviceId)}`}>{view.device}</Link>
          ) : (
            view.device
          )}
        </span>
      ) : null}
      {view.reason !== '' ? (
        <span className="d-block small text-body-secondary">{view.reason}</span>
      ) : null}
    </div>
  );
}

/** Builds the Flow Explorer address for the current view narrowed by one more filter. */
export type FlowLinker = (extra: FilterValues) => string;

/** An address that, when a linker is given, drills into the flows to or from it. */
function Endpoint({
  address,
  filter,
  linkTo,
}: {
  address: string;
  filter: 'source_ip' | 'destination_ip';
  linkTo: FlowLinker | undefined;
}) {
  if (linkTo === undefined) return <span className="fw-semibold">{address}</span>;
  const verb = filter === 'source_ip' ? 'from' : 'to';
  return (
    <Link
      className="fw-semibold"
      href={linkTo({ [filter]: address })}
      title={`Show only flows ${verb} ${address}`}
    >
      {address}
    </Link>
  );
}

export function FlowRowsTable({
  flows,
  status,
  linkTo,
}: {
  flows: readonly TrafficFlow[];
  status: AttributionStatus;
  linkTo?: FlowLinker;
}) {
  return (
    <div className="table-responsive">
      <table className="table table-sm table-striped table-hover mb-0">
        <caption className="visually-hidden">
          Flows reported by the connected flow source for the selected window and filters
        </caption>
        <thead>
          <tr>
            <th scope="col">Seen (UTC)</th>
            <th scope="col">Source</th>
            <th scope="col">Who (by basis)</th>
            <th scope="col">Application</th>
            <th scope="col">Destination</th>
            <th scope="col">Direction</th>
            <th scope="col" className="text-end">
              Volume
            </th>
          </tr>
        </thead>
        <tbody>
          {flows.map((flow, index) => (
            <tr
              key={`${index}:${flow.observed_at}:${flow.source_ip}->${flow.destination_ip}:${flow.destination_port ?? ''}`}
            >
              <td className="text-nowrap">{formatUtcTimestamp(flow.observed_at)}</td>
              <td>
                <Endpoint address={flow.source_ip} filter="source_ip" linkTo={linkTo} />
              </td>
              <td>
                <AttributionCell flow={flow} status={status} />
              </td>
              <td>{reported(flow.application)}</td>
              <td>
                <Endpoint address={flow.destination_ip} filter="destination_ip" linkTo={linkTo} />
                {flow.destination_host !== null ? (
                  <span className="d-block small text-body-secondary">{flow.destination_host}</span>
                ) : null}
                <span className="d-block small text-body-secondary">
                  {flow.protocol}
                  {flow.destination_port !== null ? ` port ${flow.destination_port}` : ''}
                </span>
              </td>
              <td>
                <span className={`badge ${DIRECTION[flow.direction].theme}`}>
                  {DIRECTION[flow.direction].label}
                </span>
              </td>
              <td className="text-end">
                <span className="fw-semibold">{formatBytes(flow.bytes)}</span>
                <span className="d-block small text-body-secondary">
                  {flow.packets === null
                    ? 'packets not reported'
                    : `${flow.packets.toLocaleString('en-GB')} packets`}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function bucketWidth(seconds: number): string {
  if (seconds % 86400 === 0) return seconds === 86400 ? '1 day' : `${seconds / 86400} days`;
  if (seconds % 3600 === 0) return seconds === 3600 ? '1 hour' : `${seconds / 3600} hours`;
  return seconds === 60 ? '1 minute' : `${seconds / 60} minutes`;
}

function Bar({ ratio }: { ratio: number }) {
  const width = Math.max(2, Math.min(100, ratio * 100));
  return (
    <div className="progress traffic-bars__progress" role="presentation">
      <div className="progress-bar" style={{ width: `${width}%` }} />
    </div>
  );
}

export function FlowTimeline({
  buckets,
  bucketSeconds,
}: {
  buckets: readonly TimelineBucket[];
  bucketSeconds: number;
}) {
  const largest = Math.max(1, ...buckets.map((bucket) => bucket.bytes));
  return (
    <TrafficPanel
      title="Traffic over time"
      icon="bi-graph-up"
      note={`Each row is ${bucketWidth(bucketSeconds)} of traffic, summed from the source's own counters.`}
    >
      {buckets.length === 0 ? (
        <p className="mb-0 text-body-secondary">
          No traffic in the timeline for this window and filters.
        </p>
      ) : (
        <ol
          className="traffic-bars list-unstyled mb-0 overflow-auto"
          style={{ maxHeight: '18rem' }}
          tabIndex={0}
        >
          {buckets.map((bucket) => (
            <li className="traffic-bars__row" key={bucket.start}>
              <div className="traffic-bars__meta">
                <span className="traffic-bars__label">{formatUtcTimestamp(bucket.start)}</span>
                <span className="traffic-bars__value">
                  {formatBytes(bucket.bytes)}
                  <span className="text-body-secondary">
                    {' '}
                    · {bucket.flows.toLocaleString('en-GB')} flows
                  </span>
                </span>
              </div>
              <Bar ratio={bucket.bytes / largest} />
            </li>
          ))}
        </ol>
      )}
    </TrafficPanel>
  );
}

export function VolumeSummary({ volume }: { volume: Volume }) {
  const stat = (label: string, value: string) => (
    <div className="col-6">
      <dt className="small text-body-secondary fw-normal">{label}</dt>
      <dd className="fs-5 mb-2">{value}</dd>
    </div>
  );
  return (
    <TrafficPanel title="Volume" icon="bi-speedometer2" note="Totals over the whole filtered window.">
      <dl className="row mb-0">
        {stat('Bytes', formatBytes(volume.bytes))}
        {stat('Flows', volume.flows.toLocaleString('en-GB'))}
        {stat(
          'Packets',
          volume.packets === null ? NOT_REPORTED : volume.packets.toLocaleString('en-GB'),
        )}
        {stat('Source addresses', volume.source_addresses.toLocaleString('en-GB'))}
        {stat(
          'Internal endpoints',
          volume.internal_endpoints === null
            ? NOT_REPORTED
            : volume.internal_endpoints.toLocaleString('en-GB'),
        )}
        {stat('Destination addresses', volume.destination_addresses.toLocaleString('en-GB'))}
      </dl>
    </TrafficPanel>
  );
}

export function ApplicationMixPanel({ mix }: { mix: ApplicationMix | null }) {
  if (mix === null) {
    return (
      <TrafficPanel title="Application mix" icon="bi-pie-chart">
        <p className="mb-0 text-body-secondary">
          Application is not reported by the flow source, so no mix is shown. Nothing is guessed from
          ports.
        </p>
      </TrafficPanel>
    );
  }
  const largest = Math.max(1, mix.total_bytes);
  return (
    <TrafficPanel
      title="Application mix"
      icon="bi-pie-chart"
      note="Share of bytes across the whole filtered window, not only the listed rows."
    >
      <ol className="traffic-bars list-unstyled mb-0">
        {mix.items.map((item, index) => (
          <li className="traffic-bars__row" key={`${index}:${item.application ?? ''}`}>
            <div className="traffic-bars__meta">
              <span className="traffic-bars__label" title={item.application ?? undefined}>
                {item.application ?? 'No application reported'}
              </span>
              <span className="traffic-bars__value">
                {item.bytes === null ? (
                  <span className="text-body-secondary">{WITHHELD_ITEM}</span>
                ) : (
                  <>
                    {formatBytes(item.bytes)}
                    <span className="text-body-secondary"> · {formatShare(item.share)}</span>
                  </>
                )}
              </span>
            </div>
            {item.bytes === null ? null : <Bar ratio={item.share ?? item.bytes / largest} />}
          </li>
        ))}
        {mix.other_bytes > 0 ? (
          <li className="traffic-bars__row">
            <div className="traffic-bars__meta">
              <span className="traffic-bars__label">Other applications</span>
              <span className="traffic-bars__value">{formatBytes(mix.other_bytes)}</span>
            </div>
            <Bar ratio={mix.other_bytes / largest} />
          </li>
        ) : null}
      </ol>
    </TrafficPanel>
  );
}

export function DestinationSharePanel({
  destinations,
}: {
  destinations: readonly DestinationShare[];
}) {
  const largest = Math.max(1, ...destinations.map((destination) => destination.bytes ?? 0));
  return (
    <TrafficPanel
      title="Top destinations"
      icon="bi-globe2"
      note="Ranked by bytes across the whole filtered window."
    >
      {destinations.length === 0 ? (
        <p className="mb-0 text-body-secondary">No destinations in this window and filters.</p>
      ) : (
        <ol className="traffic-bars list-unstyled mb-0">
          {destinations.map((destination, index) => (
            <li className="traffic-bars__row" key={`${index}:${destination.address}`}>
              <div className="traffic-bars__meta">
                <span className="traffic-bars__rank" aria-hidden="true">
                  {index + 1}
                </span>
                <span className="traffic-bars__label">
                  {destination.host !== null
                    ? `${destination.host} (${destination.address})`
                    : destination.address}
                  {destination.scope === 'internal' ? (
                    <span className="badge text-bg-secondary ms-2">
                      {destinationScopeText(destination.scope)}
                    </span>
                  ) : null}
                </span>
                <span className="traffic-bars__value">
                  {destination.bytes === null ? (
                    <span className="text-body-secondary">{WITHHELD_ITEM}</span>
                  ) : (
                    <>
                      {formatBytes(destination.bytes)}
                      <span className="text-body-secondary">
                        {' '}
                        · {formatShare(destination.share)}
                      </span>
                    </>
                  )}
                </span>
              </div>
              {destination.bytes === null ? null : (
                <Bar ratio={destination.share ?? destination.bytes / largest} />
              )}
            </li>
          ))}
        </ol>
      )}
    </TrafficPanel>
  );
}

export function Aggregations({ data }: { data: FlowAggregations }) {
  return (
    <div className="row g-3 mb-3">
      <div className="col-xl-4">
        <VolumeSummary volume={data.volume} />
      </div>
      <div className="col-xl-8">
        <FlowTimeline buckets={data.timeline} bucketSeconds={data.bucket_seconds} />
      </div>
      <div className="col-xl-6">
        <ApplicationMixPanel mix={data.application_mix} />
      </div>
      <div className="col-xl-6">
        <DestinationSharePanel destinations={data.destinations} />
      </div>
    </div>
  );
}
