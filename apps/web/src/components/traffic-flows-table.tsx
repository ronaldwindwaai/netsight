import Link from 'next/link';

import type { FlowDirection, TrafficFlow } from '@/lib/api-contracts';
import { formatBytes } from '@/lib/format-bytes';

const DIRECTION_THEME: Record<FlowDirection, string> = {
  inbound: 'text-bg-info',
  outbound: 'text-bg-primary',
  internal: 'text-bg-secondary',
  unknown: 'text-bg-secondary',
};

function reported(value: string | null): string {
  return value && value.trim().length > 0 ? value : 'Not reported';
}

/**
 * Recent high-volume flows.
 *
 * Every address, host, user and application value is source-reported and is
 * rendered as text only. A flow whose source device is not resolved to a
 * canonical ID says so rather than guessing.
 */
export function TrafficFlowsTable({ flows }: { flows: TrafficFlow[] }) {
  return (
    <div className="table-responsive">
      <table className="table table-sm table-striped table-hover mb-0">
        <caption className="visually-hidden">
          Recent high-volume flows reported by the connected flow source
        </caption>
        <thead>
          <tr>
            <th scope="col">Source</th>
            <th scope="col">User</th>
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
              <td>
                <span className="fw-semibold">{flow.source_ip}</span>
                <span className="d-block small text-body-secondary">
                  {flow.source_device_id ? (
                    <Link href={`/devices/${encodeURIComponent(flow.source_device_id)}`}>
                      {flow.source_device_id}
                    </Link>
                  ) : (
                    'Device not resolved'
                  )}
                </span>
              </td>
              <td>{reported(flow.user)}</td>
              <td>{reported(flow.application)}</td>
              <td>
                <span className="fw-semibold">{flow.destination_ip}</span>
                {flow.destination_host ? (
                  <span className="d-block small text-body-secondary">{flow.destination_host}</span>
                ) : null}
              </td>
              <td>
                <span className={`badge ${DIRECTION_THEME[flow.direction]}`}>{flow.direction}</span>
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