import Link from 'next/link';

import type { AlertSeverity } from '@/lib/api-contracts';
import type { SecurityEvent } from '@/lib/api-contracts-security';

const SEVERITY_THEME: Record<AlertSeverity, string> = {
  critical: 'text-bg-danger',
  high: 'text-bg-warning',
  medium: 'text-bg-info',
  low: 'text-bg-secondary',
  info: 'text-bg-light',
};

const SOURCE_LABEL: Record<SecurityEvent['source'], string> = {
  wazuh: 'Wazuh',
  suricata: 'Suricata',
};

const TIME_FORMAT = new Intl.DateTimeFormat('en-GB', {
  dateStyle: 'short',
  timeStyle: 'medium',
  timeZone: 'UTC',
});

function formatTime(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : `${TIME_FORMAT.format(parsed)} UTC`;
}

/**
 * Security events from the connected sources.
 *
 * Signature, category and address text is source-reported, untrusted
 * telemetry and is rendered as plain text only — never as markup or as an
 * instruction. An event with no canonical device says so rather than
 * guessing from an address.
 */
/** Address of the Flow Explorer for one source address, or null when it may not be offered. */
export type FlowsHref = (sourceIp: string) => string | null;

function Address({ value, flowsHref }: { value: string; flowsHref: FlowsHref | undefined }) {
  const href = flowsHref?.(value) ?? null;
  if (href === null) return <>{value}</>;
  return (
    <Link href={href} title="Show the flows from this address">
      {value}
    </Link>
  );
}

export function SecurityEventsTable({
  events,
  flowsHref,
}: {
  events: SecurityEvent[];
  flowsHref?: FlowsHref;
}) {
  return (
    <div className="table-responsive">
      <table className="table table-sm table-striped table-hover mb-0">
        <caption className="visually-hidden">
          Security events reported by the connected security sources
        </caption>
        <thead>
          <tr>
            <th scope="col">Time</th>
            <th scope="col">Severity</th>
            <th scope="col">Signature</th>
            <th scope="col">Source</th>
            <th scope="col">Endpoints</th>
            <th scope="col">Device</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={`${event.source}:${event.id}`}>
              <td className="text-nowrap">{formatTime(event.observed_at)}</td>
              <td>
                <span className={`badge ${SEVERITY_THEME[event.severity]}`}>{event.severity}</span>
              </td>
              <td>
                <span className="fw-semibold">{event.signature}</span>
                {event.category ? (
                  <span className="d-block small text-body-secondary">{event.category}</span>
                ) : null}
              </td>
              <td>{SOURCE_LABEL[event.source]}</td>
              <td>
                <span>
                  {event.source_ip === null ? (
                    'Not reported'
                  ) : (
                    <Address value={event.source_ip} flowsHref={flowsHref} />
                  )}
                </span>
                {event.destination_ip ? (
                  <span className="d-block small text-body-secondary">
                    → {event.destination_ip}
                  </span>
                ) : null}
              </td>
              <td>
                {event.device_id ? (
                  <Link href={`/devices/${encodeURIComponent(event.device_id)}`}>
                    {event.device_id}
                  </Link>
                ) : (
                  <span className="small text-body-secondary">Device not resolved</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
