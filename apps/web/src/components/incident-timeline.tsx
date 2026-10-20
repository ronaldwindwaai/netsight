import Link from 'next/link';

import type { IncidentTimelineEvent } from '@/lib/api-contracts-incident';
import { formatUtcTimestamp } from '@/lib/format-time';
import { StateBadge } from '@/components/incident-badges';
import { timelineEventSummary, timelineSubjectLink } from '@/lib/incident-view';

const MULTILINE = { whiteSpace: 'pre-wrap' } as const;

/**
 * Append-only timeline in server order (ascending seq). Actor ids, reasons and
 * messages are untrusted text and render as plain text nodes.
 */
export function IncidentTimeline({ events }: { events: readonly IncidentTimelineEvent[] }) {
  return (
    <ol className="list-unstyled mb-0 px-3 pt-3" aria-label="Incident timeline">
      {events.map((event) => {
        const summary = timelineEventSummary(event);
        const link = timelineSubjectLink(event);
        return (
          <li key={event.id} className="border-start ps-3 pb-3">
            <div className="d-flex flex-wrap align-items-center gap-2">
              <span className="badge text-bg-light border">
                <i className="bi bi-clock-history me-1" aria-hidden="true" />
                {summary.label}
              </span>
              <time className="small text-body-secondary" dateTime={event.occurred_at}>
                {formatUtcTimestamp(event.occurred_at)}
              </time>
              <span className="small text-body-secondary text-break">
                #{event.seq} by {event.actor_id}
              </span>
            </div>
            {event.kind === 'state-changed' && event.state_from && event.state_to ? (
              <div className="mt-1 d-flex flex-wrap align-items-center gap-2">
                <StateBadge state={event.state_from} />
                <i className="bi bi-arrow-right" aria-hidden="true" />
                <StateBadge state={event.state_to} />
              </div>
            ) : summary.detail ? (
              <div className="mt-1 text-break">{summary.detail}</div>
            ) : null}
            {link ? (
              <div className="mt-1 small">
                <Link href={link.href}>
                  {link.label}
                  <i className="bi bi-arrow-right-short" aria-hidden="true" />
                </Link>
              </div>
            ) : null}
            {event.reason ? (
              <div className="mt-1 small text-break" style={MULTILINE}>
                <span className="text-body-secondary">Reason: </span>
                {event.reason}
              </div>
            ) : null}
            {event.message ? (
              <p className="mt-1 mb-0 text-break" style={MULTILINE}>
                {event.message}
              </p>
            ) : null}
          </li>
        );
      })}
    </ol>
  );
}
