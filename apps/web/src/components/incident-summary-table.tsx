import { SeverityBadge, StateBadge } from '@/components/incident-badges';
import type { IncidentSummary } from '@/lib/api-contracts-incident-api';
import { RelativeTime } from '@/components/relative-time';
import { formatUtcTimestamp } from '@/lib/format-time';

/**
 * Management's summary rows: severity, headline, state, whether somebody holds it and when it
 * was resolved. There is deliberately no link to a detail page and no assignee, evidence or
 * comment column: the API does not return them for this role. Titles are operator-entered text
 * and render as plain text nodes.
 */
export function IncidentSummaryTable({ incidents }: { incidents: readonly IncidentSummary[] }) {
  return (
    <div className="table-responsive">
      <table className="table table-sm table-striped table-hover mb-0">
        <caption className="visually-hidden">Incident summaries, newest first</caption>
        <thead>
          <tr>
            <th scope="col">Severity</th>
            <th scope="col">Incident</th>
            <th scope="col">State</th>
            <th scope="col">Ownership</th>
            <th scope="col">Created</th>
            <th scope="col">Updated</th>
            <th scope="col">Resolved</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((incident) => (
            <tr key={incident.id}>
              <td>
                <SeverityBadge severity={incident.severity} />
              </td>
              <td className="text-break fw-semibold">{incident.title}</td>
              <td>
                <StateBadge state={incident.state} />
              </td>
              <td>
                {incident.assigned ? (
                  'Assigned'
                ) : (
                  <span className="small text-body-secondary">Unassigned</span>
                )}
              </td>
              <td className="text-nowrap"><RelativeTime value={incident.created_at} /></td>
              <td className="text-nowrap"><RelativeTime value={incident.updated_at} /></td>
              <td className="text-nowrap">
                {incident.resolved_at === null ? (
                  <span className="small text-body-secondary">Not resolved</span>
                ) : (
                  formatUtcTimestamp(incident.resolved_at)
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
