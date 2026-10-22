import Link from 'next/link';

import { SeverityBadge, StateBadge } from '@/components/incident-badges';
import type { Incident } from '@/lib/api-contracts-incident';
import { RelativeTime } from '@/components/relative-time';

import { incidentHref } from '@/lib/incident-view';

/**
 * Incident rows. Titles and assignees are operator-entered, untrusted text and
 * render as plain text nodes. The link is built only from an id that matches the
 * contract pattern; otherwise the title is shown without a link.
 */
export function IncidentListTable({ incidents }: { incidents: readonly Incident[] }) {
  return (
    <div className="table-responsive">
      <table className="table table-sm table-striped table-hover mb-0">
        <caption className="visually-hidden">Incidents, newest first</caption>
        <thead>
          <tr>
            <th scope="col">Severity</th>
            <th scope="col">Incident</th>
            <th scope="col">State</th>
            <th scope="col">Assignee</th>
            <th scope="col">Evidence</th>
            <th scope="col">Created</th>
            <th scope="col">Updated</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((incident) => {
            const href = incidentHref(incident.id);
            return (
              <tr key={incident.id}>
                <td>
                  <SeverityBadge severity={incident.severity} />
                </td>
                <td className="text-break incident-title">
                  {href ? (
                    <Link className="fw-semibold" href={href}>
                      {incident.title}
                    </Link>
                  ) : (
                    <span className="fw-semibold">{incident.title}</span>
                  )}
                </td>
                <td>
                  <StateBadge state={incident.state} />
                </td>
                <td className="text-break incident-assignee">
                  {incident.assignee_id ?? (
                    <span className="small text-body-secondary">Unassigned</span>
                  )}
                </td>
                <td>{incident.evidence_ids.length}</td>
                <td className="text-nowrap"><RelativeTime value={incident.created_at} /></td>
                <td className="text-nowrap"><RelativeTime value={incident.updated_at} /></td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
