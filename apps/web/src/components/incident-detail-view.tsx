import { SeverityBadge, StateBadge } from '@/components/incident-badges';
import type { Incident, IncidentResolution } from '@/lib/api-contracts-incident';
import { formatUtcTimestamp } from '@/lib/format-time';

/** Hard-wrapped, preserved-newline text node: untrusted text, never markup. */
const MULTILINE = { whiteSpace: 'pre-wrap' } as const;

function Fact({ term, children }: { term: string; children: React.ReactNode }) {
  return (
    <div className="col-6 col-lg-3">
      <dt className="small text-body-secondary fw-normal">{term}</dt>
      <dd className="mb-0 text-break">{children}</dd>
    </div>
  );
}

export function IncidentSummary({ incident }: { incident: Incident }) {
  return (
    <dl className="row g-3 mb-0">
      <Fact term="Severity">
        <SeverityBadge severity={incident.severity} />
      </Fact>
      <Fact term="State">
        <StateBadge state={incident.state} />
      </Fact>
      <Fact term="Assignee">
        {incident.assignee_id ?? <span className="text-body-secondary">Unassigned</span>}
      </Fact>
      <Fact term="Incident id">
        <code>{incident.id}</code>
      </Fact>
      <Fact term="Created">{formatUtcTimestamp(incident.created_at)}</Fact>
      <Fact term="Last updated">{formatUtcTimestamp(incident.updated_at)}</Fact>
    </dl>
  );
}

export function IncidentEvidence({ evidenceIds }: { evidenceIds: readonly string[] }) {
  if (evidenceIds.length === 0) {
    return (
      <p className="text-body-secondary mb-0">
        No evidence has been attached to this incident.
      </p>
    );
  }
  return (
    <>
      <p className="small text-body-secondary">
        Evidence is shown by identifier only; evidence content is not fetched here.
      </p>
      <ul className="list-unstyled mb-0" aria-label="Evidence identifiers">
        {evidenceIds.map((evidenceId) => (
          <li key={evidenceId} className="text-break">
            <code>{evidenceId}</code>
          </li>
        ))}
      </ul>
    </>
  );
}

export function ResolutionBlock({ resolution }: { resolution: IncidentResolution }) {
  return (
    <dl className="mb-0">
      <dt className="small text-body-secondary fw-normal">Summary</dt>
      <dd className="text-break" style={MULTILINE}>
        {resolution.summary}
      </dd>
      <dt className="small text-body-secondary fw-normal">Root cause</dt>
      <dd className="text-break" style={MULTILINE}>
        {resolution.root_cause_status === 'determined' && resolution.root_cause !== null ? (
          resolution.root_cause
        ) : (
          <span className="text-body-secondary">Not determined</span>
        )}
      </dd>
      <dt className="small text-body-secondary fw-normal">Impact</dt>
      <dd className="text-break" style={MULTILINE}>
        {resolution.impact}
      </dd>
      <dt className="small text-body-secondary fw-normal">Service restored</dt>
      <dd>{formatUtcTimestamp(resolution.restored_at)}</dd>
      <dt className="small text-body-secondary fw-normal">Resolved</dt>
      <dd>
        {formatUtcTimestamp(resolution.resolved_at)} by{' '}
        <span className="text-break">{resolution.resolved_by}</span>
      </dd>
      <dt className="small text-body-secondary fw-normal">Follow-up actions</dt>
      <dd className="mb-0">
        {resolution.follow_up_actions.length === 0 ? (
          <span className="text-body-secondary">None recorded</span>
        ) : (
          <ul className="mb-0">
            {resolution.follow_up_actions.map((action, index) => (
              <li key={`${index}:${action}`} className="text-break">
                {action}
              </li>
            ))}
          </ul>
        )}
      </dd>
    </dl>
  );
}
