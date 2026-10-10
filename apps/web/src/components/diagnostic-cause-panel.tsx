/**
 * Probable-cause panel of a stored diagnostic session (S7 Step 4e). Read-only: every evidence line
 * is labelled Observed / Inferred / Unknown, and a cause is never presented as proven. All text from
 * the session is rendered as React text nodes, never as HTML.
 */
import { Alert, Card } from '@adminlte/react';

import { FindingList } from '@/components/diagnostic-run-view';
import type { DiagnosticRun } from '@/lib/api-contracts-diagnostic';
import type {
  CausePattern,
  DiagnosticEvidenceItem,
  DiagnosticProbableCause,
} from '@/lib/api-contracts-diagnostic-session';
import { basisLabel } from '@/lib/diagnostic-session-view';
import { confidenceLabel, faultDomainLabel, noFaultNarrative, runCheckSummary } from '@/lib/diagnostic-view';

const BASIS_TONE: Record<DiagnosticEvidenceItem['basis'], string> = {
  observed: 'text-bg-success',
  inferred: 'text-bg-warning',
  unknown: 'text-bg-secondary',
};

const PATTERN_TEXT: Record<CausePattern, string | null> = {
  'external-only-failure': 'Internal ok, external failing (inferred, not proven)',
  'service-failure': 'The service itself is failing, even from the server VLAN (inferred)',
  other: 'Narrowed by the failed checks (inferred, not measured)',
  none: null,
};

function checksText(count: number): string | null {
  if (count === 0) return null;
  return `${count} ${count === 1 ? 'check' : 'checks'}`;
}

function EvidenceList({ lines }: { lines: readonly DiagnosticEvidenceItem[] }) {
  if (lines.length === 0) {
    return <p className="small text-body-secondary mb-0">No evidence lines were recorded.</p>;
  }
  return (
    <ul className="list-unstyled mb-0" aria-label="Evidence">
      {lines.map((line, index) => {
        const cited = checksText(line.check_ids.length);
        return (
          <li key={`${line.basis}-${index}`} className="d-flex flex-wrap align-items-baseline gap-2 mb-1">
            <span
              className={`badge ${BASIS_TONE[line.basis]}`}
              data-testid="evidence-basis"
              title="How this line is known"
            >
              {basisLabel(line.basis)}
            </span>
            <span>{line.statement}</span>
            {cited !== null ? (
              <span className="badge text-bg-light border" title="checks this line cites">
                {cited}
              </span>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}

export function ProbableCausePanel({
  cause,
  run,
}: {
  cause: DiagnosticProbableCause;
  run: DiagnosticRun;
}) {
  const domain = faultDomainLabel(cause.domain);
  const pattern = PATTERN_TEXT[cause.pattern];
  return (
    <section aria-label="Probable cause" className="mb-3">
      <Card
        className="operational-card"
        title="Probable cause"
        icon="bi bi-bandaid"
        variant="outline"
        theme="primary"
        bodyClass="p-3"
      >
        {domain === null ? (
          <div className="mb-3">
            <div className="d-flex flex-wrap align-items-center gap-2 mb-1">
              <span className="fw-semibold">No probable cause was identified</span>
              <span className="badge text-bg-secondary">{confidenceLabel(cause.confidence)}</span>
            </div>
            <p className="small text-body-secondary mb-0">{noFaultNarrative(runCheckSummary(run))}</p>
          </div>
        ) : (
          <div className="mb-3">
            <div className="d-flex flex-wrap align-items-center gap-2 mb-1">
              <span className="fs-5 fw-semibold">{domain}</span>
              <span className="badge text-bg-warning">{confidenceLabel(cause.confidence)}</span>
              <span className="badge text-bg-light border">{basisLabel(cause.basis)}</span>
            </div>
            {pattern !== null ? <p className="small fw-semibold mb-1">Pattern: {pattern}</p> : null}
            <p className="mb-0">{cause.summary}</p>
          </div>
        )}
        <h3 className="h6 fw-semibold text-body-secondary border-bottom pb-1">Evidence</h3>
        <EvidenceList lines={cause.evidence} />
      </Card>

      {run.contradictions.length > 0 ? (
        <div className="mt-3">
          <Alert theme="danger" title="Contradictory evidence" icon="bi bi-exclamation-octagon">
            <FindingList heading="Contradictions" items={run.contradictions} />
          </Alert>
        </div>
      ) : null}
      {run.unknowns.length > 0 ? (
        <div className="mt-3">
          <Alert theme="warning" title="What could not be determined" icon="bi bi-question-circle">
            <FindingList heading="Unknowns" items={run.unknowns} />
          </Alert>
        </div>
      ) : null}
      {run.alternative_hypotheses.length > 0 ? (
        <div className="mt-3">
          <Alert theme="info" title="Alternative hypotheses" icon="bi bi-diagram-3">
            <FindingList heading="Alternatives" items={run.alternative_hypotheses} />
          </Alert>
        </div>
      ) : null}
      {run.recommended_next_checks.length > 0 ? (
        <div className="mt-3">
          <Card
            className="operational-card"
            title="Recommended next checks"
            icon="bi bi-list-check"
            variant="outline"
            theme="secondary"
            bodyClass="p-3"
          >
            <FindingList heading="Next checks" items={run.recommended_next_checks} />
          </Card>
        </div>
      ) : null}
    </section>
  );
}
