/**
 * Read-only rendering of a completed diagnostic run (S7-3). Untrusted values
 * (target, symptom, details, statements) are always React text nodes — never
 * injected HTML. Every finding is shown as data with its source evidence count;
 * nothing is estimated in place of an unknown.
 */
import { Alert, Card } from '@adminlte/react';

import { UnavailableActions } from '@/components/unavailable-actions';
import type {
  DiagnosticCheckStatus,
  DiagnosticFinding,
  DiagnosticProbeResult,
  DiagnosticRun,
} from '@/lib/api-contracts-diagnostic';
import {
  checkLabel,
  confidenceLabel,
  faultDomainLabel,
  noFaultNarrative,
  runCheckSummary,
} from '@/lib/diagnostic-view';
import { LOCATION_LABELS } from '@/lib/diagnostic-session-view';
import { formatUtcTimestamp } from '@/lib/format-time';

const STATUS_PILL: Record<DiagnosticCheckStatus, string> = {
  pass: 'text-bg-success',
  fail: 'text-bg-danger',
  unknown: 'text-bg-secondary',
};

function StatusPill({ status }: { status: DiagnosticCheckStatus }) {
  return (
    <span className={`badge ${STATUS_PILL[status]}`}>
      {status === 'unknown' ? 'UNKNOWN' : status.toUpperCase()}
    </span>
  );
}

function latencyText(milliseconds: number | null): string {
  if (milliseconds === null) return 'no timing';
  return `${Math.round(milliseconds)} ms`;
}

export function CheckRow({ index, check }: { index: number; check: DiagnosticProbeResult }) {
  return (
    <li className="list-group-item">
      <details>
        <summary className="d-flex flex-wrap align-items-center gap-2 list-group-item-action">
          <span
            className="diagnostic-check-index fw-semibold text-body-secondary"
            aria-hidden="true"
          >
            {index}.
          </span>
          <span className="fw-semibold">{checkLabel(check.kind)}</span>
          <span className="small text-body-secondary">
            {latencyText(check.latency_ms)}
            {check.port !== null ? ` · port ${check.port}` : ''}
          </span>
          <span className="ms-auto">
            <StatusPill status={check.status} />
          </span>
        </summary>
        <div className="px-3 py-2 small">
          {check.detail !== null ? (
            <p className="mb-1">{check.detail}</p>
          ) : (
            <p className="mb-1 text-body-secondary">No detail was reported for this check.</p>
          )}
          <dl className="row mb-0 diagnostic-check-meta">
            <div className="col-auto">
              <dt>Check</dt>
              <dd>
                <code>{check.id}</code>
              </dd>
            </div>
            <div className="col-auto">
              <dt>Vantage</dt>
              <dd>{check.vantage ?? 'not stated'}</dd>
            </div>
            <div className="col-auto">
              <dt>Location</dt>
              <dd>{check.location !== null ? LOCATION_LABELS[check.location] : 'not stated'}</dd>
            </div>
            <div className="col-auto">
              <dt>Observed at</dt>
              <dd>{check.observed_at !== null ? formatUtcTimestamp(check.observed_at) : 'not stated'}</dd>
            </div>
          </dl>
        </div>
      </details>
    </li>
  );
}

export function FindingList({ heading, items, tone }: { heading: string; items: readonly DiagnosticFinding[]; tone?: string }) {
  if (items.length === 0) return null;
  return (
    <section aria-label={heading}>
      <h3 className="h6 fw-semibold text-body-secondary border-bottom pb-1">{heading}</h3>
      <ul className="list-unstyled mb-0">
        {items.map((finding, index) => (
          <li key={`${heading}-${index}`} className={tone ?? 'mb-1'}>
            <span className="me-1 text-body-secondary" aria-hidden="true">
              {index + 1}.
            </span>
            {finding.statement}
            {finding.evidence_ids.length > 0 ? (
              <span className="badge text-bg-light border ms-2" title="supporting evidence items">
                {finding.evidence_ids.length} {finding.evidence_ids.length === 1 ? 'evidence item' : 'evidence items'}
              </span>
            ) : null}
          </li>
        ))}
      </ul>
    </section>
  );
}

export function DiagnosticRunView({ run }: { run: DiagnosticRun }) {
  const summary = runCheckSummary(run);
  const domain = faultDomainLabel(run.probable_fault_domain);

  return (
    <>
      <div className="px-3 pt-3">
        <div className="d-flex flex-wrap align-items-center gap-2 mb-2">
          <span className="fw-semibold">Run {run.id.slice('diagnostic-'.length)}</span>
          {run.target !== '' ? <span className="badge text-bg-light border">{run.target}</span> : null}
          {run.vantage !== null ? (
            <span className="badge text-bg-light border">vantage: {run.vantage}</span>
          ) : null}
          <span className="ms-auto small text-body-secondary" data-testid="run-completed">
            Completed {formatUtcTimestamp(run.completed_at)}
          </span>
        </div>

        {run.symptom !== null ? (
          <blockquote className="border-start ps-3 mb-2 small text-body-secondary">
            Symptom: {run.symptom}
          </blockquote>
        ) : null}

        <div className="row g-2 mb-3" role="group" aria-label="check summary">
          <div className="col-auto">
            <div className="border rounded p-2 px-3 text-center">
              <div className="fs-5 fw-semibold">{summary.fail}</div>
              <div className="small text-danger text-uppercase">Failed</div>
            </div>
          </div>
          <div className="col-auto">
            <div className="border rounded p-2 px-3 text-center">
              <div className="fs-5 fw-semibold">{summary.pass}</div>
              <div className="small text-success text-uppercase">Passed</div>
            </div>
          </div>
          <div className="col-auto">
            <div className="border rounded p-2 px-3 text-center">
              <div className="fs-5 fw-semibold">{summary.unknown}</div>
              <div className="small text-body-secondary text-uppercase">Unknown</div>
            </div>
          </div>
        </div>
      </div>

      {run.checks.length > 0 ? (
        <Card
          className="operational-card mb-3"
          title="Automated check results"
          icon="bi bi-list-ul"
          variant="outline"
          theme="primary"
          bodyClass="p-0"
        >
          <ol className="diagnostic-checks list-group list-group-flush mb-0" role="list">
            {run.checks.map((check, index) => (
              <CheckRow key={check.id} index={index + 1} check={check} />
            ))}
          </ol>
        </Card>
      ) : null}

      <Card
        className="operational-card"
        title="Probable cause"
        icon="bi bi-bandaid"
        variant="outline"
        theme="primary"
        bodyClass="p-3"
      >
        {domain === null ? (
          <div className="mb-0">
            <div className="d-flex flex-wrap align-items-center gap-2 mb-1">
              <span className="fw-semibold">No probable cause was identified</span>
              <span className="badge text-bg-secondary">{confidenceLabel(run.confidence)}</span>
            </div>
            <p className="small text-body-secondary mb-0">{noFaultNarrative(summary)}</p>
          </div>
        ) : (
          <>
            <div className="d-flex flex-wrap align-items-center gap-2 mb-2">
              <span className="fs-5 fw-semibold">{domain}</span>
              <span className="badge text-bg-warning">{confidenceLabel(run.confidence)}</span>
            </div>
            <FindingList heading="Evidence" items={run.facts} />
          </>
        )}
      </Card>

      {run.contradictions.length > 0 ? (
        <div className="mb-3">
          <Alert theme="danger" title="Contradictory evidence" icon="bi bi-exclamation-octagon">
            <FindingList heading="Contradictions" items={run.contradictions} />
          </Alert>
        </div>
      ) : null}
      {run.unknowns.length > 0 ? (
        <div className="mb-3">
          <Alert theme="warning" title="What could not be determined" icon="bi bi-question-circle">
            <FindingList heading="Unknowns" items={run.unknowns} />
          </Alert>
        </div>
      ) : null}
      {run.alternative_hypotheses.length > 0 ? (
        <div className="mb-3">
          <Alert theme="info" title="Alternative hypotheses" icon="bi bi-diagram-3">
            <FindingList heading="Alternatives" items={run.alternative_hypotheses} />
          </Alert>
        </div>
      ) : null}

      <Card
        className="operational-card mt-3"
        title="Recommended next checks"
        icon="bi bi-list-check"
        variant="outline"
        theme="secondary"
        bodyClass="p-3"
      >
        <FindingList heading="Next checks" items={run.recommended_next_checks} />
        {run.recommended_next_checks.length === 0 ? (
          <p className="small text-body-secondary mb-0">
            No further checks are recommended from one run.
          </p>
        ) : null}
      </Card>

      <Card
        className="operational-card mt-3"
        title="Follow-up actions"
        icon="bi bi-shield-lock"
        variant="outline"
        theme="secondary"
        bodyClass="p-3"
      >
        <p className="small text-body-secondary mb-2">
          Actions on the diagnostic target are not part of a read-only diagnostic run. Write actions
          require approval and are not wired in this slice.
        </p>
        <UnavailableActions id="diagnostic-read-actions" label="Read-only actions" actions={['View logs']} />
        <div className="mt-3">
          <UnavailableActions
            id="diagnostic-approval-actions"
            label="Approval-gated actions"
            actions={['Prepare restart']}
          />
        </div>
      </Card>
    </>
  );
}