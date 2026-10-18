/**
 * One action request with every outcome of the read, its approvals, checks, result and append-only
 * history. Every string from a person (the reason, a history note) or from the estate (a target, a
 * parameter) is untrusted and rendered as text. A history whose hash chain does not verify is said so.
 */
import Link from 'next/link';
import { Card } from '@adminlte/react';

import { ActionStateBadge, ChecksList, DryRunNotice, RiskBadge } from '@/components/action-parts';
import { DataFailure } from '@/components/data-state';
import { StateSurface } from '@/components/state-surface';
import { executionSummary } from '@/lib/actions-view';
import type { ActionDetail, ActionStatus } from '@/lib/api-contracts-actions';
import type { FetchState } from '@/lib/api-response';
import { formatUtcTimestamp } from '@/lib/format-time';

function Facts({ detail }: { detail: ActionDetail }) {
  const r = detail.request;
  return (
    <dl className="row small mb-0">
      <dt className="col-sm-3">Action</dt>
      <dd className="col-sm-9">{r.action_type}</dd>
      <dt className="col-sm-3">Target</dt>
      <dd className="col-sm-9 font-monospace text-break">
        {r.source !== null ? <Link href={`/unknown-devices/${r.source.id}`}>{r.target_id}</Link> : r.target_id}
        {r.source !== null ? (
          <span className="d-block text-body-secondary">
            Proposed from an unknown-device finding at evidence version {r.source.evidence_version}.
          </span>
        ) : null}
      </dd>
      <dt className="col-sm-3">Parameters</dt>
      <dd className="col-sm-9">
        {Object.keys(r.params).length === 0 ? (
          'None'
        ) : (
          <ul className="list-unstyled mb-0">
            {Object.entries(r.params).map(([name, value]) => (
              <li key={name}>
                <span className="font-monospace">{name}</span> = <span className="font-monospace text-break">{String(value)}</span>
              </li>
            ))}
          </ul>
        )}
      </dd>
      <dt className="col-sm-3">Reason</dt>
      <dd className="col-sm-9 text-break">{r.reason}</dd>
      <dt className="col-sm-3">Requested by</dt>
      <dd className="col-sm-9 text-break">
        {r.requester.id} ({r.requester.kind}) · {formatUtcTimestamp(r.created_at)}
      </dd>
      <dt className="col-sm-3">Approvals</dt>
      <dd className="col-sm-9">
        {r.approvals.length} of {r.approvals_required} required
        {r.approvals.map((a) => (
          <span key={a.approver_id} className="d-block text-break">
            {a.approver_id} · {formatUtcTimestamp(a.approved_at)}
          </span>
        ))}
      </dd>
      <dt className="col-sm-3">Deadlines</dt>
      <dd className="col-sm-9">
        Approve by {formatUtcTimestamp(r.approve_by)}
        {r.execute_by !== null ? ` · run by ${formatUtcTimestamp(r.execute_by)}` : ''}
      </dd>
      <dt className="col-sm-3">Version</dt>
      <dd className="col-sm-9">
        {r.version} · digest <code className="text-break">{r.digest}</code>
        <span className="d-block text-body-secondary">
          An approval is of exactly this content and version; if either changes, the decision is refused.
        </span>
      </dd>
    </dl>
  );
}

function Result({ detail }: { detail: ActionDetail }) {
  const r = detail.request;
  const summary = executionSummary(r);
  const run = r.execution;
  return (
    <>
      <p className="fw-semibold mb-1">{summary.headline}</p>
      <p className="small mb-2">{summary.detail}</p>
      {run !== null ? (
        <>
          <dl className="row small mb-2">
            <dt className="col-sm-3">Executor</dt>
            <dd className="col-sm-9">
              {run.executor} ({run.mode})
            </dd>
            <dt className="col-sm-3">Effect</dt>
            <dd className="col-sm-9">
              {run.effect === 'none' ? 'None: nothing was changed' : run.effect === 'applied' ? 'Applied' : 'Not known'}
            </dd>
            <dt className="col-sm-3">Verification</dt>
            <dd className="col-sm-9">
              {run.verification.state} <span className="text-body-secondary">({run.verification.detail})</span>
            </dd>
            {run.failure !== null ? (
              <>
                <dt className="col-sm-3">Failure</dt>
                <dd className="col-sm-9">{run.failure}</dd>
              </>
            ) : null}
            {run.rollback !== null ? (
              <>
                <dt className="col-sm-3">Rollback</dt>
                <dd className="col-sm-9">{run.rollback.state}</dd>
              </>
            ) : null}
          </dl>
          <p className="small fw-semibold mb-1">{run.mode === 'dry-run' ? 'What would happen' : 'Planned steps'}</p>
          <ol className="small mb-0">
            {run.planned_steps.map((step) => (
              <li key={step} className="text-break">
                {step}
              </li>
            ))}
          </ol>
        </>
      ) : null}
    </>
  );
}

function History({ detail }: { detail: ActionDetail }) {
  return (
    <>
      {detail.chain_intact ? (
        <p className="small text-body-secondary">
          <i className="bi bi-link-45deg me-1" aria-hidden="true" />
          The history is append-only and its hash chain verifies.
        </p>
      ) : (
        <div className="alert alert-danger py-2" role="alert">
          <i className="bi bi-exclamation-octagon me-1" aria-hidden="true" />
          <strong>The history hash chain does not verify.</strong> Entries may have been altered or lost. Do not rely
          on this record; report it.
        </div>
      )}
      <ol className="list-unstyled small mb-0">
        {detail.history.map((event) => (
          <li key={event.seq} className="mb-1">
            <span className="text-body-secondary">{formatUtcTimestamp(event.at)}</span> · <strong>{event.type}</strong>{' '}
            <span className="text-body-secondary">({event.code})</span> · {event.actor_id ?? 'the system'}
            {event.note !== null ? <span className="d-block text-break ps-3">“{event.note}”</span> : null}
          </li>
        ))}
      </ol>
    </>
  );
}

export function ActionDetailBody({
  state,
  status,
  panel,
}: {
  state: FetchState<ActionDetail>;
  status: ActionStatus | null;
  panel: React.ReactNode;
}) {
  if (state.kind !== 'ok') {
    if (state.status === 503 && state.code === 'ACTIONS_NOT_ENABLED') {
      return (
        <StateSurface
          icon="bi bi-plug"
          title="The action engine is not enabled"
          detail="Controlled actions are off on this deployment, so this request cannot be shown."
        />
      );
    }
    return <DataFailure state={state} />;
  }
  const detail = state.data;
  const r = detail.request;
  return (
    <>
      <DryRunNotice dryRunOnly={status?.dry_run_only ?? true} />
      <div className="d-flex flex-wrap gap-2 align-items-center mb-3">
        <ActionStateBadge state={r.state} mode={r.execution?.mode} />
        <RiskBadge risk={r.risk} />
        <span className="small text-body-secondary">as of {formatUtcTimestamp(detail.generated_at)}</span>
      </div>
      {panel !== null ? (
        <Card title="Decide" icon="bi bi-check2-square" variant="outline" theme="primary">
          {panel}
        </Card>
      ) : null}
      <Card title="Request" icon="bi bi-card-text" variant="outline" theme="secondary">
        <Facts detail={detail} />
      </Card>
      <Card title="Checks" icon="bi bi-list-check" variant="outline" theme="secondary">
        <p className="small fw-semibold mb-1">At proposal</p>
        <ChecksList checks={r.policy_checks} empty="No policy checks were recorded." />
        <p className="small fw-semibold mb-1 mt-3">Before the run</p>
        <ChecksList checks={r.pre_checks} empty="No pre-run checks yet: they run when the request is run." />
      </Card>
      <Card title="Result" icon="bi bi-clipboard-check" variant="outline" theme="secondary">
        <Result detail={detail} />
      </Card>
      <Card title="History" icon="bi bi-clock-history" variant="outline" theme="secondary">
        <History detail={detail} />
      </Card>
    </>
  );
}
