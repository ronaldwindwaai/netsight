import { AppCard } from '@/components/app-card';

import { DataFailure } from '@/components/data-state';
import { DryRunNotice } from '@/components/action-parts';
import { StateSurface } from '@/components/state-surface';
import type { ActionStatus } from '@/lib/api-contracts-actions';
import type { FetchState } from '@/lib/api-response';
import { formatUtcTimestamp } from '@/lib/format-time';

const EXECUTOR_WORD = { ok: 'Ready', disabled: 'Disabled', 'not-connected': 'Not connected' } as const;

/**
 * What the action engine is: enabled or not, dry-run only or not, the kill switch, the executors and
 * whether requests survive a restart. "Not connected" is never an empty success.
 */
export function ActionsStatusCard({ state }: { state: FetchState<ActionStatus> }) {
  if (state.kind !== 'ok') return <DataFailure state={state} />;
  const status = state.data;
  if (status.state === 'not-connected') {
    return (
      <StateSurface
        icon="bi bi-plug"
        title="The action engine is not enabled"
        detail="Controlled actions are off on this deployment: nothing is stored, approved or run. This is not the same as having no requests."
      />
    );
  }
  const kill = status.kill_switch;
  return (
    <>
      <DryRunNotice dryRunOnly={status.dry_run_only} />
      {kill.engaged ? (
        <div className="alert alert-danger py-2" role="alert">
          <i className="bi bi-sign-stop me-1" aria-hidden="true" />
          <strong>Kill switch engaged</strong>
          {kill.source === 'environment' ? ' by the environment (it cannot be released here)' : ' by an administrator'}
          {kill.since !== null ? ` since ${formatUtcTimestamp(kill.since)}` : ''}. No request can be
          proposed, approved or run; you can still read, reject and cancel.
        </div>
      ) : null}
      <AppCard title="Engine" icon="bi bi-shield-check" variant="outline" theme="secondary">
        <dl className="row small mb-0">
          <dt className="col-sm-3">Kill switch</dt>
          <dd className="col-sm-9">{kill.engaged ? 'Engaged' : 'Not engaged'}</dd>
          <dt className="col-sm-3">Executors</dt>
          <dd className="col-sm-9">
            {status.executors.map((executor) => (
              <span key={executor.id} className="d-block">
                {executor.id} ({executor.mode}): {EXECUTOR_WORD[executor.state]}
              </span>
            ))}
          </dd>
          <dt className="col-sm-3">Storage</dt>
          <dd className="col-sm-9">
            Held in memory: requests and their history are lost when the service restarts and are not shared
            between workers.
          </dd>
          <dt className="col-sm-3">Action types</dt>
          <dd className="col-sm-9">
            {status.definitions.map((d) => `${d.title} (risk ${d.risk}, ${d.approvals_required} approval${d.approvals_required === 1 ? '' : 's'})`).join('; ') || 'None'}
          </dd>
        </dl>
      </AppCard>
    </>
  );
}
