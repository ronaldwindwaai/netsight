/**
 * A stored diagnostic session (S7 Step 4e): header, state banners, probable cause, per-location
 * results, path, recent changes and the checks. Read-only by construction: it renders no button,
 * form or input, only data. Untrusted values (target, symptom, probe details, names, titles) are
 * React text nodes, never injected HTML. A stored session is a snapshot and says so when it is old.
 */
import { AppCard } from '@/components/app-card';

import { ProbableCausePanel } from '@/components/diagnostic-cause-panel';
import { RecentChangesPanel } from '@/components/diagnostic-changes-panel';
import { LocationResults } from '@/components/diagnostic-locations';
import { PathView } from '@/components/diagnostic-path-view';
import { CheckRow } from '@/components/diagnostic-run-view';
import { StateSurface } from '@/components/state-surface';
import type { DiagnosticSession } from '@/lib/api-contracts-diagnostic-session';
import { partialSections, sessionAge } from '@/lib/diagnostic-session-view';
import { runCheckSummary } from '@/lib/diagnostic-view';
import { formatUtcTimestamp } from '@/lib/format-time';

function Checks({ session }: { session: DiagnosticSession }) {
  const { run } = session;
  const summary = runCheckSummary(run);
  return (
    <section aria-label="Checks" className="mb-3">
      <AppCard
        className="operational-card"
        title="Automated check results"
        icon="bi bi-list-ul"
        variant="outline"
        theme="primary"
        bodyClass="p-0"
      >
        {run.checks.length === 0 ? (
          <StateSurface
            icon="bi bi-inbox"
            title="No checks were recorded"
            detail="This session holds no probe results, so there is nothing to conclude from it."
          />
        ) : (
          <>
            <p className="small text-body-secondary px-3 pt-3 mb-0">
              {summary.fail} failed, {summary.pass} passed, {summary.unknown} could not be answered.
            </p>
            <ol className="diagnostic-checks list-group list-group-flush mb-0" role="list">
              {run.checks.map((check, index) => (
                <CheckRow key={check.id} index={index + 1} check={check} />
              ))}
            </ol>
          </>
        )}
      </AppCard>
    </section>
  );
}

function Banners({ session, nowMs }: { session: DiagnosticSession; nowMs: number }) {
  const age = sessionAge(session.run.completed_at, nowMs);
  const partial = partialSections(session);
  return (
    <>
      {age.stale ? (
        <div className="alert alert-secondary" role="status" aria-label="Snapshot age">
          <i className="bi bi-clock-history me-2" aria-hidden="true" />
          This is a stored snapshot completed {age.minutes} minutes ago. The checks are not live and
          do not describe the current state of the target.
        </div>
      ) : null}
      {partial.length > 0 ? (
        <div className="alert alert-warning" role="status" aria-label="Partial session">
          <i className="bi bi-exclamation-triangle me-2" aria-hidden="true" />
          Some parts of this session are not fully available: {partial.join('; ')}. Missing
          information is unknown and is not assumed healthy.
        </div>
      ) : null}
    </>
  );
}

export function DiagnosticSessionBody({
  session,
  nowMs,
}: {
  session: DiagnosticSession;
  nowMs: number;
}) {
  const { run } = session;
  return (
    <>
      <div className="mb-3">
        <div className="d-flex flex-wrap align-items-center gap-2 mb-1">
          <span className="fw-semibold">Session {run.id.slice('diagnostic-'.length)}</span>
          <span className="badge text-bg-light border">{run.target}</span>
          <span className="ms-auto small text-body-secondary">
            Completed {formatUtcTimestamp(run.completed_at)}
          </span>
        </div>
        {run.symptom !== null ? (
          <blockquote className="border-start ps-3 mb-0 small text-body-secondary">
            Symptom: {run.symptom}
          </blockquote>
        ) : null}
      </div>
      <Banners session={session} nowMs={nowMs} />
      <ProbableCausePanel cause={session.probable_cause} run={run} />
      <LocationResults
        rows={session.locations}
        unlocatedChecks={run.checks.filter((check) => check.location === null).length}
      />
      <PathView path={session.path} />
      <RecentChangesPanel changes={session.recent_changes} />
      <Checks session={session} />
    </>
  );
}
