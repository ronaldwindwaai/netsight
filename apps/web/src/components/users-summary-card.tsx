/**
 * Aggregate counts of people by presence basis: the only users surface for a role without per-user
 * access (Management). Counts only: no names, no identifiers, no rows, no links. A non-ok state shows
 * no counts (a source that is not connected is not "zero people").
 */
import { DataFailure } from '@/components/data-state';
import { SourceNotices } from '@/components/identity-parts';
import { StateSurface } from '@/components/state-surface';
import type { UsersAggregateResponse } from '@/lib/api-contracts-identity';
import type { FetchState } from '@/lib/api-response';
import { formatUtcTimestamp } from '@/lib/format-time';
import { stateSurface } from '@/lib/identity-view';

function Count({ label, value, hint }: { label: string; value: number | null; hint: string }) {
  return (
    <div className="col-6 col-md-4 col-xl">
      <dt className="fw-normal text-body-secondary">{label}</dt>
      <dd className="fs-3 mb-0">{value === null ? 'Not reported' : value}</dd>
      <dd className="small text-body-secondary mb-0">{hint}</dd>
    </div>
  );
}

export function UsersSummaryCard({ state }: { state: FetchState<UsersAggregateResponse> }) {
  const surface = stateSurface(state);
  if (state.kind !== 'ok') {
    if (surface === 'permission') {
      return (
        <StateSurface
          icon="bi bi-shield-lock"
          title="User counts are not available to your role"
          detail="Reading the aggregate needs the users:read-summary permission, which your role does not hold. Access is enforced by the Netsight API."
        />
      );
    }
    return <DataFailure state={state} />;
  }
  const { data } = state;
  if (surface === 'not-connected') {
    return (
      <StateSurface
        icon="bi bi-plug"
        title="Identity sources not connected"
        detail="No counts are shown because no evidence source is configured. This is not the same as having no people."
      />
    );
  }
  if (surface === 'unknown') {
    return (
      <StateSurface
        icon="bi bi-question-circle"
        title="Identity state unknown"
        detail="The evidence sources are configured but could not be read. Nothing is estimated in their place."
      />
    );
  }
  return (
    <section aria-label="User counts" className="card mb-3">
      <div className="card-header">
        <h2 className="h6 mb-0">Users and identity (summary)</h2>
      </div>
      <div className="card-body">
        <SourceNotices sources={data.sources} />
        <dl className="row mb-2">
          <Count label="People known" value={data.people_total} hint="named by evidence" />
          <Count label="Observed session" value={data.with_observed_session} hint="a direct source reports one" />
          <Count label="Inferred session only" value={data.with_inferred_session} hint="reasoned, not observed" />
          <Count label="No session evidence" value={data.without_session_evidence} hint="not the same as offline" />
          <Count label="VPN sessions" value={data.vpn_sessions} hint="active in the window" />
        </dl>
        <p className="small text-body-secondary mb-0">
          Counts only: no names or identifiers are shown to your role. As of{' '}
          {formatUtcTimestamp(data.as_of)}.
        </p>
      </div>
    </section>
  );
}
