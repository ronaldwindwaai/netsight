/**
 * The identity lookup: a plain GET form (no client state, no script) and the answer for every outcome
 * of the read. An IP address alone is never identity: the answer says who is behind the subject only
 * when evidence supports it, with the basis of every link, and otherwise says why not. A role that may
 * see the endpoint but not the person is told the person is withheld. The value a person typed is
 * shown as text (and in the input's value); it is never interpreted.
 */
import { AttributionPanel, LinkList, SourceNotices } from '@/components/identity-parts';
import { DataFailure } from '@/components/data-state';
import { StateSurface } from '@/components/state-surface';
import type { ResolveResponse } from '@/lib/api-contracts-identity';
import type { FetchState } from '@/lib/api-response';
import { formatUtcTimestamp } from '@/lib/format-time';
import { entityKindLabel, stateSurface, type Lookup } from '@/lib/identity-view';

const KIND_OPTIONS = [
  { value: 'ip', label: 'IP address' },
  { value: 'mac', label: 'MAC address' },
  { value: 'hostname', label: 'Hostname' },
] as const;

function LookupForm({ lookup }: { lookup: Lookup | null }) {
  const kind = lookup !== null && lookup.ok ? lookup.kind : 'ip';
  const value = lookup !== null && lookup.ok ? lookup.value : '';
  return (
    <form method="get" action="/users" aria-label="Look up an address" className="row g-2 align-items-end mb-3">
      <div className="col-sm-3">
        <label className="form-label" htmlFor="lookup-kind">
          Look up
        </label>
        <select className="form-select form-select-sm" id="lookup-kind" name="kind" defaultValue={kind}>
          {KIND_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </div>
      <div className="col-sm-6">
        <label className="form-label" htmlFor="lookup-value">
          Value
        </label>
        <input
          autoComplete="off"
          className="form-control form-control-sm"
          defaultValue={value}
          id="lookup-value"
          maxLength={128}
          name="value"
          spellCheck={false}
          type="text"
        />
      </div>
      <div className="col-sm-3">
        <button className="btn btn-primary btn-sm" type="submit">
          <i className="bi bi-search me-1" aria-hidden="true" />
          Look up
        </button>
      </div>
    </form>
  );
}

function Result({ state }: { state: FetchState<ResolveResponse> }) {
  const surface = stateSurface(state);
  if (state.kind !== 'ok') {
    if (surface === 'permission') {
      return (
        <StateSurface
          icon="bi bi-shield-lock"
          title="Identity lookup is not available to your role"
          detail="Looking up an address needs the users:read-limited (or users:read) permission, which your role does not hold. Access is enforced by the Netsight API."
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
        detail="No answer is shown because no evidence source is configured. This is not the same as the address being unknown."
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
    <section aria-label="Lookup result" aria-live="polite">
      <h2 className="h5">
        {entityKindLabel(data.subject.kind === 'ip' ? 'ip' : data.subject.kind === 'mac' ? 'mac' : 'hostname')}{' '}
        <span>{data.subject.value}</span>
      </h2>
      <p className="small text-body-secondary">
        Computed as of {formatUtcTimestamp(data.as_of)} from evidence between{' '}
        {formatUtcTimestamp(data.window.from)} and {formatUtcTimestamp(data.window.to)}.
      </p>
      <SourceNotices sources={data.sources} />
      {data.notes.includes('register-is-current-state') ? (
        <p className="small text-body-secondary" role="note">
          This answer is for an earlier time but uses the asset register, which records current
          state only: it may not reflect what was assigned at that time.
        </p>
      ) : null}
      <AttributionPanel attribution={data.attribution} />
      <h3 className="h6">Network endpoint</h3>
      {data.endpoint.length === 0 ? (
        <p>No network links were found for this subject in the window.</p>
      ) : (
        <LinkList label="Network endpoint" links={data.endpoint} />
      )}
    </section>
  );
}

export function ResolvePanel({
  lookup,
  state,
}: {
  lookup: Lookup | null;
  state: FetchState<ResolveResponse> | null;
}) {
  return (
    <div className="mb-4">
      <LookupForm lookup={lookup} />
      {lookup === null ? (
        <p className="small text-body-secondary">
          Enter an IP address, MAC address or hostname. An address alone never identifies a person:
          the answer shows the basis of every link, and says why when it cannot name anyone.
        </p>
      ) : !lookup.ok ? (
        lookup.reason === 'empty' ? (
          <p className="small text-body-secondary">Enter an IP address, MAC address or hostname.</p>
        ) : (
          <p className="text-danger" role="alert">
            That is not a valid IP address, MAC address or hostname.
          </p>
        )
      ) : state === null ? null : (
        <Result state={state} />
      )}
    </div>
  );
}
