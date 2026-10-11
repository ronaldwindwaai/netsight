/**
 * One person for every outcome of the read: permission, unauthenticated, not found, error,
 * not-connected, unknown, and the profile with accounts, current sessions, assigned devices, traffic
 * and security. Only what a source provides is shown (no department, manager, MFA or behaviour
 * fields: none exist as data). Every correlation carries its basis, evidence and as-of time; names and
 * signatures are untrusted text rendered as text.
 */
import type { ReactNode } from 'react';

import { DataFailure } from '@/components/data-state';
import { BasisBadge, LinkList, SourceNotices } from '@/components/identity-parts';
import { SecurityPanel, TrafficPanel } from '@/components/user-activity-panels';
import { StateSurface } from '@/components/state-surface';
import type { IdentitySession, UserDetailResponse } from '@/lib/api-contracts-identity';
import type { FetchState } from '@/lib/api-response';
import { formatUtcTimestamp } from '@/lib/format-time';
import {
  confidenceText,
  entityText,
  sessionKindLabel,
  stateSurface,
  validityText,
} from '@/lib/identity-view';

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section aria-labelledby={id} className="card mb-3">
      <div className="card-header">
        <h2 className="h6 mb-0" id={id}>
          {title}
        </h2>
      </div>
      <div className="card-body">{children}</div>
    </section>
  );
}

function SessionCard({ session }: { session: IdentitySession }) {
  return (
    <div className="mb-3">
      <div className="d-flex flex-wrap align-items-center gap-2">
        <h3 className="h6 mb-0">{sessionKindLabel(session.kind)}</h3>
        <BasisBadge basis={session.basis} />
        <span className="small text-body-secondary">
          confidence {confidenceText(session.confidence)} · {validityText(session)}
        </span>
      </div>
      <LinkList label={`${sessionKindLabel(session.kind)} session links`} links={session.links} />
    </div>
  );
}

export function UserDetailBody({ state }: { state: FetchState<UserDetailResponse> }) {
  const surface = stateSurface(state);
  if (state.kind !== 'ok') {
    if (surface === 'permission') {
      return (
        <StateSurface
          icon="bi bi-shield-lock"
          title="This person is not available to your role"
          detail="Reading a person needs the users:read permission, which your role does not hold. Access is enforced by the Netsight API."
        />
      );
    }
    return <DataFailure state={state} />;
  }
  const { data } = state;
  if (surface === 'not-connected' || surface === 'unknown' || data.user === null) {
    const unknown = surface !== 'not-connected';
    return (
      <StateSurface
        icon={unknown ? 'bi bi-question-circle' : 'bi bi-plug'}
        title={unknown ? 'Identity state unknown' : 'Identity sources not connected'}
        detail={
          unknown
            ? 'The evidence sources could not be read. Nothing is estimated in their place.'
            : 'No person is shown because no evidence source is configured. This is not the same as having none.'
        }
      />
    );
  }
  const { user, traffic, security } = data;
  return (
    <>
      <div className="mb-3">
        <h1 className="h3 mb-1">
          {entityText({ type: 'person', id: user.id, label: user.display_name })}
        </h1>
        <p className="small text-body-secondary mb-0">
          Person <code>{user.id}</code> · evidence as of {formatUtcTimestamp(data.as_of)} (window{' '}
          {formatUtcTimestamp(data.window.from)} to {formatUtcTimestamp(data.window.to)}). Identity
          comes from evidence, never from an address alone.
        </p>
      </div>
      <SourceNotices sources={data.sources} />
      <Section id="accounts-heading" title="Accounts">
        {user.accounts.length === 0 ? (
          <p className="mb-0">No account is linked to this person in the evidence.</p>
        ) : (
          <LinkList label="Accounts" links={user.accounts} />
        )}
      </Section>
      <Section id="sessions-heading" title="Current sessions">
        {user.sessions.length === 0 ? (
          <p className="mb-0">
            No current session is evidenced. That is not the same as offline: it means no source
            reports one inside its validity window.
          </p>
        ) : (
          user.sessions.map((session, index) => (
            <SessionCard key={`${session.kind}:${index}`} session={session} />
          ))
        )}
      </Section>
      {user.assigned_devices.length > 0 ? (
        <Section id="assigned-heading" title="Assigned devices">
          <p className="small text-body-secondary">
            An assignment is a declaration in the asset register, not proof the person uses the
            device.
          </p>
          <LinkList label="Assigned devices" links={user.assigned_devices} />
        </Section>
      ) : null}
      {traffic !== null ? (
        <Section id="traffic-heading" title="Traffic">
          <TrafficPanel traffic={traffic} />
        </Section>
      ) : null}
      {security !== null ? (
        <Section id="security-heading" title="Security events">
          <SecurityPanel security={security} />
        </Section>
      ) : null}
    </>
  );
}
