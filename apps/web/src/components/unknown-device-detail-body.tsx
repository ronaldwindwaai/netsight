/**
 * One unknown-device finding for every outcome of the read. The evidence chain shows only the links
 * actually observed; every other hop says, in words, why it is not known. The NetBox comparison lists
 * each check. A quarantine is shown as a proposal that was not executed. The timeline is append-only.
 * All endpoint values, labels, comments and actor identities are untrusted text rendered as text.
 * The workflow actions are a slot: the page passes the client panel when the viewer may act.
 */
import { Badge, Card } from '@adminlte/react';
import type { ComponentProps } from 'react';

import { DataFailure } from '@/components/data-state';
import { StateSurface, StoreStateSurface } from '@/components/state-surface';
import { FindingStateBadge, ProposedBadge, SeverityBadge } from '@/components/unknown-device-parts';
import type {
  UnknownDeviceEvent,
  UnknownDeviceFinding,
  UnknownDeviceDetail,
  UnknownDeviceLinkSlot,
  UnknownDeviceTimeline,
} from '@/lib/api-contracts-unknown-devices';
import type { FetchState } from '@/lib/api-response';
import { formatUtcTimestamp } from '@/lib/format-time';
import {
  checkPresentation,
  slotLabel,
  slotStatement,
  statePresentation,
} from '@/lib/unknown-device-view';

const NOT_REPORTED = 'Not reported';

type Theme = NonNullable<ComponentProps<typeof Badge>['theme']>;

const BASIS_BADGE: Record<UnknownDeviceLinkSlot['basis'], { label: string; theme: Theme; icon: string }> = {
  observed: { label: 'Observed', theme: 'success', icon: 'bi-eye-fill' },
  inferred: { label: 'Inferred', theme: 'warning', icon: 'bi-lightbulb-fill' },
  unknown: { label: 'Unknown', theme: 'secondary', icon: 'bi-question-circle-fill' },
};

const SEVERITY_BASIS_TEXT: Record<UnknownDeviceFinding['severity_basis'], string> = {
  'policy-rule': 'Set by a rule in the operator severity policy.',
  'policy-default': 'Set by the default of the operator severity policy.',
  'no-policy': 'No severity policy is configured, so no severity is claimed.',
};

function ChainHop({ slot }: { slot: UnknownDeviceLinkSlot }) {
  const basis = BASIS_BADGE[slot.basis];
  return (
    <li className="list-group-item">
      <div className="d-flex flex-wrap align-items-center gap-2">
        <strong>{slotLabel(slot.slot)}</strong>
        <Badge theme={basis.theme} pill>
          <i className={`bi ${basis.icon} me-1`} aria-hidden="true" />
          {basis.label}
        </Badge>
        {slot.basis !== 'unknown' && slot.confidence !== null ? (
          <span className="small text-body-secondary">confidence {slot.confidence}</span>
        ) : null}
      </div>
      <div className={slot.basis === 'unknown' ? 'text-body-secondary' : 'font-monospace text-break'}>
        {slotStatement(slot)}
      </div>
      {slot.basis !== 'unknown' && slot.value !== null && slot.label !== null ? (
        <div className="small text-body-secondary font-monospace text-break">{slot.value}</div>
      ) : null}
      {slot.evidence.length > 0 ? (
        <ul className="small text-body-secondary mb-0 mt-1">
          {slot.evidence.map((ref) => (
            <li key={ref.id}>
              <span className="text-break">{ref.source}</span> · <span className="text-break">{ref.kind}</span> ·
              observed {formatUtcTimestamp(ref.observed_at)}
            </li>
          ))}
        </ul>
      ) : null}
    </li>
  );
}

function EventLine({ event }: { event: UnknownDeviceEvent }) {
  const heading =
    event.kind === 'state-changed' && event.state_from !== null && event.state_to !== null
      ? `State changed from ${statePresentation(event.state_from).label} to ${statePresentation(event.state_to).label}`
      : event.kind === 'state-changed'
        ? 'State changed'
        : event.kind === 'assignee-changed'
          ? event.subject_id === null
            ? 'Unassigned'
            : 'Assigned'
          : event.kind === 'comment'
            ? 'Comment'
            : event.kind === 'action-proposed'
              ? 'Quarantine proposed (not executed)'
              : event.kind === 'evidence-updated'
                ? 'Evidence updated'
                : event.kind === 'suppressed-sighting'
                  ? 'Seen again while dismissed (not reopened)'
                  : 'Detected';
  return (
    <li className="list-group-item">
      <div className="d-flex flex-wrap justify-content-between gap-2">
        <strong>{heading}</strong>
        <span className="small text-body-secondary">{formatUtcTimestamp(event.occurred_at)}</span>
      </div>
      <div className="small text-body-secondary">
        By <span className="text-break">{event.actor_id}</span>
        {event.subject_id !== null ? (
          <>
            {' '}
            · to <span className="text-break">{event.subject_id}</span>
          </>
        ) : null}
      </div>
      {event.reason !== null ? <div className="text-break" style={{ whiteSpace: 'pre-wrap' }}>{event.reason}</div> : null}
      {event.message !== null ? <div className="text-break" style={{ whiteSpace: 'pre-wrap' }}>{event.message}</div> : null}
    </li>
  );
}

export function FindingTimeline({ state }: { state: FetchState<UnknownDeviceTimeline> | null }) {
  const body = (() => {
    if (state === null) return <p className="small text-body-secondary mb-0">Your role does not read the timeline.</p>;
    if (state.kind !== 'ok') {
      return state.kind === 'forbidden' ? (
        <p className="small text-body-secondary mb-0">The timeline is not available to your role.</p>
      ) : (
        <DataFailure state={state} />
      );
    }
    if (state.data.state !== 'ok') {
      return (
        <StoreStateSurface state={state.data.state === 'unknown' ? 'unknown' : 'not-connected'} noun="events" store="Finding store" />
      );
    }
    if (state.data.events.length === 0) return <p className="small text-body-secondary mb-0">No events yet.</p>;
    return (
      <>
        <ol className="list-group list-group-flush">
          {state.data.events.map((event) => (
            <EventLine key={event.id} event={event} />
          ))}
        </ol>
        {state.data.next_after_seq !== null ? (
          <p className="small text-body-secondary px-3 py-2 mb-0">
            Earlier events are shown; more exist than fit on this page.
          </p>
        ) : null}
      </>
    );
  })();
  return (
    <Card title="Timeline" icon="bi bi-clock-history" variant="outline" theme="secondary" bodyClass="p-0">
      {body}
    </Card>
  );
}

function FindingBody({
  item,
  actions,
  timeline,
}: {
  item: UnknownDeviceFinding;
  actions: React.ReactNode;
  timeline: FetchState<UnknownDeviceTimeline> | null;
}) {
  return (
    <>
      <Card title="Endpoint" icon="bi bi-hdd-network" variant="outline" theme="primary">
        <div className="d-flex flex-wrap align-items-center gap-2 mb-2">
          <FindingStateBadge state={item.state} />
          <SeverityBadge severity={item.severity} />
          {item.proposed_action !== null ? <ProposedBadge /> : null}
        </div>
        <dl className="row small mb-2">
          <dt className="col-sm-3">IP address</dt>
          <dd className="col-sm-9 font-monospace text-break">{item.endpoint.ip ?? NOT_REPORTED}</dd>
          <dt className="col-sm-3">MAC address</dt>
          <dd className="col-sm-9 font-monospace text-break">{item.endpoint.mac ?? NOT_REPORTED}</dd>
          <dt className="col-sm-3">Hostname</dt>
          <dd className="col-sm-9 text-break">{item.endpoint.hostname ?? NOT_REPORTED}</dd>
          <dt className="col-sm-3">Assignee</dt>
          <dd className="col-sm-9 text-break">{item.assignee_id ?? 'Unassigned'}</dd>
          <dt className="col-sm-3">First / last seen</dt>
          <dd className="col-sm-9">
            {formatUtcTimestamp(item.first_seen_at)} / {formatUtcTimestamp(item.last_seen_at)} · seen {item.seen_count}{' '}
            {item.seen_count === 1 ? 'time' : 'times'}
          </dd>
        </dl>
        <p className="small text-body-secondary mb-0">{SEVERITY_BASIS_TEXT[item.severity_basis]}</p>
      </Card>

      <div className="row g-3">
        <div className="col-12 col-lg-7">
          <Card title="Evidence chain" icon="bi bi-diagram-3" variant="outline" theme="primary" bodyClass="p-0">
            <ol className="list-group list-group-flush" aria-label="Evidence chain from IP address to VLAN">
              {item.chain.map((slot) => (
                <ChainHop key={slot.slot} slot={slot} />
              ))}
            </ol>
            <p className="small text-body-secondary px-3 py-2 mb-0">
              Only links a source actually observed are shown as values. A hop no connected source can see
              is Unknown, never guessed.
            </p>
          </Card>
        </div>
        <div className="col-12 col-lg-5">
          <Card title="Comparison with NetBox" icon="bi bi-arrow-left-right" variant="outline" theme="secondary">
            <ul className="list-unstyled mb-1">
              {item.comparison.checks.map((check) => {
                const view = checkPresentation(check);
                return (
                  <li key={check.field} className="mb-2">
                    <strong>{view.name}</strong> <Badge theme={check.result === 'match' ? 'success' : 'secondary'} pill>{view.label}</Badge>
                    <div className="small text-body-secondary text-break">{view.text}</div>
                  </li>
                );
              })}
            </ul>
            {item.comparison.reason === 'name-matches-mac-does-not' ? (
              <p className="small mb-1">
                The name matched a NetBox device but the MAC address did not. A name alone never clears an
                endpoint.
              </p>
            ) : null}
            <p className="small text-body-secondary mb-0">
              Checked {formatUtcTimestamp(item.comparison.checked_at)}. NetBox is read, never written.
            </p>
          </Card>
        </div>
      </div>

      {item.proposed_action !== null ? (
        <Card title="Proposed action" icon="bi bi-shield-exclamation" variant="outline" theme="warning">
          <p className="mb-1">
            <strong>Isolate this endpoint (quarantine)</strong> <ProposedBadge />
          </p>
          <p className="small mb-1 text-break">{item.proposed_action.rationale}</p>
          <p className="small text-body-secondary mb-0">
            This is a recommendation only. Nothing has been isolated and nothing here can isolate it: any
            execution is owned by the action engine, which needs an approver, and is not built yet.
          </p>
        </Card>
      ) : null}

      <Card title="Workflow" icon="bi bi-list-check" variant="outline" theme="primary">
        {actions}
      </Card>
      <FindingTimeline state={timeline} />
    </>
  );
}

export function UnknownDeviceDetailBody({
  state,
  actions,
  timeline,
}: {
  state: FetchState<UnknownDeviceDetail>;
  actions: React.ReactNode;
  timeline: FetchState<UnknownDeviceTimeline> | null;
}) {
  if (state.kind !== 'ok') {
    if (state.kind === 'forbidden') {
      return (
        <StateSurface
          icon="bi bi-shield-lock"
          title="Finding detail is not available to your role"
          detail="Reading one finding needs the unknown-devices:read permission, which your role does not hold."
        />
      );
    }
    if (state.kind === 'not_found') {
      return (
        <StateSurface
          icon="bi bi-question-circle"
          title="Finding not found"
          detail="No finding with this identifier exists."
        />
      );
    }
    return <DataFailure state={state} />;
  }
  const { data } = state;
  if (data.state !== 'ok' || data.item === null) {
    return <StoreStateSurface state={data.state === 'unknown' ? 'unknown' : 'not-connected'} noun="the finding" store="Finding store" />;
  }
  return <FindingBody item={data.item} actions={actions} timeline={timeline} />;
}
