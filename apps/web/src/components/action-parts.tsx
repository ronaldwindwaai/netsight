import { Badge } from '@adminlte/react';

import { riskPresentation, statePresentation } from '@/lib/actions-view';
import type { ActionCheck, RequestState, Risk } from '@/lib/api-contracts-actions';

/** A lifecycle state as a word and an icon (never colour alone), with its meaning on hover. */
export function ActionStateBadge({ state, mode }: { state: RequestState; mode?: 'dry-run' | 'live' }) {
  const view = statePresentation(state, mode);
  return (
    <span title={view.explanation}>
      <Badge theme={view.theme} pill>
        <i className={`bi ${view.icon} me-1`} aria-hidden="true" />
        {view.label}
      </Badge>
    </span>
  );
}

export function RiskBadge({ risk }: { risk: Risk }) {
  const view = riskPresentation(risk);
  return (
    <span title={view.explanation}>
      <Badge theme={view.theme} pill>
        <i className={`bi ${view.icon} me-1`} aria-hidden="true" />
        {view.label}
      </Badge>
    </span>
  );
}

/** Said wherever a request or a result is shown: no executor in this release touches a device. */
export function DryRunNotice({ dryRunOnly }: { dryRunOnly: boolean }) {
  if (!dryRunOnly) return null;
  return (
    <div className="alert alert-info py-2" role="note">
      <i className="bi bi-info-circle me-1" aria-hidden="true" />
      <strong>Dry run only.</strong> Running a request records what would happen. It does not contact or
      change any device, switch, firewall or network system, and nothing here can.
    </div>
  );
}

const CHECK_ICON = { pass: 'bi-check-circle', fail: 'bi-x-circle', unknown: 'bi-question-circle' } as const;
const CHECK_WORD = { pass: 'Passed', fail: 'Failed', unknown: 'Not known' } as const;

/** Checks as words, with the static detail code; "Not known" is never rendered as a pass. */
export function ChecksList({ checks, empty }: { checks: ActionCheck[]; empty: string }) {
  if (checks.length === 0) return <p className="small text-body-secondary mb-0">{empty}</p>;
  return (
    <ul className="list-unstyled mb-0">
      {checks.map((check) => (
        <li key={check.name} className="small">
          <i className={`bi ${CHECK_ICON[check.state]} me-1`} aria-hidden="true" />
          <strong>{check.name}</strong>: {CHECK_WORD[check.state]}
          <span className="text-body-secondary"> ({check.detail})</span>
        </li>
      ))}
    </ul>
  );
}
