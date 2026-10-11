import { Badge } from '@adminlte/react';

import type { FindingState, Severity } from '@/lib/api-contracts-unknown-devices';
import { severityPresentation, statePresentation } from '@/lib/unknown-device-view';

/** A lifecycle state as a word and an icon (never colour alone), with its meaning on hover. */
export function FindingStateBadge({ state }: { state: FindingState }) {
  const view = statePresentation(state);
  return (
    <span title={view.explanation}>
      <Badge theme={view.theme} pill>
        <i className={`bi ${view.icon} me-1`} aria-hidden="true" />
        {view.label}
      </Badge>
    </span>
  );
}

/** Severity is the operator policy; "Unknown severity" is shown as such and is not low. */
export function SeverityBadge({ severity }: { severity: Severity }) {
  const view = severityPresentation(severity);
  return (
    <span title={view.explanation}>
      <Badge theme={view.theme} pill>
        <i className={`bi ${view.icon} me-1`} aria-hidden="true" />
        {view.label}
      </Badge>
    </span>
  );
}

/** A quarantine is only ever a recommendation: this says so wherever it is mentioned. */
export function ProposedBadge() {
  return (
    <span title="A recommendation only. Nothing was isolated and nothing will be until the action engine and an approver act.">
      <Badge theme="secondary" pill>
        <i className="bi bi-hourglass-split me-1" aria-hidden="true" />
        Quarantine proposed, not executed
      </Badge>
    </span>
  );
}
