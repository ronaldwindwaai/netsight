import { CopilotPanel } from '@/components/copilot-panel';
import { CopilotStatusCard } from '@/components/copilot-status-card';
import { DataFailure } from '@/components/data-state';
import { StateSurface } from '@/components/state-surface';
import type { CopilotStatus } from '@/lib/api-contracts-copilot';
import type { FetchState } from '@/lib/api-response';

/**
 * The copilot page body for every outcome of the status read: permission, unauthenticated, error and
 * the connected states. Without permission there is no form and no ask is ever attempted.
 */
export function CopilotBody({ state }: { state: FetchState<CopilotStatus> }) {
  if (state.kind === 'forbidden') {
    return (
      <StateSurface
        icon="bi bi-shield-lock"
        title="Ask Netsight is not available to your role"
        detail="Using the copilot needs the copilot:ask permission, which your role does not hold. Access is enforced by the Netsight API."
      />
    );
  }
  if (state.kind !== 'ok') return <DataFailure state={state} />;
  return (
    <div>
      <CopilotStatusCard status={state.data} />
      <CopilotPanel status={state.data} />
    </div>
  );
}
