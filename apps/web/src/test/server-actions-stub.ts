import type { WriteActionResult } from '@/lib/write-result';

/**
 * Stands in for the incident and alerting server actions in component tests. A test installs a
 * handler (usually a `mock.fn`) and inspects the inputs the component sent.
 */
export type ActionHandler = (input: unknown) => Promise<WriteActionResult>;

const unconfigured: ActionHandler = () => {
  throw new Error('No server action handler installed for this test');
};

export const actionHandlers: { incident: ActionHandler; alerting: ActionHandler } = {
  incident: unconfigured,
  alerting: unconfigured,
};

export function resetActionHandlers(): void {
  actionHandlers.incident = unconfigured;
  actionHandlers.alerting = unconfigured;
}

export function performIncidentAction(input: unknown): Promise<WriteActionResult> {
  return actionHandlers.incident(input);
}

export function performAlertingAction(input: unknown): Promise<WriteActionResult> {
  return actionHandlers.alerting(input);
}
