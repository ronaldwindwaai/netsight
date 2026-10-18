import type { WriteActionResult } from '@/lib/write-result';

/**
 * Stands in for the controlled-action server actions in component tests. A test installs a handler
 * (usually a `mock.fn`) and inspects what the component sent.
 */
type Handler = (input: unknown) => Promise<WriteActionResult>;
const missing = (name: string): Handler => () => {
  throw new Error(`No ${name} handler installed for this test`);
};

export const actionHandlers: { decision: Handler; killSwitch: Handler; propose: Handler } = {
  decision: missing('decision'),
  killSwitch: missing('kill switch'),
  propose: missing('proposal'),
};

export function performActionDecision(input: unknown): Promise<WriteActionResult> {
  return actionHandlers.decision(input);
}

export function performKillSwitch(input: unknown): Promise<WriteActionResult> {
  return actionHandlers.killSwitch(input);
}

export function proposeActionFromFinding(input: unknown): Promise<WriteActionResult> {
  return actionHandlers.propose(input);
}
