import type { AskActionResult } from '@/lib/copilot-view';

/**
 * Stands in for the copilot server action in component tests. A test installs a handler (usually a
 * `mock.fn`) and inspects the question the component sent.
 */
export const copilotHandlers: { ask: (question: string) => Promise<AskActionResult> } = {
  ask: () => {
    throw new Error('No copilot handler installed for this test');
  },
};

export function askCopilot(question: string): Promise<AskActionResult> {
  return copilotHandlers.ask(question);
}
