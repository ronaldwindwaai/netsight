'use server';

import { apiPost } from '@/lib/api';
import { parseCopilotAsk } from '@/lib/api-contracts-copilot';
import { validateQuestion, type AskActionResult } from '@/lib/copilot-view';
import { NOT_SAME_ORIGIN_MESSAGE, fromSameOrigin } from '@/lib/server-write';
import { describeWriteFailure } from '@/lib/write-outcome';

/** The model has up to 60 s on the API side; the default 10 s would cut a real answer short. */
const ASK_TIMEOUT_MS = 75_000;

/**
 * Ask the API one question. The copilot is read-only: it reads evidence with the asker's own
 * permissions and returns text. The origin is checked, then the session and CSRF token are attached
 * server-side by `apiPost`; the answer must parse against the canonical contract or it is not shown.
 */
export async function askCopilot(question: string): Promise<AskActionResult> {
  if (!(await fromSameOrigin())) {
    return { ok: false, title: 'Not sent', message: NOT_SAME_ORIGIN_MESSAGE, correlationId: 'not-available' };
  }
  const checked = validateQuestion(typeof question === 'string' ? question : '');
  if (!checked.ok) {
    return { ok: false, title: 'Not sent', message: checked.message, correlationId: 'not-available' };
  }
  const state = await apiPost('/api/v1/copilot/ask', { question: checked.question }, parseCopilotAsk, {
    timeoutMs: ASK_TIMEOUT_MS,
  });
  if (state.kind === 'ok') return { ok: true, ask: state.data };
  const failure = describeWriteFailure(state);
  return { ok: false, title: failure.title, message: failure.message, correlationId: failure.correlationId };
}
