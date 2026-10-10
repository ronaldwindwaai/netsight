'use server';

import { parseIncident, parseIncidentTimelineEvent } from '@/lib/api-contracts-incident';
import { planIncidentRequest } from '@/lib/incident-actions';
import { NOT_SAME_ORIGIN_MESSAGE, fromSameOrigin, rejected, runWrite } from '@/lib/server-write';
import type { WriteActionResult } from '@/lib/write-result';

/**
 * Perform one incident write (acknowledge, advance, assign, comment, resolve, reopen).
 *
 * The payload arrives from the browser, so it is never trusted: the incident id must match the
 * contract pattern and the body is rebuilt field by field with the contract's bounds
 * (`planIncidentRequest`). The session cookie and CSRF token are attached server-side by
 * `apiPost`; the API remains the authority on permission, scope, step-up and state.
 */
export async function performIncidentAction(input: unknown): Promise<WriteActionResult> {
  if (!(await fromSameOrigin())) return rejected(NOT_SAME_ORIGIN_MESSAGE);
  const plan = planIncidentRequest(input, Date.now());
  if (!plan.ok) return rejected(plan.message);
  const write = { method: 'POST' as const, path: plan.path, body: plan.body };
  return plan.result === 'event'
    ? runWrite(write, parseIncidentTimelineEvent)
    : runWrite(write, parseIncident);
}
