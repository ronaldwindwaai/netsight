'use server';

import { parseUnknownDeviceEvent, parseUnknownDeviceFinding } from '@/lib/api-contracts-unknown-devices';
import { NOT_SAME_ORIGIN_MESSAGE, fromSameOrigin, rejected, runWrite } from '@/lib/server-write';
import { planFindingRequest } from '@/lib/unknown-device-actions';
import type { WriteActionResult } from '@/lib/write-result';

/**
 * Perform one finding write (acknowledge, investigate, assign, comment, resolve or dismiss).
 *
 * The payload arrives from the browser, so it is never trusted: the finding id must match the
 * contract pattern and the body is rebuilt field by field with the contract bounds
 * (`planFindingRequest`). The session cookie and CSRF token are attached server-side by `apiPost`;
 * the API remains the authority on permission, state and step-up. There is no isolate action.
 */
export async function performFindingAction(input: unknown): Promise<WriteActionResult> {
  if (!(await fromSameOrigin())) return rejected(NOT_SAME_ORIGIN_MESSAGE);
  const plan = planFindingRequest(input);
  if (!plan.ok) return rejected(plan.message);
  const write = { method: 'POST' as const, path: plan.path, body: plan.body };
  return plan.result === 'event'
    ? runWrite(write, parseUnknownDeviceEvent)
    : runWrite(write, parseUnknownDeviceFinding);
}
