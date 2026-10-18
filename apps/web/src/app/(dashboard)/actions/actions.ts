'use server';

import { parseActionRequest, parseActionStatus } from '@/lib/api-contracts-actions';
import { planDecision, planFindingProposal, planKillSwitch } from '@/lib/actions-view';
import { NOT_SAME_ORIGIN_MESSAGE, fromSameOrigin, rejected, runWrite } from '@/lib/server-write';
import type { WriteActionResult } from '@/lib/write-result';

/**
 * Controlled-action writes. The payload arrives from the browser, so it is never trusted: the id must
 * match the contract pattern, the verb selects one of four fixed paths, and the body is rebuilt field
 * by field with the contract bounds (`planDecision`). The session cookie and CSRF token are attached
 * server-side by `apiPost`; the API remains the authority on permission, the requester rule, the
 * digest and version the person saw, step-up, the kill switch and idempotency. There is no control
 * here that runs a command: `execute` asks the API to record a dry run.
 */
export async function performActionDecision(input: unknown): Promise<WriteActionResult> {
  if (!(await fromSameOrigin())) return rejected(NOT_SAME_ORIGIN_MESSAGE);
  const plan = planDecision(input);
  if (!plan.ok) return rejected(plan.message);
  return runWrite(
    {
      method: 'POST',
      path: plan.path,
      body: plan.body,
      ...(plan.idempotencyKey !== null ? { idempotencyKey: plan.idempotencyKey } : {}),
    },
    parseActionRequest,
    (request) => ({ id: request.id, state: request.state }),
  );
}

/** Engage (any time) or release (needs step-up) the action kill switch. */
export async function performKillSwitch(input: unknown): Promise<WriteActionResult> {
  if (!(await fromSameOrigin())) return rejected(NOT_SAME_ORIGIN_MESSAGE);
  const plan = planKillSwitch(input);
  if (!plan.ok) return rejected(plan.message);
  return runWrite({ method: 'POST', path: '/api/v1/actions/kill-switch', body: plan.body }, parseActionStatus);
}

/** Create the action request for a Step 8 quarantine proposal. Proposal only: nothing is executed. */
export async function proposeActionFromFinding(input: unknown): Promise<WriteActionResult> {
  if (!(await fromSameOrigin())) return rejected(NOT_SAME_ORIGIN_MESSAGE);
  const plan = planFindingProposal(input);
  if (!plan.ok) return rejected(plan.message);
  return runWrite(
    {
      method: 'POST',
      path: '/api/v1/actions/from-finding',
      body: plan.body,
      idempotencyKey: plan.idempotencyKey,
    },
    parseActionRequest,
    (request) => ({ id: request.id, state: request.state }),
  );
}
