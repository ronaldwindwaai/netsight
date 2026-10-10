'use server';

import { parseAlertRule, parseMaintenanceWindow } from '@/lib/api-contracts-alert-rule';
import { planAlertingRequest } from '@/lib/alerting-forms';
import { NOT_SAME_ORIGIN_MESSAGE, fromSameOrigin, rejected, runWrite } from '@/lib/server-write';
import type { WriteActionResult } from '@/lib/write-result';

/**
 * Perform one alert-rule or maintenance-window write (create, edit, approve, disable, cancel).
 *
 * Like the incident action, the payload is untrusted: ids are validated against the contract
 * patterns, form values are rebuilt and re-validated, and approve/edit carry the rule version
 * the operator reviewed (`expected_version`), so a rule edited meanwhile makes the call a 409
 * instead of activating or overwriting something nobody reviewed. The API re-checks permission
 * and every lifecycle rule.
 */
export async function performAlertingAction(input: unknown): Promise<WriteActionResult> {
  if (!(await fromSameOrigin())) return rejected(NOT_SAME_ORIGIN_MESSAGE);
  const plan = planAlertingRequest(input, Date.now());
  if (!plan.ok) return rejected(plan.message);
  const write = { method: plan.method, path: plan.path, body: plan.body };
  return plan.result === 'rule'
    ? runWrite(write, parseAlertRule)
    : runWrite(write, parseMaintenanceWindow);
}
