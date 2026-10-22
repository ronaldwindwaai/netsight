# Remote Action Security

## Principle
Monitoring access and control access are distinct.

## Action Request
Required fields:
- action type;
- target;
- requested parameters;
- requester;
- reason;
- evidence/incident;
- risk class;
- impact estimate;
- policy result;
- approval requirements;
- step-up status;
- idempotency key;
- executor;
- result;
- verification result.

## Controls
- allow-listed action types;
- allow-listed parameters;
- target scope validation;
- no arbitrary shell;
- no arbitrary SNMP set;
- no arbitrary command string;
- short-lived execution credentials;
- network egress restrictions;
- execution timeout;
- verification;
- rollback instructions where possible.

## Implementation status (Step 12)

The Action Request framework exists (ACTION-ENGINE.md): allow-listed action types and typed parameters, target validation, risk class, policy
result, approval requirements (requester != approver, two approvers for risk D), step-up, idempotency key, executor interface with
pre-checks, verification and rollback hooks, execution timeout, kill switch and a hash-chained history. Fields not yet carried: impact estimate,
evidence/incident link beyond the Step 8 finding source, short-lived execution credentials and egress restrictions (they belong to a real
executor, none ships). Only a dry-run executor exists.

## Example
Instead of `execute_shell("systemctl restart " + service)`, expose `restart_service(device_id, service_id)` with a server-side allow list.
