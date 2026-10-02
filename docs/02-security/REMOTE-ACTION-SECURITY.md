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

## Example
Instead of `execute_shell("systemctl restart " + service)`, expose `restart_service(device_id, service_id)` with a server-side allow list.
