# Controlled Action Engine

## Design
No generic command execution API.

## Action definition
Each action type declares:
- name;
- risk;
- permitted target types;
- parameter schema;
- authorisation permission;
- required step-up age;
- approval count/role;
- executor;
- timeout;
- verify function;
- rollback guidance.

## State machine
Proposed -> PolicyChecked -> AwaitingApproval -> Authorised -> Executing -> Verifying -> Verified

Failure states:
Rejected, Expired, Failed, VerificationFailed, Cancelled.

## Example types
- endpoint.isolate
- switch.port.disable
- switch.port.enable
- service.restart
- firewall.destination.block

Do not implement these until a lab proves restricted execution.

## Idempotency
All write execution requires idempotency key and action lock.

## Two-person controls
Risk D actions may require an approver who is not the requester.
