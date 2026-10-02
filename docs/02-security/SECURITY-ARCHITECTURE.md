# Netsight Security Architecture

## Security objective

Compromise of the web application must not automatically grant unrestricted control of the monitored network.

## Core controls

1. Federated identity.
2. MFA/conditional access.
3. Backend RBAC/ABAC.
4. Least-privileged source credentials.
5. Read/write credential separation.
6. Network segmentation.
7. Secrets manager.
8. Step-up authentication.
9. Explicit approval for consequential actions.
10. Immutable/append-only audit strategy.
11. Strict input validation.
12. Strong egress controls for integration workers.
13. Secure SDLC/security gates.
14. AI tool policy outside model prompts.
15. Monitoring of the monitoring platform.

## Fail-closed behaviour

Deny when:
- auth service state is invalid;
- role is unknown;
- action permission is absent;
- step-up proof is stale/missing;
- approval is missing;
- target scope cannot be verified.

Telemetry unavailability returns `unknown`, not `healthy`.

## Browser boundary

Browser receives:
- session cookie;
- canonical app data.

Browser does not receive:
- monitoring-engine API tokens;
- SNMP secrets;
- firewall credentials;
- database credentials.

## Integration boundary

Each integration gets a minimal credential. Write credentials are separate and disabled where not needed.

## High-risk action boundary

Action execution requires:
- authorised identity;
- permitted action;
- permitted target;
- fresh step-up auth;
- required approval(s);
- reason;
- idempotency key;
- audit entry;
- verification step.

## AI boundary

Telemetry/logs are untrusted input. Model tool calls are schema constrained. The model cannot manufacture permissions.
