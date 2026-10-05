# ADR 0002 — Federated Authentication for Normal Users

Status: Accepted, **partially superseded by ADR 0010**

## Decision
Normal users authenticate through approved identity providers: Microsoft
Entra ID/Microsoft 365 or Google Workspace OIDC.

## Consequence
No routine local password reset flows. A tightly controlled break-glass process
is separate.

## Amendment (ADR 0010, 2026-10-05)

Netsight MAY additionally store credentials for ordinary users, provided every
control in ADR 0010 is implemented: Argon2id hashing, mandatory TOTP MFA with
single-use recovery codes, escalating lockout, no user enumeration, session
reuse, and audit of all auth events. A password alone never grants a session.

Federated providers above remain approved and are not deprecated.