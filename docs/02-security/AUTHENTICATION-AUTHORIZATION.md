# Authentication & Authorization Specification

## Providers
- Microsoft Entra ID
- Google Workspace

No other *federated* provider is approved. ADR 0002 governs the federated
list; adding one requires a new ADR plus explicit settings wiring.

## Netsight-managed credentials (ADR 0010)

Optional, per deployment, and permitted **only** with every control below.
Runs alongside the federated providers, which remain approved.

- Passwords are stored with Argon2id, never reversibly. Minimum 12 characters,
  common-password denylist, bounded maximum length.
- MFA is mandatory. A password alone never issues a session: login is
  password -> MFA challenge -> session.
- TOTP per RFC 6238. Secrets encrypted at rest with AES-GCM, revealed once at
  enrolment, replay-rejected inside a time step.
- Ten single-use recovery codes, hashed at rest, issued once.
- Escalating per-account lockout plus per-IP rate limiting.
- Responses must not reveal whether an account exists (constant-time, identical
  error codes and shapes).
- Local users reuse the hardened session manager; no new session mechanism.
- Every auth event is audited with a correlation ID and no secrets.

The deployment must serve HTTPS. Account recovery when both the authenticator
and the recovery codes are lost is operator-assisted, audited and out-of-band.

## Protocol
OIDC/OAuth 2.0 Authorization Code flow; PKCE as appropriate.

## Provider allow-list
Configuration must explicitly list:
- allowed Microsoft tenant IDs;
- allowed Google Workspace hosted domains or approved identities.

An empty allow-list denies every identity (fail closed).

## Session
- Secure + HttpOnly cookie
- SameSite appropriate to deployment
- server-side or strongly controlled session state
- inactivity timeout
- absolute lifetime
- session revocation
- CSRF protection where relevant

## Roles
Administrator, Network Engineer, Security Analyst, Technician, Management Viewer, Auditor.

## Permissions
Use granular permissions such as:
- device:read
- traffic:read
- security:read
- incident:write
- alert-rule:admin
- diagnostic:execute
- action:propose
- action:approve
- action:execute
- integration:admin
- iam:admin

## Step-up
High-risk routes check authentication freshness/assurance before allowing approval/execution.

## ABAC additions
Scope by:
- organisation;
- site;
- device group;
- department;
- action risk.

UI hiding is not authorization.
