# Authentication & Authorization Specification

## Providers
- Microsoft Entra ID
- Google Workspace
- Clerk (ADR 0009) — as a standard OIDC provider only; Netsight does not use
  the Clerk SDK and keeps its own server-side sessions.

## Protocol
OIDC/OAuth 2.0 Authorization Code flow; PKCE as appropriate.

## Provider allow-list
Configuration must explicitly list:
- allowed Microsoft tenant IDs;
- allowed Google Workspace hosted domains or approved identities;
- for Clerk: the exact instance authority (pinned; a token from any other
  instance is rejected) **and** an explicit identity allow-list. A Clerk
  instance may allow self-service sign-up, so instance membership is not an
  authorisation decision. An empty Clerk allow-list denies every identity.

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
