# ADR 0010 — Netsight-Managed Local Credentials with Mandatory MFA

Status: Accepted
Date: 2026-10-05
Decides: Amends ADR 0002 at the platform owner's explicit direction
Deciders: platform owner

## Context

ADR 0002 restricted normal-user authentication to approved federated providers
(Microsoft Entra ID, Google Workspace) and recorded the consequence: no routine
local password flows. `AGENTS.md` listed "add a local password login for
ordinary users" as an absolute agent prohibition.

The platform owner reviewed that conflict, was shown the residual risk of a
publicly reachable NOC platform holding credential material, and chose to
amend the policy. This ADR records that decision and the controls it requires.

## Decision

Netsight MAY authenticate ordinary users with credentials it stores itself.
This is **opt-in per deployment** and runs *alongside* the federated providers;
ADR 0002's providers remain approved and are not deprecated.

Local credential authentication is permitted **only** with all of the
following controls. These are preconditions, not follow-up work.

### 1. Password storage

- Argon2id (`argon2-cffi`), never a general-purpose hash and never reversible.
- Per-user random salt; parameters OWASP-recommended (memory 64 MiB,
  time cost 3, parallelism 4). Tunable by deployment, not hardcoded silently.
- Minimum 12 characters. Common passwords are rejected against a denylist.
- Maximum length enforced to bound hashing cost against a request-size DoS.
- Verification is constant-time and performs a dummy Argon2 verification when
  the account does not exist, so response time does not reveal account
  existence.

### 2. Multi-factor authentication is mandatory

- TOTP per RFC 6238 (HMAC-SHA-1, 6 digits, 30-second step) for compatibility
  with standard authenticator applications.
- A password alone **never** produces a session. Login is two-step: password
  verification, then an MFA challenge, then session issuance.
- TOTP secrets are encrypted at rest with AES-GCM under a key derived from
  `NETSIGHT_SESSION_SECRET`. They are returned exactly once, during enrolment.
- Verification accepts a +/- one step window and compares in constant time.
- The last accepted code is remembered per user to reject replay inside the
  same time step.
- Ten single-use recovery codes are issued at activation, hashed with Argon2id,
  shown once, and consumed on use.

### 3. Brute-force resistance

- Per-account failure tracking with escalating lockout.
- Per-IP rate limiting on the local login path, independent of the federated
  auth limiter.
- Lockout state is not distinguishable from a bad password by an outsider.

### 4. Session handling

Local users receive exactly the same session treatment as federated users:
the existing hardened manager applies (HMAC-signed opaque cookie, HttpOnly,
Secure, SameSite, sliding inactivity timeout, absolute lifetime, explicit
revocation, CSRF on state-changing calls). No new session mechanism is
introduced.

### 5. Audit

Every local auth event is recorded with a correlation ID: login success and
failure, lockout, MFA enrolment, MFA activation, MFA failure, recovery-code
use. Records never contain passwords, TOTP codes, secrets or session values.

### 6. Residual risks accepted by the platform owner

- Netsight is now in scope for credential-material breach. A compromise of the
  identity store plus the session secret is materially worse than an IdP
  compromise, because Netsight also fronts monitoring credentials.
- The deployment must be served over HTTPS. MFA and password login are
  unacceptable over plaintext transport; the web tier already terminates TLS.
- Account recovery is weaker than an IdP: a lost authenticator and lost
  recovery codes require an operator-assisted reset, which must be an audited,
  out-of-band process.
- MFA enrolment friction applies to every local account.

## Consequences

- The `AGENTS.md` absolute prohibition is amended to permit local credentials
  only under the controls in this ADR.
- New attack surface exists on the authentication path and must stay inside the
  S-series security matrix (credential stuffing, enumeration, replay, lockout
  bypass, recovery-code reuse, secret disclosure).
- Federation remains the recommended path for organisations that have an IdP.

## Alternatives considered

- **Keep federation-only** — rejected by the platform owner.
- **Clerk as a federated provider** — would have delivered an email/password
  login without Netsight storing credentials. Offered; not chosen.
- **Hand-rolled password hashing or TOTP** — rejected. Argon2id comes from
  `argon2-cffi`. TOTP is implemented against `hmac`/`hashlib` from the standard
  library only because it is a short, auditable RFC 4648/6238 construction with
  published test vectors; the test suite verifies those vectors.