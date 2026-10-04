# ADR 0009 — Clerk as an Additional Federated Identity Provider

Status: Accepted (supersedes part of ADR 0002)
Date: 2026-10-04
Deciders: platform owner (requested), implementing agent

## Context

The platform owner asked to "add Clerk Auth" alongside the existing federated
sign-in.

ADR 0002 states that normal users authenticate *only* through Microsoft Entra
ID/Microsoft 365 or Google Workspace OIDC, and `AGENTS.md` prohibits adding a
local password login for ordinary users. Taken as a request to hand
authentication to Clerk's hosted user store, this would conflict with both.

However, Clerk supports acting as a standards-compliant **OpenID Connect
provider** (an "OAuth application" in Clerk terms). Wiring Clerk through the
existing OIDC provider abstraction satisfies the request while preserving
every guarantee already built, so this ADR records that route rather than a
session/SDK integration.

## Decision

Clerk is added as a **third federated OIDC provider**, configured exactly like
Entra and Google. It is not integrated via Clerk's client-side SDK and Netsight
does not adopt Clerk's session management.

Access is denied unless all of the following hold:

1. The id_token is signed by a key published in the configured Clerk instance's
   JWKS, and the algorithm is an approved asymmetric algorithm.
2. `aud` equals the configured Netsight client ID, `exp`/`nbf`/`iat` are valid.
3. `iss` **exactly equals** the configured Clerk authority (trailing slash
   normalised). Each Clerk instance is its own security domain, so a token
   from any other instance — including one with a look-alike host — is
   rejected with `OIDC_ISSUER_INVALID`.
4. `nonce` matches the value generated for this authorization request.
5. The identity is on the Netsight allow-list (`sub` or `email`). **An empty
   allow-list denies everyone.**

### Why the allow-list is mandatory for Clerk

Unlike Entra tenants and Google Workspace domains, a Clerk instance may allow
self-service sign-up. Instance membership is therefore *not* an authorisation
decision. Netsight never treats "has a Clerk account" as "may use Netsight".

When the token carries an `email_verified` claim it is honoured strictly:
`false` (or any non-`true` value) is rejected with `OIDC_EMAIL_NOT_VERIFIED`.

Roles continue to resolve through the existing config-driven
`NETSIGHT_ROLE_CLAIM` / `NETSIGHT_ROLE_MAPPING` mechanism, with
`NETSIGHT_DEFAULT_ROLE` as the least-privilege fallback. An unmapped claim value
is dropped (deny-by-default).

## Consequences

- **Positive:** organisations can offer a third, self-hosted-branded sign-in
  without Netsight giving up control of sessions, roles or authorisation. All
  existing RBAC, session, CSRF, rate-limit and audit behaviour applies unchanged.
- **Positive:** adding the provider required no change to the auth flow, so the
  security surface did not grow.
- **Negative / accepted risk:** Netsight operators who use Clerk introduce a
  third-party dependency into the authentication path. Clerk becomes
  security-relevant infrastructure for that deployment and its availability
  affects sign-in.
- **Negative:** Clerk's own MFA/session policy applies upstream of Netsight.
  Netsight still enforces its own session inactivity and absolute limits
  independently.
- **Negative:** `allowed_identities` is a flat list of `sub`/`email` values.
  It does not scale to large populations; Clerk organization/role claims should
  be mapped through `NETSIGHT_ROLE_MAPPING` or Netsight should synchronise
  identities from a directory instead.

## Alternatives considered

- **Clerk client-side SDK / `<ClerkProvider>`** — rejected. It would move
  session state into the browser and bypass Netsight's server-side sessions,
  CSRF protection and fail-closed middleware. Conflicts with ADR 0002 and
  `AGENTS.md`.
- **Clerk as a hosted user store with Netsight-managed passwords** — rejected.
  This is exactly the "local password login" that `AGENTS.md` prohibits.
- **Replace Entra and Google with Clerk** — rejected. Those providers encode
  tenant/domain allow-lists that Clerk does not reproduce natively.
- **Keep the provider list closed** — rejected by the platform owner's explicit
  request; the additive OIDC route carries acceptable residual risk, recorded above.

## Follow-up required (human)

- Confirm the Clerk instance is approved for Netsight use and record its
  authority in the deployment's `api.env`.
- Populate `NETSIGHT_OIDC_CLERK_ALLOWED_IDENTITIES` before enabling the
  provider; an empty list denies everyone by design, which is fail-closed
  but will look like a broken sign-in.
- Review the data-processing agreement with Clerk if Netsight is deployed in a
  jurisdiction that constrains third-party identity processing.