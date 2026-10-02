# Identity Architecture

## Normal user authentication

Allowed:
- Microsoft Entra ID / Microsoft 365 OIDC
- Google Workspace OIDC

Disallowed for ordinary users:
- application-managed passwords.

## OIDC security requirements

- Authorization Code flow; PKCE where applicable.
- Validate issuer.
- Validate audience/client.
- Validate signature.
- Validate expiry/not-before.
- Validate state and nonce.
- Restrict Microsoft tenant IDs.
- Restrict Google Workspace domains/approved identities.
- Use immutable provider subject IDs; do not use email alone as primary identity.
- Server-side session where practical.
- Secure, HttpOnly, SameSite cookies.
- Do not store access/refresh tokens in localStorage.
- Token/session revocation strategy.
- Session inactivity and maximum-age policies.

## Step-up authentication

Required for high-risk operations. Store authentication assurance/time in session and require fresh proof.

## Break-glass

A local emergency account may exist only if:
- disabled by default;
- credential held offline;
- use raises critical alert;
- use is audited;
- password is rotated after use;
- access path is documented/tested.

## Identity correlation

Login identity is not automatically the same thing as the current user of a network device. Device/user correlation has separate evidence/confidence.
