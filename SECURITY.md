# Security Policy

Netsight is security-sensitive because it aggregates network topology, identities, traffic metadata, security telemetry and remote actions.

## Report a vulnerability

Do not open a public issue containing exploit details or secrets. Use the organisation's private security reporting channel once configured.

## Supported security posture

- Federated identity only for normal users.
- MFA/conditional access expected for privileged users.
- Least privilege.
- Backend-enforced RBAC/ABAC.
- Separate read vs write integrations.
- Step-up authentication for high-risk actions.
- Complete audit trails.
- Secrets in an approved secrets manager.
- Secure SDLC aligned to NIST SSDF and OWASP ASVS.

See `docs/02-security/`.
