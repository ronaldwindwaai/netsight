# GitHub Copilot Instructions — Netsight

Follow `AGENTS.md`, the PRD, ADRs and security docs.

Netsight is a security-sensitive network operations platform. Prefer explicit, typed, testable implementations. Never suggest bypassing RBAC, TLS validation, MFA, OIDC validation, secret management, audit controls or approval workflows.

Frontend uses Next.js/React/TypeScript and AdminLTE React as the base shell.
Platform services use Python/FastAPI unless an ADR changes this.
Adapters isolate vendor-specific APIs.
