# START HERE — Netsight Software Factory

This document is the launch sequence for a human or an LLM coding agent.

## 1. Do not start coding immediately

First consume, in order:

1. `AGENTS.md`
2. `docs/00-product/PRD.md`
3. `docs/01-architecture/system-architecture.md`
4. `docs/01-architecture/integration-architecture.md`
5. `docs/02-security/SECURE-SDLC.md`
6. `docs/02-security/SECURITY-ARCHITECTURE.md`
7. `docs/03-ui-ux/ADMINLTE-DESIGN-SYSTEM.md`
8. `docs/06-data/CANONICAL-DATA-MODEL.md`
9. `docs/07-ai/AI-ARCHITECTURE.md`
10. `docs/10-project-management/DEFINITION-OF-DONE.md`

## 2. The first build target

Do **not** install every monitoring product at once.

The first vertical slice is:

**OIDC login -> Netsight shell -> LibreNMS adapter -> device list -> device detail -> health states -> alert list**

Then add NetBox reconciliation. Only after this slice is stable should traffic, security and AI be layered in.

## 3. Required engineering behaviour

Every implementation issue must contain:

- objective;
- scope;
- non-scope;
- architecture references;
- API/data contracts;
- acceptance criteria;
- tests;
- security considerations;
- observability requirements;
- rollback/migration considerations.

## 4. LLM operating model

Use one orchestrator and specialised agents. Agents may propose architecture changes but may not silently make them. Use Architecture Decision Records (ADRs) for meaningful changes.

LLM output is untrusted until:
- tests pass;
- contracts pass;
- security checks pass;
- review is complete;
- a human approves sensitive changes.

## 5. Mandatory safety constraints

Never give an LLM:
- production firewall administrator credentials;
- unrestricted shell on production;
- IdP tenant-wide secrets unless strictly required;
- raw secrets in prompts;
- unrestricted database superuser access;
- ability to merge its own PR;
- ability to deploy directly to production.

## 6. Definition of a successful MVP

An authorised operator can, from desktop or mobile:
- sign in with Microsoft or Google;
- see network health;
- see real monitored devices;
- see an interactive topology;
- identify top traffic consumers;
- identify unusual/after-hours activity;
- receive email/push alerts;
- open and manage an incident;
- ask "Why is this server inaccessible?";
- receive an evidence-backed diagnostic result;
- run read-only diagnostics remotely;
- see a complete audit trail.

See the PRD for full scope.
