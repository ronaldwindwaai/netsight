# Netsight Build Plan (derived from PRD and related docs)

Status: living plan. Sources consumed in order: `AGENTS.md`, `docs/00-product/PRD.md`, `docs/01-architecture/*`, two ADRs listed in this repo, `docs/06-data/CANONICAL-DATA-MODEL.md`, `backlog/backlog.csv`, `backlog/VERTICAL-SLICES.md`,
`docs/10-project-management/IMPLEMENTATION-ROADMAP.md`, `docs/09-testing/E2E-SCENARIOS.md`, `docs/00-product/ACCEPTANCE-SCENARIOS.md`.

## Constraints (from AGENTS.md / ADRs)
- Evidence-first AI; never fabricate telemetry; adapter boundaries; AdminLTE 4 React; server-managed sessions; no local password login unless ADR 0010 controls implemented (they are).
- No remote write actions until approval/action framework slice.
- Secure by default, least privilege, fail closed.
- Contracts under `contracts/**` are authoritative; changes require matching OpenAPI/JSON-schema updates.

## Current state (through build order steps 1–3)
- Foundation, CI, security gates, contracts base, canonical API path `/api/v1`.
- S1 slice implemented: OIDC login + local credentials with MFA (ADR 0010), sessions, RBAC, AdminLTE shell, overview aggregate, LibreNMS devices/interfaces/alerts, device table/detail, interface table, source-health states, E2E harness + security matrix tests.
- NetBox (NS-030): read-only adapter + `/api/v1/sources/netbox/health`, `/api/v1/netbox/devices`, `/api/v1/netbox/devices/{id}`, `/api/v1/reconcile/findings`. Contract + parser contract surfaces updated for overview source state.
- Topology (S3 steps 1–3): canonical `topology.schema.json`, `/api/v1/topology` endpoint, NetBox active cables as the only edge source (states `not-connected` / `unknown` / `ok`; only terminations that resolve to devices on both ends become edges), `/network/map` UI with explicit states, contract + parser tests (no-source/empty/valid graph). Reviewed: independent review (1 MAJOR contract-agreement finding fixed: `TopologyNode.name` now required-nullable across pydantic/OpenAPI/JSON-schema/TS parser) + security review (negative authz tests, SSRF pagination-origin test, hostile-name test, token-echo test added; threat-model delta recorded).
- Web overview placeholders: topology, incidents, traffic, applications, users, internet, security are explicitly "not connected" surfaces; no fabricated metrics.

## Build plan (next slices, DoD-gated)

### S3 — Network map (security slice start)
Goal: S3 per `backlog/VERTICAL-SLICES.md`
Stories: NS-030 (done), NS-031 scaffold, NS-032 topology graph model, NS-033 interactive network map, NS-024 partial hardening.
Steps:
1. Define topology canonical model in contracts (nodes = canonical Device IDs, edges = source-explicit links from LLDP/CDP/NetBox cables/manual). No inferred links.
2. Create `/api/v1/topology` endpoint returning explicit graph or explicit not-connected state (no fabrication).
3. Reconciliation findings consumed in topology edge context only; sources of truth remain NetBox.
4. UI: responsive list/graph component using AdminLTE + design system, pan/zoom if source supports, site filter, quick-drawer placeholder until incidents/alerts are real.
5. Contract tests for topology response schema; tests for no-source/empty/valid graph. Independent review + security review.

### E04 — Traffic intelligence
Stories: NS-040..NS-044.
Steps: ClickHouse flow query adapter (read-only, bounded, typed schemas). `/api/v1/traffic/top-talkers`, `/api/v1/traffic/top-destinations`, drilldown with time bounds. Overview wiring replaces placeholders only with real data. Tests/contract tests.

### E05 — Security operations
Stories: NS-050..NS-052.
Steps: Wazuh/Suricata read-only adapters; security overview API; correlated evidence model; security centre UI with explicit unknown states.

### E06 — Alerts & incidents
Stories: NS-060..NS-065.
Steps: alert-rule domain model, notif routing, incident store, timeline, acknowledgement/incident ownership, audit.

### E09 — AI copilot
Stories: per PRD E9.
Steps: tool broker (read-only diagnostics), evidence bundles, RAG, evals; no direct write actions; prompt-injection hardening validated by scenario 11/12.

## Definition of Done per slice
- Acceptance criteria met; tests (unit + integration + contract + slice E2E) pass.
- OpenAPI + JSON-schema updated; type/lint/security checks pass.
- UI loading/empty/stale/permission/error states present.
- Docs updated; no secrets; rollback notes.

## Build order (for this loop)
1. ✅ Topology contracts + `/api/v1/topology` not-connected/unknown endpoint (S3 foundation, contract-first).
2. ✅ Topology UI surface wiring placeholder states (empty-state already exists).
3. ✅ Real topology only when an LLDP/CDP/NetBox explicit edge source is configured; otherwise explicit not-connected state (NetBox active cables wired).
4. Remaining for S3: interactive graph component (pan/zoom, site filter), reconciliation findings in edge context, independent + security review. **Done** (reviews completed; fixes applied).
5. Follow-up issues recorded from review (not blocking S3): `partial` topology state for partial name data (UI-STATES.md), canonical schema referential integrity (edges→nodes) + `format` assertion in `contracts.py`, rate limiting/caching for `/api/v1/topology`, upstream TLS failure test, devices pagination for node names (page 1 only today), path-prefixed `base_url` pagination quirk, distinguish misconfigured vs unconfigured NetBox (`unknown` vs `not-connected`).
