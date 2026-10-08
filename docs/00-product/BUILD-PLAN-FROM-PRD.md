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
- Topology (S3 steps 1–4): canonical `topology.schema.json`, `/api/v1/topology` endpoint, NetBox active cables as the only edge source (states `not-connected` / `unknown` / `ok`; only terminations that resolve to devices on both ends become edges), `/network/map` UI with explicit states + interactive layered canvas (pan/zoom/fit), contract + parser tests (no-source/empty/valid graph). Reconciliation findings consumed in edge context: nodes carry `reconciled` + `finding` (`missing-discovered` / `status-mismatch` only, finding requires `reconciled=true` in schema/pydantic/parser); `unknown-discovered` stays in `/reconcile/findings`. Reviewed: independent review (1 MAJOR contract-agreement finding fixed: `TopologyNode.name` now required-nullable across pydantic/OpenAPI/JSON-schema/TS parser) + security review (negative authz tests, SSRF pagination-origin test, hostile-name test, token-echo test added; threat-model delta recorded).
- Web overview placeholders: topology, incidents, traffic, applications, users, internet, security are explicitly "not connected" surfaces; no fabricated metrics.
- Traffic (S4-1 + S4-2): canonical `traffic.schema.json` (top responses) + `traffic-flows.schema.json`, pydantic models, OpenAPI paths and TS parsers in three-way agreement; `/api/v1/traffic/top-talkers`, `/api/v1/traffic/top-destinations`, `/api/v1/traffic/flows` gated by `traffic:read` with server-bounded windows (`preset` `1h`/`6h`/`24h`/`7d` or explicit `from`/`to`, ≤31 days, `limit` ≤100/≤500 → 422 on violations) and explicit `not-connected`/`unknown`/`ok` states. S4-2 wires the read-only ClickHouse/Akvorado `TrafficSource` (unset `CLICKHOUSE_DSN` → `not-connected`; configured-but-invalid or failed read → `unknown`; real reads → `ok` with source-reported freshness) — never fabricated sample rows.

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
Steps:
1. ✅ Traffic contracts + explicit-state endpoints (S4-1, contract-first): `traffic.schema.json` + `traffic-flows.schema.json`, pydantic/OpenAPI/TS-parser agreement, `/api/v1/traffic/top-talkers`, `/api/v1/traffic/top-destinations`, `/api/v1/traffic/flows` with bounded windows and `traffic:read`; `TrafficSource` protocol defined, source unwired → `not-connected`. Negative contract tests (non-ok must carry no rows), RBAC 401/403 (technician denied), window/limit 422 tests, XSS-label passthrough-as-data test.
2. ✅ ClickHouse flow query adapter (S4-2; read-only, parameterised, bounded: row limit + window + query timeout/budget) wired via `TrafficSource`; real reads produce `ok`/`unknown` only; security delta for untrusted flow labels/user fields. Three-upstream-call ceiling (discovery + data; ≤3 with settings-free readonly retry), `system.columns` schema discovery, IPv4-mapped IPv6 normalisation, nullable-counter handling, freshness `fresh`/`stale`/`unknown`; mock-transport unit tests + opt-in live integration test (`CLICKHOUSE_TEST_DSN`, skips when unset).
3. ✅ UI `/traffic` page (S4-3) per DESIGN-INVENTORY row 5: server-rendered time-range picker (1h/6h/24h/7d), Top talkers (source IP) and Top Destinations bars, Top Applications (source-reported `application` share across the listed high-volume flows, unattributed remainder shown, explicitly labelled, no estimate), Recent High-Volume Flows table, consolidated not-connected/unknown surface plus per-panel loading/empty/permission/failure states, and a `Traffic` menu entry. Presentational components only; no contract change. Web tests for byte/share formatting and the application-mix helper; typecheck/lint/build clean.
4. Overview wiring replaces the traffic placeholder only with real data. (Deferred — the overview keeps its explicit placeholder surfaces; track with the next overview pass.)
5. ✅ Tests/contract tests; independent review + security review (S4-4 slice gate). Independent review returned CHANGES REQUIRED (pydantic not enforcing the non-ok⇒no-rows invariant; `ok`-path construction outside the contract guard; application-mix denominator), all fixed in `5fca09d` and confirmed APPROVE on re-review. Security review returned PASS WITH FOLLOW-UPS; redirect/TLS hardening and secret-repr fix landed, with per-identity rate limiting (F2), traffic ABAC/site scoping (F3) and read auditing (F4) recorded as platform follow-ups in the threat model.

Out of slice pass (P1 follow-ups): NS-043 identity correlation framework, NS-044 after-hours baselines.

### E05 — Security operations
Stories: NS-050..NS-052.
Steps: Wazuh/Suricata read-only adapters; security overview API; correlated evidence model; security centre UI with explicit unknown states.
1. ✅ Security events contract + explicit-state endpoint (S5-1, contract-first): `security.schema.json`, pydantic `SecurityEvent`/`SecurityEventsResponse`, OpenAPI path + schemas, TS parser (`api-contracts-security.ts`), `GET /api/v1/security/events` gated by `security:read` with the shared server-bounded window (`timewindow.py`, extracted from the traffic routes). `SecuritySource` protocol unwired → `not-connected`; source failure or contract-invalid row → explicit 200 `unknown`; untrusted signature text passes through as data.
2. ✅ Wazuh read-only indexer adapter (S5-2): bounded `_search` against `wazuh-alerts-*` (`WAZUH_INDEXER_URL`/`_USER`/`_PASSWORD`/`_CA_BUNDLE`/`WAZUH_ALERTS_INDEX`; unset → `not-connected`), rule-level→severity bands, TLS verify on, redirects refused, credentials excluded from repr, index/URL validated. `device_id` stays null until identity correlation maps agents (no IP inference).
3. ✅ Suricata EVE alerts are consumed from the same indexer (Wazuh-forwarded): `data.alert.*` signature/category, severity 1/2/3→high/medium/low, `src_ip`/`dest_ip`; flow-id preservation and entity linking remain follow-ups.
4. ✅ `/security` UI page (S5-3): time-range picker, severity counts (labelled as counts of the listed events), events table with plain-text untrusted fields, per-state surfaces (not-connected/unknown/empty/failure), `Security` menu entry. Web: typecheck/lint/103 tests/build clean.
5. ✅ S5 slice gate (self-review against the security checklist; **independent reviewer pass still outstanding**): threat-model delta recorded. Follow-ups: agent->device mapping, per-identity rate limiting, site scoping + read auditing, Suricata flow-id preservation, `partial` state for malformed hits, live Wazuh integration test.

6. ✅ S5 independent review (ecc:code-reviewer, 2026-10-08): **APPROVE**, 0 CRITICAL/HIGH, 4 MEDIUM, 5 LOW; 67 API tests pass. Follow-ups (schedule as an S5 hardening pass, M1/M2 before real Wazuh credentials are configured):
   - M1 require https when `WAZUH_INDEXER_USER` is set (plain http only via explicit dev flag) + test.
   - M2 `.env.example` still lists `WAZUH_BASE_URL`/`WAZUH_TOKEN`; update to `WAZUH_INDEXER_*`/`WAZUH_ALERTS_INDEX`.
   - M3 OpenAPI `SecurityEventsResponse` does not express non-ok ⇒ no-rows; add it plus an OpenAPI-vs-JSON-schema diff test.
   - M4 `_optional_text` must strip before the empty check (a whitespace-only field currently degrades the whole read to `unknown`); fold into the `partial`-state work.
   - L1 log adapter failure status; L2 use `ssl.SSLContext` for CA bundle (httpx 0.28 deprecation); L3 response-size cap; L4 require `wazuh-` index prefix; L5 stale docstring in `security_routes.py`.
   - Rollback note: unset `WAZUH_INDEXER_URL` returns the endpoint to `not-connected`.

### E06 — Alerts & incidents
Storage decision (2026-10-08, human ruling): follow `DATABASE-OWNERSHIP.md` — PostgreSQL owns incidents, alert rules and maintenance windows. The VPS gets Docker with the required services (Postgres first); local/CI tests run against Postgres.

1. ✅ S6-1 contracts + storage (2026-10-08): `incident.schema.json` / `alert-rule.schema.json` (+ maintenance window), pydantic/OpenAPI/TS parsers in agreement via shared vectors (`contracts/test-vectors/incident-alert.vectors.json`), repository Protocol with in-memory + PostgreSQL stores, migrations 0001/0002, app-role grants, migrator CLI (`python -m netsight_api.storage.migrate up|status`). No routes yet. database-reviewer: CHANGES REQUIRED → H1 role split/grants, H2 guarded down, H3 CLI, M1/M4/M5/M8 fixed; final code review: **APPROVE** (0 CRITICAL/HIGH). Live-Postgres suite passed on PG 16.2 (1284 passed) during the fix pass; the reviewer ran the default suite only (1063 passed, 223 live-DB skips).
   Gate items before/at S6-2 / S6 gate:
   - `approve_rule` must take `expected_version` (approval bound to the reviewed version) — do before S6-2 fixes the Protocol.
   - Rule edit/disable carry no actor; S6-2 must write them to the audit pipeline (PRD §32) or pass `actor_id`.
   - Resolve must be restricted to human principals in S6-2 (no AI-proposed root cause recorded without operator acceptance).
   - Confirm adjacent-only state machine (no backward step before `resolved`) is intended.
   - Grants script revokes PUBLIC on schema `public`: the NetSight DB must be dedicated; document.
   - Run live suite on Postgres 17 (compose target); add CI Postgres service container.
   - Deferred: keyset paging (M2), resolution history on reopen (M3), connection pool (M6), tighter jsonb CHECKs + corrupt-row tolerance (M7), migration checksums (M9), startup check that `DATABASE_URL` is not an owner/superuser role, 409/503 mapping of storage errors in routes, never log `__cause__` verbatim.
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
4. ✅ Interactive graph component (layered SVG, pan/zoom/fit, deterministic, explicit-link only) + reconciliation findings in edge context + independent + security review (findings fixed).
5. Follow-up issues recorded from review (not blocking S3): `partial` topology state for partial name data (UI-STATES.md), canonical schema referential integrity (edges→nodes) + `format` assertion in `contracts.py`, rate limiting/caching for `/api/v1/topology`, upstream TLS failure test, devices pagination for node names (page 1 only today), path-prefixed `base_url` pagination quirk, distinguish misconfigured vs unconfigured NetBox (`unknown` vs `not-connected`).
6. ✅ Traffic contracts + explicit-state traffic endpoints (S4-1, contract-first). ✅ ClickHouse/Akvorado read-only `TrafficSource` adapter wired, source-reported freshness, adapter unit tests + opt-in live test (S4-2; `/traffic` UI page is S4-3).
