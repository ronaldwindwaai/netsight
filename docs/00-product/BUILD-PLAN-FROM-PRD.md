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
2. ✅ S6-2 incident routes (2026-10-08, **done: independent reviews complete, review fixes applied, follow-ups below**; not committed): code-reviewer APPROVE, security-reviewer PASS WITH FOLLOW-UPS (no CRITICAL/HIGH). Fixed in the review pass: technician assigned-scope enforced under the incident row lock (`required_assignee` in `transition_state`/`append_event`/`add_evidence`, the unlocked pre-read removed); one session resolution per request and fail-closed, byte-safe CSRF; origin allow-list (`NETSIGHT_ALLOWED_ORIGINS` + public base URL) for cookie writes; dev-bridge writes need the CSRF header; `SameSite=None` rejected unless explicitly allowed; success/failure audit emitted from the worker thread (cancel-safe) and the audit logger configured at start-up (`docs/08-operations/AUDIT-LOGGING.md`); audit hygiene (validated target, hashed free-form values, hashed not truncated actor ids); resolution re-validation inside the audited boundary; only pydantic/domain errors map to 4xx. Delivered scope: `/api/v1/incidents` list/detail/timeline reads and acknowledge/transition/assign/comment/evidence/resolve/reopen writes (`incident_routes.py`), `incident-api.schema.json` + OpenAPI + pydantic + TS parsers in four-way agreement (new vectors), granular RBAC permissions (`incidents:transition|assign|comment|resolve|reopen|write-assigned`), `Identity.principal` (resolve/reopen human-only), CSRF on cookie-authenticated writes, per-identity write rate limit, interim audit log (`netsight_api.audit`), `DATABASE_URL` app-role store wiring. Gate items closed here:
   - `approve_rule(..., expected_version)` (StorageConflictError on mismatch) in Protocol, memory and PostgreSQL stores + conformance.
   - `update_rule` / `disable_rule` now require `actor_id` (validated, not persisted: rules have no editor column). **Alert-rule routes (S6-3) must write the audit event** with `record_audit`.
   - Resolve/reopen restricted to human principals in `rbac.is_allowed`; every non-session identity defaults to `PrincipalKind.SERVICE`.
   - Reads: no store configured -> 200 `not-connected`; store failure -> 200 `unknown` (rows/cursors always empty); writes: 503 `STORE_NOT_CONNECTED` / `STORE_UNAVAILABLE`, 409 conflict/illegal transition, 422 invalid, 404 unknown id.
   Remaining S6-2 follow-ups (open for the S6 gate; none blocks S6-3):
   - **Human decision needed:** should the Management role get a summary-only incident view (and a dedicated summary permission) instead of full `incidents:read`? Not decided; today Management reads everything the other read roles read.
   - Technician read scope ("Assigned" is enforced for writes only) and site/asset scope for reads.
   - Read auditing (privacy-sensitive reads are not audit-logged).
   - Read rate limit and a connection pool (one connection per store call today; a write limiter exists).
   - Request body size cap (field limits only).
   - Tamper-evident audit store (PRD 32): the audit sink is a configured log; the append-only timeline is the durable record.
   - Keyset paging (list uses a server-capped offset of 10 000; a full final page yields one empty trailing page).
   - Step-up authentication for resolve/reopen.
   - Per-worker in-memory rate limiter and session store (needs a shared store before running more than one worker).
   - Comment idempotency (a retry after a timeout can duplicate a comment).
   - Column-level `UPDATE (state, ...)` on `incidents` for the app role: SQL run as that role can change state without the timeline event (record/history divergence); consider a trigger or stored-procedure write path.
   - `assignee_id` shape validation (length only today).
   - Startup check that `DATABASE_URL` is not an owner role; Postgres 17 run + CI service container.
3. ✅ S6-3 alert-rule engine, notification routing and alert-rule/maintenance routes (2026-10-08; **uncommitted on `main`; independent reviews complete and re-reviewed — code review APPROVE, security review PASS WITH FOLLOW-UPS**). Delivered:
   - Deterministic evaluation engine (`alerting/`, pure, injected clock): conditions (numeric operators, a linear-time glob for `matches`, baseline direction), schedules in the schedule timezone (DST gap/repeat, overnight, whole-day, weekday-of-start; Windows has no OS tz database, so `tzdata>=2024.1` is now an explicit dependency in `pyproject.toml` — without it scheduled rules fail closed), `for` debounce, cooldown (blocked notifications are deferred while the alert keeps firing, never lost), exceptions, scope, freshness/duplicate/out-of-order screening, maintenance windows (`active`/`expired` derived from the clock, half-open, overlap = union, `disable` beats `retain`), grouping keys and an incident plan, and a fail-closed configuration check (an invalid rule never evaluates, is refused at create/update/approve). Semantics and the interpretations to confirm are in `ALERT-ENGINE.md`.
   - Notification routing (`notifications/`): email/push/webhook behind a `NotificationSender` Protocol with a fake; `Secret` credentials excluded from repr/logs; untrusted text rendered as data only; webhook SSRF defence (https only, no userinfo, no IP/numeric hosts, deny-by-default host allow-list, resolve-once + every answer must be public incl. mapped/NAT64/6to4/Teredo/compat forms, connection pinned to the validated address with SNI/Host preserved, no redirects, no proxy env, timeouts + deadline, response read-capped); bounded queue, bounded retry with deterministic backoff, bounded delivery ring, severity/label/schedule routing and escalation (`NOTIFICATION-ENGINE.md`). Not wired to the engine or the routes; the routes never send.
   - Routes `/api/v1/alert-rules` (list, get, create, `PUT` with `expected_version`, `approve`, `disable`, read-only `evaluate` dry-run) and `/api/v1/maintenance-windows` (list with a clock-derived `active` filter, get, create, cancel). New RBAC permissions `alert-rules:read|write|approve|disable`, `maintenance:read|write|write-organisation` mapped per RBAC-MATRIX (approve and organisation-wide windows are administrator-only; Technician and Management hold none; Auditor reads; every write is human-only so no AI/service principal can change monitoring configuration). Writer order authorise -> CSRF + origin -> rate limit, worker-side audit with hashed free-form values, `StorageConflictError` -> 409, explicit `not-connected`/`unknown` reads without rows, 503 writes, 422 pagination/body bounds, rules start as drafts and approval is bound to `expected_version` (a concurrent edit makes the approval a 409; proven with threads and under real PostgreSQL row locks).
   - Four-way contract agreement for the new envelopes and bodies: `alert-rule-api.schema.json`, OpenAPI components/paths, pydantic models and TS parsers (`api-contracts-alert-rule-api.ts`), driven by new shared vectors (non-ok => no rows; cross-field rules flagged `jsonschema_rejects: false`). `parseAlertRuleDefinition` is now exported by `api-contracts-alert-rule.ts`.
   - Closes the S6-2 gate item "rule edit/disable carry an actor": every rule and window mutation is audited with actor, target id, version and action.
   - Verification (re-run after the review fixes): ruff clean, mypy (`src`) clean; default pytest 2977 passed / 309 skipped (live-DB skips); live PostgreSQL 16.2 (ephemeral pgserver, stopped afterwards, no postgres process remains) 3284 passed / 2 skipped; web typecheck and lint clean. No new SQL and no migration (rollback: unregister the two routers in `main.py`).
   - Skipped deliberately: the AI "propose" stub (no AI broker or hook point exists; any future proposal must yield a draft that only a human approval can activate); wiring the engine to real observations and to incident creation.
   Follow-ups (open for the S6 gate; none blocks the remaining S6 work):
   - Review outcomes: first code review **CHANGES REQUESTED** (1 MEDIUM, 6 LOWs) and first security review **PASS WITH FOLLOW-UPS** (1 MEDIUM, 3 LOWs). Every finding was fixed in this diff — security-model two-axis wording in RBAC-MATRIX/THREAT-MODEL, window-creation organisation-scope gate (default deny), untrusted-TLS SSRF premise test, evaluation-slot leak on dispatch failure, audit reason codes, stale-data stamps in the UI, contract-test scope for approve/disable, explicit `tzdata` dependency. Re-review (2026-10-09): the code reviewer verified all seven prior findings **CLOSED** and raised 2 further LOWs, both fixed (`Retrieved <UTC>` stamp added to the incident-detail surface; THREAT-MODEL tzdata wording made consistent) — verdict **APPROVE**; the security reviewer verified MEDIUM/LOW-1/LOW-3 fixed, verdict **PASS WITH FOLLOW-UPS**, and its 2 non-blocking items were also fixed (creation-scope docstring corrected; `cryptography` declared in the dev extra). Informational only, no action: cancelling a site-scope `evaluation: disable` window needs just `maintenance:write`, but such a window can only be created with the organisation permission and cancelling it removes silencing (de-escalation, and organisation-scope cancel stays gated). Residual follow-up: security LOW-2 — audit records created on denied organisation-scope window checks grow the audit file with no rotation; audit-file rotation/scoping (the systemic fix) is tracked under `docs/08-operations/AUDIT-LOGGING.md`.
   - **Human decisions:** may the creator of a rule also approve it (no four-eyes today); should approval need step-up authentication; should Technician see maintenance windows; how "Scoped" is defined for Network Engineer / Security Analyst (site scoping does not exist, so they can disable any rule and schedule non-organisation windows for any scope); Management summary view for incidents (still open from S6-2; alert rules stay "No" per the matrix).
   - Wire an observation source, the engine and `plan_incident` to the incident store; durable delivery-attempt storage (today a bounded in-memory ring); production email (SMTP relay) and push senders; secret storage for webhook URLs/headers once persisted; a DNS timeout for `system_resolver` (the OS lookup has none); decide how internal (private-network) webhook targets are supported, if ever (no bypass exists on purpose).
   - Dependency inhibition and silences; a supported-metric catalogue (an unknown metric is accepted and never receives data); validate `scope.ref` against inventory; rule version history (an edit keeps no diff beyond the audit record).
   - Carried over from S6-2 and still open: request body size cap, read rate limiting and read auditing, per-worker in-memory rate limiter, tamper-evident audit store, Postgres 17 run and CI service container.
4. ✅ S6-4 alerts & incidents UI (2026-10-08; **uncommitted; the code review's stale-data finding (L3) against these pages is fixed and the re-review gave APPROVE**). Delivered:
   - `/incidents` list (server component): filters (state/severity/assignee), a severity-count strip explicitly scoped to the listed page, keyset pager, and the full state matrix — loading, empty, filtered-empty, store `not-connected`/`unknown` (`StoreStateSurface`), permission-denied and error. `/incidents/[incidentId]` detail: summary, resolution, evidence ids and the append-only timeline with cursor paging ("Later events"/"Back to start").
   - `/alerts` extended: the existing LibreNMS source-alert table plus `AlertRulesCard` and `MaintenanceWindowsCard` (clock-derived active/expiry), fetched through the typed `api-contracts-alert-rule-api.ts` parsers; paging via URL offsets shared by both sections.
   - Operator-entered text (rule/window names, labels, reasons, titles, assignees) is rendered as data only — no raw HTML anywhere in these views (`no-raw-html.test.ts`).
   - Stale-data honesty (code-review LOW L3): pages that call APIs without a freshness value print `Retrieved <UTC>` and say so; empty states never claim "nothing happened".
   - Verification: web typecheck and lint clean, **523 web tests pass**, `next build` succeeds (all S6 routes compile). Read-only: the UI issues no mutations, so the only security surface is what RBAC already enforces server-side.
   Follow-ups (S6-4):
   - Incident write actions (Acknowledge/Assign/Comment/Resolve/Reopen) exist in the API but are rendered disabled with a visible "not available yet" explanation; wiring them needs CSRF-protected POSTs, the S6-2 step-up decision, and 409/conflict handling.
   - Alert-rule/maintenance-window create, edit, approve, disable and cancel forms: the routes, RBAC and contracts are complete (S6-3) but the UI is read-only over them in this slice.
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
