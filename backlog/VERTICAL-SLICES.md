# Vertical Slice Plan

Complements `backlog.csv` (story-level) and `docs/10-project-management/IMPLEMENTATION-ROADMAP.md`
(epic-level). Slices follow ADR 0007: each slice is a complete, usable
source → adapter → API → UI → tests increment. A slice starts only after the
previous slice meets the Definition of Done
(`docs/10-project-management/DEFINITION-OF-DONE.md`) and the per-slice gate below.

## Per-slice gate (every slice, no exceptions)

1. Acceptance criteria satisfied; tests pass (unit + contract + integration + slice E2E).
2. Independent review (`netsight-reviewer`).
3. Security review vs `docs/02-security/SECURITY-REVIEW-CHECKLIST.md` + negative tests (`netsight-security`).
4. UI slices: Playwright screenshots captured and compared against the referenced
   `/designs` file(s) in `docs/03-ui-ux/DESIGN-INVENTORY.md`; deltas corrected or
   explicitly accepted by the human owner.
5. ECC quality gate: lint, typecheck, tests, security scans green + `skills/qa-validation` checklist.
6. "What remains" documented and appended to the backlog before the next slice opens.

---

## S1 — Identity + Shell + Network Overview (CURRENT)

**Backlog stories:** NS-005, NS-010, NS-011, NS-012, NS-013 ✅(engine done), NS-014, NS-015, NS-020 ✅, NS-021 ✅, NS-023 (partial: harden + type).
**Designs:** login (`09_03_55 AM-2`), overview (`09_02_39 AM-1` / `09_03_53 AM-1`).
**Chain:** Microsoft 365 / Google Workspace OIDC → secure server session → RBAC → AdminLTE shell → Network Overview → LibreNMS adapter → real device health → tests → security review → design screenshot comparison → quality gate.

Workstreams:
- **S1.A Identity (API):** OIDC Authorization Code + PKCE for Entra and Google; tenant/domain allow-lists (`MICROSOFT_ALLOWED_TENANT_IDS`, `GOOGLE_ALLOWED_WORKSPACE_DOMAINS`); issuer/audience/expiry/state/nonce validation; server-managed sessions in Postgres/Redis (`netsight_session` HttpOnly+Secure+SameSite cookie); inactivity + absolute timeouts; revocation; CSRF protection; rate limits on auth endpoints; audit events for login/logout/deny. Removes the dev-identity bridge from the production path (dev-only flag retained for local).
- **S1.B RBAC wiring:** map IdP claims/groups → Netsight roles (config-driven); enforce existing rbac.py on all routes; negative auth tests on every route.
- **S1.C Shell + Login (web):** `/login` per design (SSO buttons only — no local password form, ADR 0002); dashboard shell per design sidebar/topbar (logo, nav, ⌘K search, Ask AI button, critical badge, avatar); light/dark; unhide/replace the temporary user-menu; full UI states.
- **S1.D Network Overview (web):** match the overview design: 4 KPI cards, Live Network Map panel, Active Incidents, Top Bandwidth, Application Mix. Only LibreNMS-backed data is real in S1 (device health/counts, source freshness). Panels without a connected source render the UI-STATES source-unavailable state — never fabricated values, never "0".
- **S1.E Overview API:** `/api/v1/overview` aggregate (device health counts, WAN placeholder state=unknown, source freshness per widget); harden `/alerts` typing (typed response_model, pagination, freshness).
- **S1.F Tests:** unit (OIDC validation, session, role mapping), contract (LibreNMS fixtures incl. malformed/auth-failure), integration (auth flow vs stub IdP), E2E scenarios 1–4 (docs/09-testing/E2E-SCENARIOS.md), security matrix subset (issuer confusion, wrong tenant/domain, expired token, replay/nonce, session fixation, CSRF, privesc, IDOR, role bypass, XSS via device strings, secret leakage in logs, upstream TLS failure).
- **S1.G Gates:** security review → screenshot comparison (login + overview vs designs) → quality gate → DoD → document remainder.

**Open decisions (need human ruling before/during S1.A):**
1. Session timeout values (docs mandate inactivity + absolute limits but set no numbers). Proposal: 30 min inactivity / 12 h absolute, configurable.
2. IdP claim → role mapping source (Entra group IDs vs app roles; Google group). Proposal: config-driven mapping table, deny unmapped.
3. Coverage target (Netsight docs set none; ECC TDD skill expects 80%). Proposal: adopt ≥80% on slice-changed code.
4. Overview panels without S1 data sources: render explicit unavailable states (proposed) vs hide.

---

## Later slices (outline — do not start until S1 passes the gate)

| Slice | Scope | Design | Stories | Key adds |
| --- | --- | --- | --- | --- |
| S2 | Devices inventory + detail | devices (`09_03_58 AM-4`) | NS-022, NS-024 | LibreNMS ports/interfaces; table per design (search/filter/export/pagination/status detail); device detail Summary tab real, other tabs unavailable-state |
| S3 | Network Map | network-map (`09_03_56 AM-3`) | NS-030–NS-033 | NetBox adapter, reconciliation, topology graph, interactive map (pan/zoom/filter/drawer) |
| S4 | Traffic Intelligence | traffic (`09_03_59 AM-5`) | NS-040–NS-044 | Akvorado/ClickHouse read-only bounded queries, top talkers/apps, flows table, baselines |
| S5 | Security Centre | security-centre (`09_04_01 AM-6`) | NS-050–NS-052 | Wazuh + Suricata adapters, correlated findings, severity KPIs |
| S6 | Incidents + Alerts & Automation | incident-detail (`09_04_03 AM-7`), alerts (`09_04_04 AM-8`) | NS-060–NS-064 | Incident CRUD/timeline/evidence; alert rules, schedules, notifications, maintenance windows; AI rule interpretation (read-only propose) |
| S7 | Diagnostics | diagnostics (`09_04_06 AM-9`) | NS-070–NS-073 | Blackbox probes, multi-vantage "Why?" workflow, probable-cause with facts/inference/unknown |
| S8 | Configuration intelligence | (no design — SCREEN-SPECS only) | NS-080, NS-081 | Oxidized diffs, drift, change-to-incident correlation; request design first |
| S9 | Ask Netsight AI | ask-ai (`09_04_08 AM-10`) | NS-090–NS-094 | AI gateway, read-only tool broker, evidence answers, RAG, prompt-injection evals |
| S10 | Reports + Administration | (no designs — gap) | E06/E11 spillover | Reports, integrations/sites/roles admin; request designs first |
| S11 | Controlled remote actions | (partial: incident/diagnostics action buttons) | NS-110–NS-113 | ActionRequest engine, step-up auth, approvals, restricted executors, verification |
| S12 | Mobile/PWA + forecasting | (no designs) | NS-100, NS-101, NS-120, NS-121 | PWA, push, capacity forecast |

Design gaps in S8/S10/S12: obtain approved designs before UI polish; until then derive
layout only from SCREEN-SPECS.md + the global shell. Do not create alternative visual concepts.
