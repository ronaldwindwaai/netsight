# PRD v2 implementation and release assessment

Source: `PRD-V2-USER-SUPPLIED.md`, supplied 17 October 2026 and preserved verbatim.
The existing PRD/build plan remains in place for traceability; this assessment is
not a claim that the full new PRD has been implemented or accepted.

## Route evidence

Route existence indicates source coverage only. It does not establish completed
features, design acceptance, production integrations, authorization, or performance.
Dynamic parameter names are normalized when matching existing routes.

| PRD route | Screen | Repository evidence |
| --- | --- | --- |
| `/login` | Secure Login | Route exists: `apps/web/src/app/login/page.tsx` |
| `/` | Network Overview | Route exists: `apps/web/src/app/page.tsx` |
| `/network/map` | Network Map | Route exists: `apps/web/src/app/(dashboard)/network/map/page.tsx` |
| `/devices` | Device Inventory | Route exists: `apps/web/src/app/(dashboard)/devices/page.tsx` |
| `/devices/[id]` | Device Detail | Route exists: `apps/web/src/app/(dashboard)/devices/[deviceId]/page.tsx` |
| `/users` | Users | Route exists: `apps/web/src/app/(dashboard)/users/page.tsx` |
| `/users/[id]` | User Detail | Route exists: `apps/web/src/app/(dashboard)/users/[userId]/page.tsx` |
| `/traffic` | Traffic Intelligence | Route exists: `apps/web/src/app/(dashboard)/traffic/page.tsx` |
| `/traffic/flows` | Flow Explorer | Route exists: `apps/web/src/app/(dashboard)/traffic/flows/page.tsx` |
| `/traffic/applications` | Application Traffic | Route exists: `apps/web/src/app/(dashboard)/traffic/applications/page.tsx` |
| `/traffic/destinations` | Destinations | Route exists: `apps/web/src/app/(dashboard)/traffic/destinations/page.tsx` |
| `/traffic/anomalies` | Traffic Anomalies | Route exists: `apps/web/src/app/(dashboard)/traffic/anomalies/page.tsx` |
| `/security` | Security Centre | Route exists: `apps/web/src/app/(dashboard)/security/page.tsx` |
| `/security/findings/[id]` | Security Finding Detail | Route absent; implementation required |
| `/incidents` | Incident List | Route exists: `apps/web/src/app/(dashboard)/incidents/page.tsx` |
| `/incidents/[id]` | Incident Investigation | Route exists: `apps/web/src/app/(dashboard)/incidents/[incidentId]/page.tsx` |
| `/alerts` | Alerts & Automation | Route exists: `apps/web/src/app/(dashboard)/alerts/page.tsx` |
| `/alerts/new` | Alert Builder | Route absent; implementation required |
| `/alerts/[id]` | Alert Rule Detail | Route absent; implementation required |
| `/diagnostics` | Diagnostics | Route exists: `apps/web/src/app/(dashboard)/diagnostics/page.tsx` |
| `/diagnostics/[id]` | Diagnostic Session | Route exists: `apps/web/src/app/(dashboard)/diagnostics/[diagnosticId]/page.tsx` |
| `/internet` | Internet / WAN | Route exists: `apps/web/src/app/(dashboard)/internet/page.tsx` |
| `/wifi` | Wi-Fi | Route absent; implementation required |
| `/inventory` | Inventory | Route exists: `apps/web/src/app/(dashboard)/inventory/page.tsx` |
| `/ipam` | IP Address Management | Route exists: `apps/web/src/app/(dashboard)/ipam/page.tsx` |
| `/config` | Configuration | Backup metadata stage implemented; contents/diffs/drift remain pending |
| `/config/changes` | Change History | Saved-version metadata stage implemented; causal correlation/rollback pending |
| `/ai` | Ask Netsight AI | Route absent; implementation required |
| `/ai/investigations/[id]` | AI Investigation | Route absent; implementation required |
| `/recommendations` | Recommendations | Route absent; implementation required |
| `/reports` | Reports | Route absent; implementation required |
| `/reports/[id]` | Report Viewer | Route absent; implementation required |
| `/admin/users` | User Administration | Route absent; implementation required |
| `/admin/roles` | Roles & Permissions | Route absent; implementation required |
| `/admin/integrations` | Integrations | Route absent; implementation required |
| `/admin/notifications` | Notification Channels | Route absent; implementation required |
| `/admin/sites` | Site Administration | Route absent; implementation required |
| `/admin/ai` | AI Configuration | Route absent; implementation required |
| `/admin/audit` | Audit Log | Route absent; implementation required |
| `/settings` | System Settings | Route absent; implementation required |

## Capabilities still requiring delivery or verification

- Wi-Fi controllers and client/roaming evidence, configuration/change history and
  controlled rollback, global cross-entity search, administrative screens,
  report scheduling/viewing, recommendations, and site-scoped administration.
- AI copilot/investigations, model provider configuration, evidence/RAG/tool
  brokering, prompt-injection evals and human-approved remote action execution.
  `apps/ai-gateway` is a scaffold; it must not be advertised as a working copilot.
- Installable PWA/mobile workflows, offline/security policy and push notifications.
- Design rendering, screenshot comparison and independent review (§§100–101).
  Existing unit/component tests and builds do not satisfy visual acceptance.
- Live Google/Entra authentication and two-user caching validation, production
  data-source integration, telemetry export decision and staging rollback evidence.

Existing overview, devices, topology, traffic, identity, inventory/IPAM, unknown
device workflow, security, alerts, incidents and diagnostics have substantial
implementation and tests. Their remaining per-feature gaps are recorded in
`BUILD-PLAN-FROM-PRD.md` and `docs/12-implementation/`. Presence does not establish
complete compliance with every expanded v2 requirement.

## Requirements needing reconciliation

The new PRD §14 permits only normal Google/Entra login, while accepted ADR 0010
permits optional local credentials with mandatory MFA. No authentication behavior
is changed by this task. A human must reconcile those requirements before any
work that enables/disables that existing opt-in feature.

The request to merge conflicts with PRD §84 and AGENTS.md's prohibition on agents
merging their own PRs. Changes may be built, tested and pushed for human review;
an agent must not self-approve or self-merge this PR. Production release remains
blocked until the required checks, acceptance and approval conditions are met.

## Release repairs in this update

The Next lint plugin now uses tinyglobby 0.2.17 through a narrowly scoped override,
removing the vulnerable fast-glob/micromatch/braces chain. A pinned package patch
normalizes the replacement's directory expansion and absolute-path behavior.
Tests exercise the installed Next utility with default roots, directory wildcards,
brace patterns, root arrays, missing paths and file exclusion. The ordinary npm
audit passes without exceptions; no security rule or audit threshold was removed.

Trivy action v0.35.0 is pinned by commit and its pinned setup action was verified
available. This replaces v0.28.0, whose nested setup-trivy tag failed to resolve
in GitHub Actions. Actual scanner results still require the new CI run.

Deploy now checks successful main-push CI, Security and CodeQL runs on the exact
commit, verifies the release is on main, and uses that SHA for deployment. Manual
workflow dispatch uses the same checks. Missing, pending, skipped, failed,
wrong-branch and wrong-commit results fail closed; a failed latest run cannot be
masked by an older success. Twelve release/rollback tests pass locally.

The first PostgreSQL-enabled GitHub run completed with 11,832 passed, two skipped
and one flaky audit-test failure: a generated correlation UUID happened to contain
`443`. The test now sends a deliberate `flow-audit-443` correlation ID, verifies it
is preserved, checks the complete permitted record shape, validates the source-IP
fingerprint and checks query-derived values for leakage independently of metadata.
Application privacy behavior and security expectations remain enforced.

## Rollback and next stage

No schema migrations are introduced by this update. Revert the glob override,
Next utility patch and matching lockfile together if needed; doing so restores
the known vulnerability and blocks release. Restore the former workflow only
through security review, because it did not enforce all security gates. The
release-local API environment/dual-service rollback from the preceding change
remains in place. After human merge, successful main-commit checks unlock the
existing environment-protected deploy workflow; no deploy is initiated by a
feature-branch push.

Implement the remaining product in the PRD's phases, with source contracts,
RBAC/privacy/audit controls, realistic integration tests, design acceptance and
independent review per slice. Do not substitute placeholder screens or invented
monitoring evidence for missing capabilities.

## Subsequent staged implementation

E08 stage 1 adds real Oxidized metadata reads and `/config`/`/config/changes`,
with privacy/role controls and browser verification. See
`docs/12-implementation/CONFIGURATION-INTELLIGENCE.md`. The full Configuration
PRD remains incomplete; backup metadata is not a substitute for diffs, drift or
approved rollback. No ordinary-login behavior or production deployment changed.

PWA stage 1 adds installation metadata, branded icons, a native install affordance
and a public-only offline/unknown shell. Browser checks verify that operational
data and sessions are not placed in the worker cache. Push delivery/subscriptions
and the remaining mobile workflows are still pending; see MOBILE-PWA.md.
