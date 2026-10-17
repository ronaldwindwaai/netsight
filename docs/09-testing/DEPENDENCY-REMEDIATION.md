# Dependency remediation and release gates

Status: local implementation, 17 October 2026. All ten dependency PRs remain on hold.

Update: the subsequent PRD v2 release-readiness change removes the braces chain
entirely via the scoped tinyglobby override and Next utility compatibility patch;
the standard npm audit now reports no known vulnerabilities. It also replaces
Trivy's broken nested action reference and adds exact-commit deployment gates.
See `docs/00-product/PRD-V2-GAP-ASSESSMENT.md`. Historical validation and the
original findings below describe the preceding revision, not current audit status.
No PR has been merged, approved, rebased, or deployed by this work.

## Implementation

| PR | Local treatment |
| --- | --- |
| #2 PyJWT | Minimum 2.15.1; locked runtime remains 2.15.1. Required claims and custom JWKS validation strengthened. |
| #3 QR-code types | Minimum 8.2.0.20260518; existing matching resolution retained. |
| #4 Hatchling | Build and dev minima 1.32.4; existing matching dev resolution retained. Built and installed wheel verified. |
| #10 Next.js | Next and eslint-config-next pinned together at 16.4.0. |
| #1 FastAPI | Minimum 0.143.0; lock resolves 0.143.3. Telemetry export remains an explicit deployment decision. |
| #7 OpenCode | Plugin 2.0.27; ECC V2 build, import, hook registration, and basic permission decisions verified. |
| #5 pytest | Minimum 9.1.1; pytest-asyncio upgraded from 0.26.0 to 1.4.0 because the old plugin requires pytest <9. |
| #9 Node types | Both packages use Node 24 declarations (locked 24.19.2), matching CI/runtime. Node 26 migration deferred. |
| #6 ESLint | Retain major 9; do not install the demonstrated incompatible ESLint 10 stack. |
| #8 TypeScript | Retain 5.9.3 using a ~5.9.3 range; TS7 requires a separately verified parser/plugin and compiler-API migration. The OpenCode build uses the TypeScript JavaScript API. |

Python CI now synchronizes the reviewed uv.lock with `--locked --extra dev`, rather
than resolving an editable pip install anew. Deployment also checks the lock and
installs a non-editable API into a release-local environment. Dependency auditing
exports the locked production requirements with hashes. Python auditing has its
own job, so an npm audit failure cannot prevent it from running.

The deploy workflow description is valid YAML. Trivy uses the verified upstream
`v0.28.0` tag. The Python CI job now supplies an isolated PostgreSQL 16 service via
NETSIGHT_TEST_PG_DSN, enabling the existing database tests instead of silently
omitting them. Existing Ruff failures were corrected without removing checks or
changing hostile-character fixture values.

## Security findings

- GHSA-ch52-4w7c-c8xp: http-cache-semantics forced to fixed 4.3.0; the finding is
  absent from the new npm audit.
- GHSA-vfj7-8cjw-p6xm: braces 3.0.3 has no published patched release in the queried
  registry. A pnpm patch caps combined brace/parenthesis nesting before recursive
  compilation/expansion/stringification. Regression tests resolve braces through
  the actual Next lint dependency chain. This is a local mitigation for string
  pattern input, not a claim of upstream advisory closure or protection for
  callers constructing arbitrary ASTs. The normal high/critical audit threshold
  remains enabled and still fails on this finding. Do not merge until a fixed
  dependency is available and validated, or the security owner explicitly
  resolves the finding under the existing security policy.
- The Python runtime dependency audit reports no known vulnerabilities.

OIDC requires iss, aud, sub, exp, iat, and nonce; bounds token length; converts
malformed keys and recursively malformed JSON into controlled authentication
errors; and matches Entra v2 issuer URLs exactly. The HTTP client no longer follows
redirects. JWKS URLs must be HTTPS on the approved Google/Entra public hosts,
without credentials, explicit ports, or fragments. JWKS documents are streamed
with a 256 KiB decoded size cap and at most 100 dictionary keys. Failed documents
are not cached as valid data. The existing one-hour key-cache TTL is retained:
an unknown kid fails closed and does not force an attacker-triggered refresh.
Operators must account for that TTL during provider key rotation. These controls
do not rely on PyJWT's separate PyJWKClient implementation.

## Local validation

- Node 24; frozen install using the declared pnpm 12.8.1.
- Frontend lint, strict TypeScript check, unit suite, 522 component tests, Next
  production build; OpenCode build/import and local hook/permission smoke tests.
- Baseline pytest 8.4.2: 11,008 passed, 798 skipped (11,806 collected).
- After 24 additional auth cases: pytest 9.1.1 + pytest-asyncio 1.4.0:
  11,032 passed, 798 skipped (11,830 collected). The collection increase matches
  the added cases; no baseline cases were removed. Three subsequent auth cases
  (padded valid tokens, JWKS size/cache expiry, malformed signing keys) were
  checked in the focused suite, separately from that full-suite result.
- Ruff and mypy (189 source files), actionlint 1.7.11, shell syntax, repository
  security policy, npm and locked Python dependency audits.
- Wheel built, installed into a clean environment with the exported locked
  runtime requirements, API imported, six forward migrations found, rollback SQL
  absent. Existing wheel/migration tests also ran in the backend suite.
- Deployment orchestration tested with fake services: successful candidate and
  API-health failure; previous API environment preserved and both services
  restarted on rollback. No VPS access occurs in these tests.

The 798 local skips include database/external-service scenarios. PostgreSQL is
provisioned in the updated CI configuration but was not available for a local
live run. GitHub-hosted CI, Trivy, CodeQL and gitleaks were not executed here.
Local plugin smoke tests do not establish full OpenCode host compatibility.

## Deployment and staging gates

FastAPI 0.143 disables automatic OpenTelemetry exporter configuration by default.
Keep that default unless automatic export is intended. If intended, explicitly
set `FASTAPI_OTEL_AUTO_CONFIGURE=true` in the API service environment, configure
the exporter, and prove expected export in staging. Check for duplicate spans
with any external instrumentation and for sensitive token/identity attributes.
Do not enable telemetry export merely to preserve an unverified historical default.

Before release, exercise real Google and Entra login/callbacks, nonce/state,
secure cookies, logout, protected navigation, server actions, and browser back
navigation under a production build. Use two distinct authenticated users and
verify that protected content is never served across sessions. Unit/component
coverage and local HTTP checks do not replace these provider/browser checks.
Run PostgreSQL CI, all security workflows and contract checks on the exact reviewed
revision. Keep #6/#8 on hold until the entire lint/compiler stack supports them;
never suppress rules or relax strict checking to migrate.

## Rollback and migration

There are no database schema changes. Each new release installs its own
`apps/api/.venv`; the API unit resolves it through `current`. The previous release
and lockfiles remain available. Health checks cover both web and API; a failed
restart or health check switches `current` back, restores the previous API unit
(including compatibility with older shared-venv releases), reloads systemd and
restarts both services. Keep the old shared API venv until the migration is
accepted so rollback to an older release remains possible. Test real systemd/VPS
rollback in staging; the local tests use fake services.

Follow-ups: published braces fix; supported ESLint 10/TS7 migration; PostgreSQL
CI evidence; full host plugin validation; real OIDC/two-user browser checks;
telemetry deployment decision and staging rollback evidence. Keep runtime and
test-runner dependency reviews separate when applying these changes to the
existing PR branches, regenerate/review both locks, and rerun checks after each
integration. This combined working tree is not approval of any existing PR.
