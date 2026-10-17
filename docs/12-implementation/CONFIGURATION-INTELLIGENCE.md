# Configuration intelligence — stage 1: backup metadata and version history

Ownership: configuration domain and Oxidized adapter (E08; PRD v2 §§47–50).
This stage is read-only. It implements backup status and saved-version metadata,
not configuration-content viewing, diffs, drift detection, causal correlation or
rollback execution. Those remain separate stages with their own security gates.

## Source boundary and contracts

The adapter uses the upstream Oxidized endpoints `/nodes.json` and
`/node/version.json?node_full=<group/name>`, verified against oxidized-web's
`lib/oxidized/web/webapp.rb` and Oxidized's Git output implementation. Only node
name, group, model, backup-attempt status/time, saved commit ID and timestamp are
mapped. Node credentials/vars, configuration text, commit messages and author
identities are never returned. Canonical IDs are UUIDv5 under an Oxidized-specific
namespace; nodes are not joined to LibreNMS/NetBox devices by guessed hostname.

Canonical JSON schemas are `configuration-nodes.schema.json` and
`configuration-versions.schema.json`. OpenAPI documents both routes, errors,
no-store behavior and pagination. Pydantic, JSON Schema and TypeScript share 22
contract vectors. Additional model/parser invariants enforce unique identifiers,
page bounds and source-state coherence.

`GET /api/v1/config/nodes` and
`GET /api/v1/config/nodes/{node_id}/versions` accept only `page` and `page_size`.
Unknown and repeated parameters are rejected. Page size is 1–100, default 50.
The adapter reads at most 2,000 rows; any larger source is explicitly truncated
and its total is withheld. A partial result counts skipped/duplicate/unsafe rows.
All-invalid source rows become unknown. An empty successful read remains distinct
from not-connected or unknown. A node missing from a partial inventory cannot
be falsely reported as a definitive 404.

A successful backup older than 24 hours is labeled stale; never/failed/untimed
backups have unknown freshness. This is a display convention, not a monitored
alert rule or an assertion about current running configuration. The source read
time is separate from backup time. Configuration matching and incident causality
are never inferred from backup metadata alone.

## Deployment configuration

Set `OXIDIZED_BASE_URL` to the internal Oxidized HTTP API or its authenticating
reverse proxy, preserving any deployment path prefix. HTTPS is required except
for loopback. `OXIDIZED_TOKEN`, if needed by that proxy, is sent server-side as a
Bearer credential. Credentials are never embedded in the URL, sent to the browser,
or recorded in the data/audit output. Keep Oxidized private; do not expose its
management/reload/backup-trigger endpoints publicly. Prefer a reverse-proxy
identity restricted to the two GET endpoints above.

Each source operation has a 12-second deadline, five-second HTTP timeout, two-MiB
decoded body cap and at most one retry for 502/503/504. Four non-waiting process-wide
source slots bound concurrent operations; API reads are limited to 60 per identity
per minute. These are per-process limits, not distributed cluster guarantees.
Redirects and compressed responses are refused. All source errors become unknown;
upstream error bodies and exception messages are never exposed.

## Authorization and privacy

`configuration:read` follows the existing Config history RBAC row: Administrator,
Network Engineer, Security Analyst, Technician and Auditor; Management denied.
The backend independently authorizes every request before reading source data.
Every completed/refused read is audited with static action/reason, actor, state
and row count, without source names/addresses/credentials in audit details.
Unknown source reads are audited as failures. Success, authentication/permission
errors, validation errors and rate-limit errors are non-cacheable.

Threat-model delta: a newly configured server-to-server HTTP source and hostile
source JSON. Controls include TLS, no redirects, fixed endpoint paths, strict
node selection via canonical ID, bounded response/time/row/concurrency limits,
selected metadata only, output encoding, role checks, read auditing and no-store.
The operator-selected base URL is a trusted deployment setting; it is never a
browser-controlled destination. This metadata integration adds no remote writes.

## UI and validation

`/config` shows paged backup metadata; selecting a node opens
`/config/changes?node=<canonical ID>`. Both pages enforce reported session
permissions before fetching protected data. Loading, empty, partial, stale,
not-connected, unknown, permission, authentication and transport errors are
explicit. Desktop uses the established AdminLTE shell and table; mobile uses
cards to prevent long revision hashes from overflowing the page. Source text is
rendered as text. No restore or generic command control is exposed.

No configuration-specific approved screenshot exists. Layout follows
SCREEN-SPECS Configuration and the existing shell, with the Devices reference
inspected for density/table structure. Local Chromium screenshots and navigation
checks use an explicitly synthetic Oxidized fixture and real API/session routes.
They establish rendered behavior and role denial, not final independent design
acceptance or real-device compatibility.

Local validation: 54 focused adapter/API/contract tests; 26 TypeScript parser and
shared-vector tests; full backend 11,076 passed/798 skipped before the last three
adapter/pagination tests and 22 vector tests were added (those pass separately);
full web unit suite, 534 component tests after mobile repair, strict frontend
and backend typing, Ruff/ESLint, production build and repository security policy.
Full PostgreSQL execution and scanner checks for the stage must run on GitHub.

## Rollback and remaining work

No database migration or persisted configuration content. Unset
`OXIDIZED_BASE_URL` to return to not-connected. Revert the configuration router,
permission/menu and UI registration together to remove the feature; no upstream
state has changed. No production service was contacted in local tests.

Next configuration stages: live-version fixture verification against the deployed
Oxidized release; approved secret-redaction/export policy before any config body
or diff is exposed; safe two-version comparisons; intentional-baseline drift
comparison; source-backed change/incident correlation; policy-controlled rollback
requests with step-up/approval/idempotency/verification. None is implied by a
backup timestamp or a successful metadata read.

Follow-up: the adapter now uses the upstream `full_name` to disambiguate
ungrouped nodes: oxidized-web substitutes the display group `default` even when
the real lookup has no group. Ambiguous default-group rows without `full_name`
fail closed rather than querying the wrong node. A new adapter regression test
verifies the upstream `node_full` query; the focused backend suite now has 55 tests.
