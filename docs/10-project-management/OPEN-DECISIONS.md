# Open decisions (human owner)

Every "human decision pending / needed" recorded in `docs/00-product/BUILD-PLAN-FROM-PRD.md`, `docs/12-implementation/*`,
`docs/02-security/RBAC-MATRIX.md` and `docs/06-data/DATA-RETENTION-MATRIX.md`, in one place.

* **Recommended default** is a proposal for the owner to accept or change. It is *not* applied. Where the table says "none", nothing is
  recommended because the answer depends on facts only the owner has (a contract, a deployment, a legal opinion).
* **Current behaviour** is what the code does today. Nothing here was changed to the recommended default, except the items marked
  **changed 2026-10-18** (D-25, D-50 and the export-route guard in the last section) (they were decided as engineering follow-ups, not policy; see the last section).
* Decisions already taken (for example the 2026-10-10 step-up and Management summary decisions, and the `diagnostics:read` narrowing)
  are not repeated; the documents that record them stay authoritative.
* Authority order is `AGENTS.md`: a decision that touches security or privacy goes through an ADR or a requirement correction.

## 1. Privacy, retention and legal (blocks any persistence of history)

| ID | Decision | Recommended default | Current behaviour | Source |
|---|---|---|---|---|
| D-01 | Privacy/legal policy (PRD 92) for keeping and showing per-person network history (MAC, IP, port, user) | Commission the review before any role other than Administrator browses people or any history is persisted | No such policy exists. Administrator and Network Engineer browse people; nothing is persisted for identity; unknown-device findings are stored with MAC/IP/port | PRD 92, RBAC-MATRIX (Identity), BUILD-PLAN E07/E08 |
| D-02 | Retention of unknown-device findings and timeline | 12 months for findings, 24 months for the append-only timeline of closed findings; audited prune by the migrator | None set, no prune built, tables only grow | DATA-RETENTION-MATRIX, INVENTORY-IPAM |
| D-03 | Retention of diagnostic sessions (and whether free text is minimised sooner) | 12 months, free-text target and symptom expired at 90 days | None set, no prune built (the candidate range in the matrix is 90 days to 1 year) | DATA-RETENTION-MATRIX, THREAT-MODEL |
| D-04 | Retention of WAN probe samples and cycles; who runs the migrator partition drop; whether dispute exports are preserved separately | Cycles for the contract term plus the dispute window (owner to supply); raw samples shorter than cycles; exported months never dropped | None set, nothing scheduled, tables only grow | DATA-RETENTION-MATRIX, INTERNET-WAN |
| D-05 | Persistence and retention of identity correlation history | Keep none (compute on read) until D-01 is answered | Nothing stored; effective history is the sources' own retention, up to 7 days via `?at=` | IDENTITY-CORRELATION, DATA-RETENTION-MATRIX |
| D-06 | Retention of notification delivery attempts; approve or defer an audited prune | 90 days with an audited prune step | None set, no prune exists | BUILD-PLAN E05 |
| D-07 | Conversation retention for the AI copilot | None (do not store conversations) | None stored | AI-COPILOT |
| D-08 | Retention for any future history source for WAN utilisation and inventory growth (forecast) | Decide together with D-26 before building either series | Both series are `not-connected` | FORECASTING |

## 2. Roles and permissions (RBAC readings)

| ID | Decision | Recommended default | Current behaviour | Source |
|---|---|---|---|---|
| D-10 | Management in the Flow Explorer: aggregate-only (no rows, no address filters, no top talkers); what Technician "Limited" removes | Confirm aggregate-only for Management; keep Technician at none until a limited rung is designed | Management aggregate only; row access follows the `traffic:read-detail` grant in `rbac.py` | BUILD-PLAN E03, RBAC-MATRIX |
| D-11 | May any role besides Administrator see people in flow rows; may Auditor see endpoint rows | No, until D-01 | Endpoint rows need the `traffic:read-detail` grant (`rbac.py`); see RBAC-MATRIX for which roles hold it | BUILD-PLAN E03 |
| D-12 | Network Engineer holds `users:read` (browse people) or only the limited rung | Limited rung until D-01 is answered | Network Engineer holds `users:read` | RBAC-MATRIX (Identity) |
| D-13 | Auditor and `users:*` | Grant `users:read-summary` (counts) only | Auditor holds no `users:*` permission | RBAC-MATRIX (Identity) |
| D-14 | Site and security scoping ("Scoped" for Network Engineer, "Security scope" for Security Analyst, "Basic" for Technician diagnostics, per-owner scoping of sessions) | Introduce site scoping as an ADR before any role is narrowed | No scoping exists; those roles see everything their permission allows | RBAC-MATRIX, BUILD-PLAN E04/E06 |
| D-15 | Technician and maintenance windows; Management and alert rules | Technician: read-only maintenance windows; Management: none | Alert rules "No" for Management per the matrix; maintenance read/write grants are as set in `rbac.py` (see `_ALERTING_READ` and the maintenance write sets) | BUILD-PLAN E05 |
| D-16 | Reading incidents narrowed to assigned incidents | Keep all-incident read for operational roles | Not narrowed | RBAC-MATRIX (Incidents) |
| D-17 | `internet:read_detail` and export: should Technician and Auditor hold detail; Management hold the export; probe targets withheld from the export | Keep as is (detail: Administrator, Network Engineer, Security Analyst; export: Administrator, Network Engineer, Auditor); do not give Management the export | As described | BUILD-PLAN E04 (Internet) |
| D-18 | Unknown-device RBAC: Technician finding counts only, Auditor rows without comment, Management counts only | Confirm | Implemented as stated | BUILD-PLAN E08 |
| D-19 | Step-up on resolve and dismiss of an unknown-device finding | Keep step-up for resolve and dismiss | Step-up required for both | RBAC-MATRIX (Unknown devices) |
| D-20 | Configuration history RBAC (Technician and Auditor see the same redacted content) | Confirm | Not applicable on this branch: only upstream metadata is exposed (`configuration:read`: Administrator, Network Engineer, Security Analyst, Technician, Auditor; Management none). Redacted content/diffs were not integrated (see Integration notes) | CONFIGURATION-INTELLIGENCE |
| D-21 | `copilot:ask` for Management | None | Management holds none | AI-COPILOT |
| D-22 | Whether Technician may export the capacity report | No (no reporting role in the matrix) | Technician cannot export | FORECASTING |
| D-23 | Who may approve and execute actions; the matrix says "Policy" for Network Engineer and Security Analyst; whether a risk A/B requester may approve | Administrator-only for risk C and D; revisit A/B after a lab proves a real executor | Administrator holds `actions:approve`, `actions:execute`, `actions:kill-switch`; requester never approves (a risk D request needs two Administrators) | ACTION-ENGINE, RBAC-MATRIX |
| D-24 | Technician proposing risk B (`switch.port.enable`) | No | Per catalog and `actions:propose` grants | ACTION-ENGINE |
| D-25 | **May a requester execute their own request** (new, Step 12 review) | No | **changed 2026-10-18**: refused with `409 SELF_EXECUTION` unless `NETSIGHT_ACTIONS_ALLOW_SELF_EXECUTE` is set; default off. Dry runs are refused too, so a single-Administrator deployment cannot run its own request until the flag is set or a second person executes. The status contract exposes the flag (`policy.self_execute_allowed`) and the UI disables Execute for the requester with an explanation | ACTION-ENGINE |

## 3. Integrations and data sources

| ID | Decision | Recommended default | Current behaviour | Source |
|---|---|---|---|---|
| D-26 | Which source feeds WAN utilisation (LibreNMS port history or a stored snapshot) and inventory growth | LibreNMS port-history read for utilisation; a nightly inventory count snapshot (needs D-08) | Both series `not-connected` | FORECASTING |
| D-27 | Which Akvorado flow columns are populated (`Application`, `ApplicationCategory`, `ExporterName`, VLAN, country, AS, interface boundaries) | Inventory the real table first | A missing column degrades that feature to Unknown | BUILD-PLAN E03 |
| D-28 | Provide the operator traffic policy file (approved/unapproved applications, risk levels, destination allow/deny lists, working-hours zone and days) | None (owner data) | Nothing is classified without it | BUILD-PLAN E03 |
| D-29 | `SamplingRate`-scaled volumes (labelled) | No; keep bytes as stored | Bytes summed as stored | BUILD-PLAN E03 |
| D-30 | "Device" in the Explorer: exporter or inventory device | Exporter until an address-to-device join exists | Exporter | BUILD-PLAN E03 |
| D-31 | Create the ClickHouse reader profile of AKVORADO-CLICKHOUSE.md | Do it before first live connect | Not verifiable by the API | BUILD-PLAN E03 |
| D-32 | NetBox: role/type class map; the custom field joining Wazuh agents; contact roles meaning "uses this device" (default `Owner,User`); device role names for diagnostics (access point / access switch / core / firewall) | None (deployment data) | Fixed vocabulary or env-supplied; nothing classified without the map | BUILD-PLAN E07/E08/E04 |
| D-33 | Network classification of the real estate (NAT, VPN, guest, internal public blocks, server/static ranges); provision and rotate `NETSIGHT_IDENTITY_ID_KEY` | None (deployment prerequisite) | Required for identity answers | BUILD-PLAN E07 |
| D-34 | Probe targets and exporter locations per link; backup-link probing | None (deployment data) | Local prober only | BUILD-PLAN E04 |
| D-35 | Oxidized credentials and rotation; an approved reference configuration source for true drift | Read-only Oxidized account, rotated with the other service secrets | No drift detection (no reference source); upstream stage 1 reads metadata only | CONFIGURATION-INTELLIGENCE |
| D-36 | Which model/provider for the copilot and whether evidence may leave the host; model budgets; the knowledge corpus and its `roles:` headers | Local or in-region model first; evidence leaves the host only by explicit opt-in | Provider from env; unset is `not-connected` | AI-COPILOT |
| D-37 | Web Push provider and who runs the gateway/subscription store; SMTP relay and sender | None (infrastructure) | Provider-agnostic gateway, not built; email via env | BUILD-PLAN E05/E10 |
| D-38 | Notification routing table and minimum severity | A routing table in the database with per-severity rules | One flat list from the environment | BUILD-PLAN E05 |
| D-39 | Incident policy for a many-device outage (`group` vs `create`); webhook rule action; recovered alert annotating an incident; internal (private-network) webhook targets | Default `group`; no webhook rule action until secret storage exists; annotate, never resolve | `create` opens one incident per device (up to 100 per cycle); webhooks unreachable from rules; no bypass for private targets | BUILD-PLAN E05 |

## 4. Policy constants and thresholds

| ID | Decision | Recommended default | Current behaviour | Source |
|---|---|---|---|---|
| D-40 | Baseline constants (4 weeks, at least 3, threshold 3.5, at least 10 MiB, 10 % noise floor, 7 days first-seen) and operator-tunability | Keep; make tunable only after a live run shows the need | Fixed constants | BUILD-PLAN E03 |
| D-41 | Minimum cohort `k` (5) and whether Management sees in-organisation destinations | k = 5; Management sees none | k = 5; Management aggregate only | BUILD-PLAN E03 |
| D-42 | Audit fingerprints of endpoint lookups on by default and the key (`NETSIGHT_AUDIT_FILTER_KEY`, rotation) | On, key from the secret store, rotated yearly | As stated | BUILD-PLAN E03 |
| D-43 | SLA definitions: degraded counts as reachable, 1.5x coverage grace, reachability-only cycle state, closed-month settling hour, per-link `uptime_target_pct` | Take them from the ISP contract | As stated; target per link from configuration | BUILD-PLAN E04 |
| D-44 | Whether SLA evidence needs signing or independent attestation | Defer until a dispute needs it | Only as trustworthy as the recording host | BUILD-PLAN E04 |
| D-45 | Identity trust TTLs and thresholds (open session 15 min RADIUS/VPN/Wi-Fi/MAC table, DHCP 1 h, agent and sign-in 30 min, directory/assignment 24 h; observed >= 0.8; inferred cap 0.7) | Keep | As stated | BUILD-PLAN E07 |
| D-46 | Unknown-device stale window (24 h), severity policy and `quarantine_recommended_at` threshold, scheduled scan on or off and its interval | 24 h; severity policy from the owner; scheduled scan off until the policy exists | Stale 24 h; nothing classified without a severity policy; scan on request only | BUILD-PLAN E08 |
| D-47 | Configuration stale threshold (48 h) and the risk rule catalogue and severities | Keep 48 h; review the six rules with the network team | Not applicable on this branch: upstream labels a successful backup older than 24 h stale; no risk rules (see Integration notes) | CONFIGURATION-INTELLIGENCE |
| D-48 | Action approval and run windows (24 h / 1 h) and default isolation duration (60 min) | Keep | As stated | ACTION-ENGINE |
| D-49 | Forecast: daily traffic limit and how it relates to link capacity; growth (20 %) and weekend (60 %) rule thresholds | Limit from the ISP contract or link rating; keep 20 % and 60 % | Limit only from `NETSIGHT_FORECAST_TRAFFIC_DAILY_LIMIT_BYTES`; thresholds fixed | FORECASTING |
| D-50 | **Forecast partial-day rules**: a newest day is partial when its last flow is more than 1 h before midnight; a day is an outage day when fewer than 22 of 24 UTC hours held a flow | Keep (22 h and 1 h are engineering judgement) | **changed 2026-10-18**: such days are excluded and counted as missing, never shown as measured | FORECASTING |
| D-51 | Whether a scheduled/archived capacity report, PDF/Excel and an inventory report are wanted | No until a consumer asks | Synchronous CSV only | FORECASTING, REPORTING |
| D-52 | Executors: which action types get a real executor, in which order, and the lab that proves them | None until a lab exists | Dry-run executor only; no live executor | ACTION-ENGINE |
| D-53 | Where the durable action store lives | PostgreSQL, behind the `ActionStore` Protocol | **built**: PostgreSQL (migration 0007) when `DATABASE_URL` is set, in-memory (lost on restart) otherwise; retention of requests and history is a separate pending decision (DATA-RETENTION-MATRIX) | ACTION-ENGINE |

## 5. Deployment and security posture

| ID | Decision | Recommended default | Current behaviour | Source |
|---|---|---|---|---|
| D-60 | Page CSP and HSTS policy for the web app | Strict CSP with nonces; HSTS preload only after a stable HTTPS period | `next.config.mjs` sets baseline headers on every route and a tight CSP only on `/sw.js` and `/offline.html`; no page CSP, no HSTS decision recorded | MOBILE-PWA |
| D-61 | A mobile home combining health/WAN/incidents/alerts/top traffic before approvals | No; approvals wait for the Action Request mobile design | Not built | MOBILE-PWA |
| D-62 | Exporter authentication for diagnostic probes (mTLS or a management network) and egress policy | Management network plus mTLS | Exporters carry no authentication | BUILD-PLAN E04, BLACKBOX |
| D-63 | Tamper-evident audit store (PRD 32) | An append-only sink outside the application host | Operational log sink | ACTION-ENGINE, BUILD-PLAN |
| D-64 | Approved designs for the Explorer sub-pages, `/internet`, the unknown-device pages and the configuration, copilot and mobile pages (the repository has none) | Commission designs, or accept the current ones explicitly | Built to AGENTS.md UI rules without an approved design | BUILD-PLAN E03/E04/E08/E09/E10 |
| D-65 | Icon artwork for the PWA | Supply final artwork | Upstream-supplied `netsight-192/512` icons | MOBILE-PWA |
| D-66 | Shared (cross-worker) rate limits, caches and kill switch | Redis-backed once more than one worker runs | Per-process | BUILD-PLAN (several) |
| D-67 | Secret storage for webhook URLs and headers once persisted | Secret manager reference, never the database | Environment only | BUILD-PLAN E05 |

## Changed 2026-10-18 (engineering follow-ups, not policy)

1. **D-25** requester cannot execute their own request unless `NETSIGHT_ACTIONS_ALLOW_SELF_EXECUTE` is set (default off).
2. **D-50** forecast days with a stopped collector or silent hours are excluded, not shown as measured.
3. Export routes (`/internet/export`, `/forecast/export`) now refuse a request that has no `Sec-Fetch-Site` and no matching
   `Origin`/`Referer` (previously a header-less request was allowed). Non-browser clients must send a same-site `Origin`.


## Accepted defaults (2026-10-19)

The owner chose "adopt recommended defaults" for the low-risk, offline decisions. In each case the recommended default equals
the current behaviour, so no code changed. These stay revisitable.

- **D-20** (not applicable on this branch: redacted configuration content was not integrated; see Integration notes.)
- **D-21** Management holds no `copilot:ask`.
- **D-22** Technician cannot export the capacity report.
- **D-24** Technician cannot propose risk B actions beyond the catalogue grants.
- **D-40** Baseline constants stay fixed.
- **D-45** Identity trust TTLs and thresholds stay as stated.
- **D-47** (not applicable on this branch: upstream configuration stage 1 has a 24 h stale label and no risk rules; see Integration notes.)
- **D-48** Action approval and run windows (24 h / 1 h) and the 60 min isolation default stay.
- **D-49** Growth (20 %) and weekend (60 %) thresholds stay; the traffic limit remains owner data.
- **D-50** Partial-day tolerances (1 h and 22 of 24 UTC hours) stay until checked on real flow data.
- **D-51** No scheduled or archived capacity report, PDF/Excel or inventory report until a consumer asks.

Deliberately not adopted (privacy, security or infrastructure choices): D-01 to D-08 retention and privacy, D-23 approver
policy, D-36 model provider, D-37 push and SMTP, D-41 and D-42 cohort and audit-key policy, D-52 and D-53 executors and the
durable store.

## Accepted defaults (2026-10-26)

The owner chose "adopt the recommended default" for the decisions held back on 2026-10-19. They stay revisitable.

- **Build next (audited prune by the migrator):** D-02 (findings 12 months, closed-finding timeline 24 months), D-03 (diagnostic
  sessions 12 months, free text expired at 90 days), D-06 (notification delivery attempts 90 days).
- **D-04** adopted in shape (cycles kept for the contract term plus dispute window, raw samples shorter, exported months never
  dropped), but the contract term is owner data, so no prune is built until it is supplied.
- **Keep nothing / build nothing, equal to current behaviour:** D-05 (no identity history stored), D-07 (no conversations stored),
  D-08 (decide with D-26 before any series), D-23 (Administrator-only approval and execution), D-36 (local or in-region model,
  evidence leaves the host only by opt-in), D-37 (no push provider), D-41 (k = 5, Management sees none), D-42 (fingerprints on,
  key from the secret store), D-52 (no live executor), D-53 (PostgreSQL, already built).
- **D-01** (privacy/legal review) is not a default that can be adopted: it stays a precondition before any role other than
  Administrator browses people or identity history is persisted.

## Integration notes (2026-10-19, branch `integrate/steps-9-13`)

The local Configuration Intelligence (Step 9: redacted configuration text, diffs, risk findings, change timeline, `config:read`)
was not integrated. Upstream already ships a reviewed metadata-only stage 1 (`configuration:read`, `/config/nodes`), which states
that content viewing, diffs and drift are separate stages with their own security gates. Reintroducing content fetching would
contradict that boundary and duplicate its routes, permission and pages. Those pieces remain on local `main` and need an explicit
decision (and an ADR, since they read device configuration text) before being ported onto the upstream adapter. Only the
configuration redactor (`configuration/redact.py`, `text.py`) was kept, because the copilot sanitiser uses it. The copilot's
`get_recent_config_changes` tool was removed for the same reason. D-20, D-47 and the "skipped Oxidized nodes" note therefore
describe code that is not on this branch.
