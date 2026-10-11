# Internet / WAN (PRD 21; Step 5)

Read-only WAN status, quality and availability from two sources, plus a deterministic monthly SLA and
an evidence export for ISP disputes. Nothing is fabricated: every field is source-reported or `null`,
an absent source is `not-connected`, a failing one `unknown`, and stale data is labelled with the
source's own freshness.

Contracts: `contracts/json-schema/internet.schema.json`, `internet-sla.schema.json`, the OpenAPI
components `InternetResponse`, `Wan*`, `InternetSla*`, pydantic `schemas_internet.py`, TS parsers
`api-contracts-internet.ts`; four-way agreement through `contracts/test-vectors/internet.vectors.json`.

## Surfaces

| Route | Permission | Notes |
| --- | --- | --- |
| `GET /api/v1/internet` | `internet:read` (detail: `internet:read_detail`) | per link: configured ISP/gateway, status, interface block (LibreNMS), quality block (probe samples), availability block (rolling 24 h), failover. Without `internet:read_detail` the ISP name, gateway, public IP and per-link throughput are `null` and `detail_redacted` is `true` |
| `GET /api/v1/internet/sla?month=YYYY-MM` | `internet:read` | deterministic month figures (`windows_truncated` says when the export would be cut); 30 requests/min/identity |
| `GET /api/v1/internet/sla/export?month=&format=json\|csv` | `internet:export` (ISP name: `internet:read_detail`) | bounded evidence; 10 requests/min/identity; audited (`internet.export`) |
| `/internet` (web) | `internet:read` | status, SLA panel with month picker, export links |
| `/internet/export` (web route) | forwards the session | read-only download, cross-site requests refused |

Months are server-bounded: the current UTC month and the 24 before it; anything else is a 422. The
instant a month starts is an empty period (zero seconds, nothing known, no violation), not an error.

### Detail permission (`internet:read_detail`)

Held by Administrator, Network Engineer and Security Analyst; **not** by Technician, Management or
Auditor, who get status, quality, availability and the SLA summary. The API (not the browser) withholds
the ISP name, gateway, public IP and per-link throughput (rx, tx and the utilisation derived from them)
as `null` with `detail_redacted: true` (JSON Schema, OpenAPI, pydantic and the TS parser reject a
redacted response that still carries one). The UI shows "Restricted", never "Not reported", for them.
The export withholds the ISP name the same way (an Auditor can export the evidence without it).
Capacity is kept: it is the link's rating, not usage. Decision recorded in RBAC-MATRIX.

## Declaring links (operator, never inferred)

`NETSIGHT_WAN_LINKS` is a JSON array (at most 8; at most one `primary`). Netsight never guesses which
interface is a WAN link, who the ISP is or what the gateway is.

```json
[{"id": "fibre-1", "name": "Primary fibre", "role": "primary", "isp": "Example ISP",
  "gateway": "192.0.2.1", "librenms_device": "12", "librenms_port": "345",
  "probe_targets": ["probe-a.example"], "probe_location": "branch",
  "dns_target": "dns-check.example", "uptime_target_pct": 99.5}]
```

Unset = `not-connected`. Any invalid entry makes the whole declaration `unknown` (a half-parsed list
could mislead the failover reading); the log carries a count, never the content. `isp`, `gateway` and
`probe_location` are labelled "configured" in the API and UI, not telemetry. `uptime_target_pct` is the
contract value from the ISP's SLA; without it no violation is ever stated.

## Sources and what each may say

* **LibreNMS** (existing read-only adapter, `wan_port`): operational status, link speed (capacity),
  in/out octet rates (x8 = bps), the source's own `poll_time` (freshness) and the public IPv4. A
  missing, malformed or negative counter is `null`, never zero. The public IP is set only when the
  port has exactly one globally routable IPv4 address (private, shared, documentation or ambiguous
  answers are not a public IP). A failing address lookup loses only the address. Counters older than
  15 minutes are shown labelled `stale`; with no poll time, `unknown`.
  Verify on a real LibreNMS: the ports list must carry `ifInOctets_rate`, `ifOutOctets_rate` and
  `poll_time` (if the deployment's default columns omit them, throughput reads `null`, which is honest
  but unhelpful).
* **Probe samples** (existing allow-listed Blackbox clients, stored by the collector): latency (mean of
  passing reachability samples), jitter (mean absolute difference of consecutive latencies per target),
  loss (failed over passed-plus-failed; unknown is neither) and DNS over the last 15 minutes; rolling
  24-hour availability and the outage in progress. No store: `not-connected`; a failing store:
  `unknown`; no samples yet: `ok` but empty ("No probe samples yet", never zero loss).

Gateway reachability, route and the contracted capacity are **not** sources in this step (see
follow-ups); the gateway shown is the configured address.

## Inferred values (labelled `inferred`)

* **Link status** = the worst *current* evidence: interface `up` -> up; `down`/`lowerLayerDown`/
  `notPresent` -> down; `dormant`/`testing` -> degraded; probe round up/degraded/down. An interface that
  is up while every probe fails is **down** (the link is up but the Internet is not). A stale or
  undated interface reading and a lapsed probe round are not evidence; with none, `unknown`.
* **Failover** reads link status only (routing and the gateway are not read): one link -> `single-link`;
  primary up/degraded -> `normal`; primary down and a backup up/degraded -> `failed-over`; primary down
  and every backup down -> `all-down`; anything else (silent link, no primary) -> `unknown`.

## SLA arithmetic (deterministic, `wan/sla.py`)

* A **cycle** is one sampling round of one link. Its state comes from its *reachability* samples (`icmp`
  and `tcp`) only: all passed (unknown ignored) -> `up`; some passed, some failed -> `degraded`; all
  failed and none unknown -> `down`; otherwise `unknown`. DNS is reported separately.
* A cycle **covers** the time to the next cycle, at most its sampling interval plus half of it. Time no
  cycle covers is **unknown**: a gap in sampling is never counted as up or down.
* `uptime_pct = (up + degraded) / (up + degraded + down)` over *known* time (a degraded link was
  reachable); `null` when nothing was known; `coverage_pct` = known / month. Outages are runs of `down`
  coverage. A violation is `uptime_pct < uptime_target_pct` and is only stated when both exist.
* Every duration is whole seconds (cycle times are whole seconds; the database enforces it) and
  `up + degraded + down + unknown = total` **exactly**: when a window has fractional-second edges
  (a clock with microseconds) the rounding remainder is time nothing covered, so it is added to
  `unknown`.
* Two writers (a standby that briefly overlaps the leader): a cycle is cut at the next cycle, so
  interleaved cycles tile deterministically; two cycles stored for the same instant that agree count
  once, and two that disagree make that instant `unknown` (contradicting evidence proves neither
  state). The result never depends on input order.
* These choices (degraded counts as reachable; the 1.5x coverage grace; reachability-only state) are
  interpretations to confirm with the ISP contract: see "Human decisions".

## Storage (migration 0005, PostgreSQL per DATABASE-OWNERSHIP)

`wan_probe_samples` (raw evidence) and `wan_link_cycles` (per-round rollup; a CHECK pins `state` to the
counts, so a stored state can always be re-derived). Both are **range-partitioned by month** on
`sampled_at` (`wan_link_cycles_pYYYYMM`, `wan_probe_samples_pYYYYMM`, UTC months, no default
partition). A failed or unknown sample carries no latency (CHECK); a pass may carry none.

* **Append-only:** `BEFORE UPDATE OR DELETE` / `BEFORE TRUNCATE` triggers (`ENABLE ALWAYS`, the 0003
  function) on the parents **and on every partition** stop every role including the owner; a repeated
  `(link, time)` is a conflict, never an overwrite. A cycle and its samples are written in one
  transaction (samples with one `executemany`). **Deferred constraint triggers** check at COMMIT that
  a cycle's counts equal its stored reachability samples (also for a sample added to a stored cycle);
  the function is `SECURITY DEFINER` because the collector role cannot read.
* **Two runtime roles** (security review M1). The API role (`DATABASE_URL`) has `SELECT` only on the
  WAN tables; the collector role (`NETSIGHT_WAN_COLLECTOR_DATABASE_URL`) has `INSERT` only and
  nothing else. Neither can run DDL, so neither can create a partition. Grants: `grants/app_role.sql`
  and `grants/wan_collector_role.sql`, applied by `migrate up --app-role ... --wan-collector-role ...`
  (or `DATABASE_APP_ROLE` / `DATABASE_WAN_COLLECTOR_ROLE`). The roles must differ; neither may be a
  superuser, bypass row security or own the tables.
* **Partitions are a migrator step.** `python -m netsight_api.storage.migrate up` creates the current
  and next month; schedule `python -m netsight_api.storage.migrate partitions` (monthly; it is
  idempotent and takes `--months-ahead`) so the next month always exists. The helper
  `netsight_ensure_wan_partition(date)` is not executable by the runtime roles. **Fail closed:** a
  cycle whose month has no partition is rejected by the database; the collector logs
  `WAN sampling cannot write: no database partition exists ... run ... migrate partitions`, records
  nothing for the round (a gap, shown as unknown) and resumes when the partition exists.
* **Reads** are bounded and an over-large window is an error, never a silent cut: 5 000 samples, and
  cycles up to `cycle_read_cap(interval)` = 2 x (31 days / the configured sampling interval) + the
  look-back (about 89 k at the default 60 s, 179 k at 30 s). The API derives it from
  `NETSIGHT_WAN_SAMPLE_INTERVAL_SECONDS`; if the interval is raised after a dense month was stored,
  reading that month can exceed the new cap (an error, not a wrong figure).
* **Closed months are cached.** A month that ended more than an hour ago (the settling time for a
  round that started just before midnight) is immutable, so its per-link figures (and, for the
  export, its probe sources) are computed once and kept in a bounded in-memory cache; recomputing is
  deterministic and gives the same result. The open month is always recomputed. The probe-source query
  (`DISTINCT probe, target, location`) is served by the covering index
  `wan_probe_samples_sources_idx (link_id, sampled_at) INCLUDE (probe, target, location)` and
  partition pruning to the month.
* **Retention** (period: pending human decision, DATA-RETENTION-MATRIX; nothing is invented or
  scheduled): the migrator removes a whole month with `DROP TABLE wan_probe_samples_pYYYYMM;
  ALTER TABLE wan_link_cycles DETACH PARTITION wan_link_cycles_pYYYYMM; DROP TABLE
  wan_link_cycles_pYYYYMM;` (samples first; the cycles partition must be detached because the
  foreign key on the samples parent references it; detach the samples partition instead of removing it
  to archive). This is an owner-only action; the append-only triggers guard rows, not partitions.
* The `down` migration is guarded like 0003/0004 and removes only these tables (and their partitions)
  and the two helper functions.

## Sampling: a small bounded collector, not the evaluation scheduler (decision)

`NETSIGHT_WAN_SAMPLING_ENABLED` (default off; strict value; enabled needs
`NETSIGHT_WAN_COLLECTOR_DATABASE_URL` and a usable `NETSIGHT_WAN_LINKS`, otherwise start-up fails; the
collector no longer uses `DATABASE_URL`, and the two credentials must name different roles) with `NETSIGHT_WAN_SAMPLE_INTERVAL_SECONDS` (30-300,
default 60; stored with every cycle so the SLA stays deterministic if the setting changes). It reuses
the loop, leader election and shutdown of `evaluation.wiring.run_scheduler` with its own PostgreSQL
advisory-lock key, so exactly one collector samples per database and it never contends with the alert
evaluator.

Why not the evaluation scheduler: evaluation is tied to alert rules, notification channels, a 30 s floor
and per-cycle budgets; a slow probe must never delay an alert cycle; WAN evidence must be collectable
without enabling alerting (and the reverse); the two jobs may live in different processes.

The collector adds **no probe capability**: it uses the existing allow-listed clients (target allow-list,
fixed modules, SSRF guards). A link is served by the exporter at its `probe_location` (ICMP) or by the
local prober (TCP and DNS) when it names no location or the prober sits there; a link nobody serves
records nothing (a gap). A probe that fails, hangs, raises or returns an unexpected status is an
`unknown` sample; no probe text is stored. Per-probe timeout 15 s and a per-link deadline of one
interval. DNS is probed only by the local prober, so it reflects the host's resolver, not the link's
path: a link at an exporter location has no DNS sample.

At start-up the collector's database role is checked (`check_collector_role`): a superuser, a role
that bypasses row security, an owner of the WAN tables, or a role that cannot be checked at all stops
the start. Only a unique violation counts as "this second already has a cycle" (skipped); a deadlock,
serialization failure or missing partition is a failed round and is logged by error type and link id.

## Evidence export

JSON (`InternetSlaExport`) or CSV with a fixed header, one row per window (`down`, `degraded`,
`unknown`), `started_at`/`ended_at` UTC, duration, probe-round count (`0` for a gap in sampling), and the
distinct probe, target and location behind the samples. At most 2 000 windows per link and a
`windows_truncated` flag; the figures are never truncated. When a link's windows were cut, the CSV ends
with one `truncated` sentinel row per such link (empty times and counts, a note
`EXPORT INCOMPLETE: ...` in the `sources` column), so a cut file cannot pass as complete; the SLA
panel shows the same warning from `SlaLink.windows_truncated`. The CSV neutralises spreadsheet formulas
(a leading apostrophe), quotes through the csv module and uses CRLF. The ISP name is the operator's
declaration, and the `basis` text states that the evidence is only as trustworthy as the host that
recorded it (samples are taken and stored by the Netsight host; nothing is signed or independently
attested). The export is read-only and is withheld from roles without `internet:export`.

Audit (`internet.export`): actor, month, format, state, `link_count` and `row_count` (never content).
A refused export is `denied`; an export whose state is `unknown` (the evidence could not be read) is a
`failure`; `not-connected` is a `success`.

## Rollback

Unset `NETSIGHT_WAN_SAMPLING_ENABLED` (collector off; stored rows stay) and/or `NETSIGHT_WAN_LINKS`
(`/internet` answers `not-connected`). Unregister `internet_router` in `main.py` to withdraw the API.
Schema: `apply_down(conn, allow_destructive=True)` reverses 0005 only (refuses while rows exist unless
`NETSIGHT_ALLOW_DESTRUCTIVE_DOWN=1`). Removing `NETSIGHT_WAN_COLLECTOR_DATABASE_URL` stops all writes;
the migrator re-applies the grants of both roles on every `up`.
