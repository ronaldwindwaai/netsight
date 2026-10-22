# Audit Logging (interim sink)

The API writes one JSON object per line for every security-sensitive mutation (currently the
incident routes, `incident.*` actions) on the Python logger `netsight_api.audit`. This is the
interim audit sink: an operational log. The tamper-evident audit store (PRD 32) will consume
the same records; until then the append-only incident timeline is the authoritative record of
who changed an incident.

## Why it must be configured

Python logging drops records below WARNING unless something enables them, and the success
audit is an INFO record. The API therefore configures the `netsight_api.audit` logger itself at
start-up (`configure_audit_logging`, called from the application lifespan). Do not rely on a
global logging setup for this.

## Settings

| Variable | Values | Default | Meaning |
|---|---|---|---|
| `NETSIGHT_AUDIT_LOG_LEVEL` | `INFO`, `WARNING` | `INFO` | `INFO` records successes, denials and failures. `WARNING` records only denied and failed attempts. Higher levels are rejected: they would silently discard denials. |
| `NETSIGHT_AUDIT_LOG_DESTINATION` | `stderr`, `stdout`, `file` | `stderr` | Where the JSON lines go (container deployments: stdout/stderr, collected by the platform). |
| `NETSIGHT_AUDIT_LOG_FILE` | path | empty | Required when the destination is `file`. UTF-8, append. No rotation is built in: use logrotate or the collector. |

An invalid value stops the API at start-up (it never runs with audit logging silently off).
The handler emits the record unmodified (`%(message)s`), so every line is valid JSON.
The logger still propagates to the root logger: leave the root logger unconfigured, or filter
`netsight_api.audit` there, to avoid receiving each line twice.

## Record shape

```json
{"action": "incident.assign", "actor_id": "microsoft:abc", "assignee_hash": "9f86d081884c7d65",
 "assignee_length": 22, "correlation_id": "c0ffee", "event": "audit", "outcome": "success",
 "target": "incident-...", "ts": "2026-10-08T08:00:00.123456+00:00"}
```

- `outcome`: `success` (INFO), `denied` or `failure` (WARNING). `reason` carries a fixed code for
  denials and failures: `permission`, `scope`, `csrf`, `origin`, `step-up` (resolve/reopen without a recent
  second factor; no MFA age or session detail is logged), `rate-limit`, `NOT_FOUND`,
  `ILLEGAL_TRANSITION`, `CONFLICT`, `INVALID_OPERATION`, `VALIDATION_ERROR`,
  `STORE_UNAVAILABLE`, `STORE_NOT_CONNECTED`, `INTERNAL`.
- Never present: comment, reason or root-cause text, tokens, session values, connection strings.
- Caller-chosen identifiers (assignee, evidence reference) appear only as `*_length` and a
  16-hex-character SHA-256 prefix (`*_hash`), so records can be correlated without disclosing
  the value.
- Identifiers longer than 128 characters are replaced by `sha256:<64 hex>` (never truncated, so
  two long identities cannot collide).
- Success and failure records are written by the worker thread immediately after the database
  call, so a client that disconnects mid-request cannot lose them. A failing sink never turns a
  committed write into an error response; it is logged as `audit record could not be emitted`
  on the `netsight_api` logger.

## Operating notes

- Ship the lines to the log collector and alert on `outcome != success` bursts per `actor_id`.
- Local files are not tamper-evident; do not treat them as the compliance record.
- Related settings: `NETSIGHT_ALLOWED_ORIGINS` (comma-separated browser origins allowed to make
  cookie-authenticated writes, in addition to the origin of `NETSIGHT_PUBLIC_BASE_URL`; refused
  writes are audited with reason `origin`) and `NETSIGHT_SESSION_ALLOW_SAME_SITE_NONE`.

## Alert-rule and maintenance actions (S6-3)

`alert_rule.create|update|approve|disable` and `maintenance.create|cancel` use the same record shape. `target` is the rule
or window id (for create, the new id on success and absent on refusal); successes add `version` and `status` (rules),
`expected_version` (update, approve), and `name_hash`/`name_length` (rule and window names are free text and are never
logged), plus `scope_kind`, `scope_ref_hash`, `evaluation`, `duration_seconds`, `starts_at` and `reason_length` for
windows. Extra `reason` codes: `RULE_INVALID`, `organisation-scope` (refusal: an organisation-scope window without
`maintenance:write-organisation`), `disable-evaluation` (refusal: a window with `evaluation: "disable"` without the same
permission, whatever its scope — it stops all rule evaluation). `alert_rule.evaluate` (the read-only dry-run) is audited
only when refused (`permission`, `csrf`, `origin`, `rate-limit`, `busy`).

## Evaluation service actions (S6 step 2)

The background evaluator writes with the actor `service:alert-evaluator` and the correlation id of its cycle
(`eval-<12 hex>`). `incident.auto_create` and `incident.auto_attach` carry `target` (the incident id), `rule_id`, `policy`
(`create`, `group` or `race`) and `alert` (the 32-hex alert fingerprint); a failure is `incident.auto_create` with
`outcome = failure` and `reason = <exception type>`, or `reason = CLAIM_LOST` (another writer claimed the key first; its incident was rolled
back, so `target` is the incident that carries the alert). `notification.send` is one record per destination attempted:
`target` is the notification id, with `channel`, `destination` (a keyed hash or a host, never an address or token), `code`
(a static code such as `OK`, `QUEUE_FULL`, `SMTP_5XX`), `attempts`, `alert` and `incident`; a send that could not be attempted
carries `reason` (`no-public-url`); a page dropped because the backlog was full carries `code = BACKLOG_FULL` with `rule_id` and `alert`. Rule names, entity names, addresses and payload text are never logged.

## Internet export (Step 5)

`internet.export` records `success` (actor, `target` = the month, `format`, the answered `state`, `link_count` and `row_count`; never the evidence),
`failure` when the evidence could not be read (the answered `state` is `unknown`; a `not-connected` answer is still a `success`) and `denied` (reason
`permission`) when a caller without `internet:export` asks for it. Status and SLA reads are not audited (read auditing remains an open
platform follow-up). The WAN collector writes no audit records: it performs no operator action and stores only probe outcomes.

## Identity reads (Step 6)

Every read of per-person data is audited (PRD 92): `identity.users.list` (`state`, `result_count`, `page`, `page_size`), `identity.user.read` (`target` = the person id, `state`,
`session_count`) and `identity.resolve` (`target` = `ip:<fingerprint>`, `mac:<fingerprint>` or `hostname:<fingerprint>`, where the fingerprint is the short SHA-256 of the canonical value and **never the raw address, MAC or hostname**; `state`, `basis` of the answer, `redacted`, `historical`,
`identified_count` = how many persons or candidates were disclosed, `endpoint_links`). They record `success`, `failure` (an unreadable source, `state = unknown`, or an unknown person with
`reason = not-found`) and `denied` (`reason = permission`) with the actor and correlation id. Refusals are audited too, each with a static `reason` and no caller input: `identity.summary`
(`denied`, `permission`), a denied `identity.user.read` (with `target` = the person id when it is a canonical id), `denied` / `rate-limited` for any identity action, `denied` / `global-limit` and
`denied` / `busy` for a past-time resolve, and `failure` / `subject-count`, `invalid-subject` or `invalid-time` for rejected resolve input (422; nothing echoed). They never carry a name, an e-mail address, an alert signature, a purpose or any text a
source supplied; the aggregate `GET /users/summary` returns counts only and is not audited. The same interim JSON-lines sink and caveats apply.

### Traffic reads (Step 7)

`traffic.flows.read` and `traffic.top-talkers.read` are audited because they list endpoints and may name people (PRD 92); since the
Step 7 security review the other three routes are audited on **success** too (`traffic.applications.read`,
`traffic.destinations.read`, `traffic.anomalies.read`), because they are the aggregate tier's view of the same data. Fields common to
all four: `outcome` (`success` for `ok` and `not-connected`, `failure` for `unknown`, `denied` for refusals), `state`, `tier`
(`detail` | `aggregate`), `cohort` (the small-cohort verdict: `not-applied` | `sufficient` | `too-few-sources`), `window_seconds`. Per route:

| Action | Further fields |
| --- | --- |
| `traffic.flows.read` | `row_count`, `attributed_count` (rows that name a person), `restricted` (rows withheld), `attribution_level` (`person` / `endpoint` / `none`), `attribution_state`, `filters` (the **names** of the filters used, e.g. `source_ip,port`, never their values), and the optional `fp_*` fingerprints below |
| `traffic.applications.read`, `traffic.destinations.read` | `row_count`, `policy` (state of the operator policy file) |
| `traffic.anomalies.read` | `row_count` (anomalies listed), `first_seen_count`, `evaluation` (status), `daylight_saving` |

Refusals and rejected input carry a static `reason` and no caller input, on every route: `permission`, `rate-limited`,
`filter-needs-detail` (an address, device or VLAN filter without `traffic:read-detail`), `busy` (the heavy-read cap is full, 503),
`identity-busy` (this identity already has a heavy read running, 429), and, for a rejected request (422, `outcome = failure`),
`unknown-parameter`, `repeated-parameter`, `invalid-filter`, `invalid-window`, `window-too-long` (anomalies over 7 days) or
`invalid-request` (FastAPI itself rejected a malformed `limit`, `preset`, `from` or `to`). No record contains an address, a hostname,
an application name, a policy entry or a person's name.

**Fingerprints of endpoint-level lookups (optional, default on).** When a *detail-tier* caller filters the Explorer by `source_ip`,
`destination_ip`, `device` or `vlan`, the record may carry `fp_source_ip`, `fp_destination_ip`, `fp_device`, `fp_vlan`: the first 16 hex
characters of `HMAC-SHA256(key, "netsight.audit.filter.v1" 0x00 filter-name 0x00 canonical-value)`. An auditor answers "who looked up
10.1.2.3?" by computing the same HMAC for the (canonical) address and searching the trail; repeated lookups of one target show up as
equal fingerprints. The key makes it non-reversible by hashing the address space.

* `NETSIGHT_AUDIT_FILTER_FINGERPRINT`: `on` (default) or `off` / `0` / `false` / `no`.
* `NETSIGHT_AUDIT_FILTER_KEY`: the HMAC key, at least 32 characters; when unset the identity evidence-id key
  (`NETSIGHT_IDENTITY_ID_KEY`) is used. With no usable key the fingerprints are **omitted** (never degraded to a plain hash) and one
  warning is logged. Rotating the key makes old and new fingerprints incomparable: keep the old key to search old records.
* Only values the caller already has the detail tier to filter by are fingerprinted; the aggregate tier cannot use these filters.
