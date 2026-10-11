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
`outcome = failure` and `reason = <exception type>`, or `reason = CLAIM_LOST` (another writer claimed the key first; `target` is
the surplus incident). `notification.send` is one record per destination attempted:
`target` is the notification id, with `channel`, `destination` (a keyed hash or a host, never an address or token), `code`
(a static code such as `OK`, `QUEUE_FULL`, `SMTP_5XX`), `attempts`, `alert` and `incident`; a send that could not be attempted
carries `reason` (`no-public-url`); a page dropped because the backlog was full carries `code = BACKLOG_FULL` with `rule_id` and `alert`. Rule names, entity names, addresses and payload text are never logged.

## Internet export (Step 5)

`internet.export` records `success` (actor, `target` = the month, `format`, the answered `state`, `link_count` and `row_count`; never the evidence),
`failure` when the evidence could not be read (the answered `state` is `unknown`; a `not-connected` answer is still a `success`) and `denied` (reason
`permission`) when a caller without `internet:export` asks for it. Status and SLA reads are not audited (read auditing remains an open
platform follow-up). The WAN collector writes no audit records: it performs no operator action and stores only probe outcomes.
