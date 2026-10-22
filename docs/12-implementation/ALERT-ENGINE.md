# Alert Engine Specification

## Goal
Represent deterministic and behavioural alert rules independently of any single upstream alert product.

## Rule dimensions
- scope: organisation/site/device/group/VLAN/user/service;
- metric/signal;
- operator;
- threshold/pattern;
- time schedule;
- duration;
- cooldown;
- exceptions;
- baseline comparison;
- severity;
- labels;
- notification policy;
- incident policy.

## Example conceptual rule

```yaml
name: After-hours large upload
scope:
  device_group: staff-workstations
condition:
  metric: traffic.upload_bytes
  operator: gt
  value: 1000000000
window: 15m
schedule:
  timezone: Africa/Windhoek
  active:
    - weekdays: [mon,tue,wed,thu,fri]
      from: "20:00"
      to: "06:00"
exceptions:
  destinations: [approved-backup, microsoft-update]
  device_groups: [backup-servers, cctv]
severity: high
actions:
  - create_alert
  - email
  - push
```

## Behavioural alerts
A baseline detector emits an `AnomalySignal`; the alert engine applies organisational policy and exceptions.

## Maintenance
Maintenance suppresses notification/action but retains evaluation evidence unless policy explicitly disables the evaluator.

## Dependency inhibition
If a root dependency is unavailable, dependent symptom alerts may be grouped/inhibited but remain visible in the incident evidence.

## Anti-noise
Support:
- group-by labels;
- debounce;
- cooldown;
- deduplication;
- escalation;
- acknowledgement;
- silence/mute;
- maintenance.

## Safety
Natural-language alert creation must generate a preview; it never activates a rule without explicit approval.

## Implementation (S6-3)

Code: `apps/api/src/netsight_api/alerting/` (pure, no I/O, injected clock) and the routes in
`alert_rule_routes.py` / `maintenance_routes.py`. Contract: `contracts/json-schema/alert-rule.schema.json`
(records) and `alert-rule-api.schema.json` (envelopes), in four-way agreement with OpenAPI, pydantic and the
browser parsers through `contracts/test-vectors/incident-alert.vectors.json`.

Evaluation semantics (`alerting/engine.py`; every step that cannot decide fails closed):

1. configuration check (`validation.check_definition`): unknown timezone, baseline mode with a text pattern, an incident
   policy without `create_alert`; an invalid rule never evaluates and is refused at create, update and approve;
2. status: only an `active` rule evaluates in production (drafts and disabled rules never fire; the dry-run evaluates a
   supplied definition regardless);
3. freshness against the injected clock: an observation older than `window_seconds`, more than 60 s in the future,
   duplicated or out of order is ignored without touching state;
4. scope: the rule only sees entities that list the rule's `(kind, ref)` among their scopes;
5. maintenance (`maintenance.py`): a window is half-open `[starts_at, ends_at)`, `active`/`expired` are derived from the
   clock, cancelled windows never count, overlapping windows are a union and `disable` beats `retain`. `disable` stops
   evaluation (no state change); `retain` keeps evaluating and defers the notification;
6. condition after exceptions (exact destination / device-group match) and the schedule (wall-clock in the schedule
   timezone, weekdays name the day a window starts, `to` exclusive, `to < from` crosses midnight, equal means the whole
   day; DST gaps simply never occur and repeated hours match in both passes);
7. state machine: inactive -> pending -> firing with `for_seconds` measured between observation timestamps; a data gap
   restarts the debounce but is not a recovery; the notification is released the first time the alert is firing,
   not yet notified, outside maintenance and outside the cooldown of the previous notification (blocked
   notifications are deferred, not lost).

Interpretations to confirm (ALERT-ENGINE.md is silent): a `baseline_mode` other than `none` requires **both** the
threshold condition and the detector direction (`above`/`below`/`outside`), and no detector signal is `no-data`;
`matches` is a glob (`*`, `?`, case-sensitive, evaluated by a bit-parallel matcher, text capped at 4096 characters), not a
regular expression; `cooldown_seconds` spaces notifications of the same alert, it does not delay creating the alert.

Grouping (`grouping.py`): alert fingerprint = (rule id, entity); group key = scope + sorted labels; `plan_incident`
decides none/create/attach from `incident_policy` and the open incidents (performed by the evaluation service below).
Escalation lives with notification routing (`notifications/dispatcher.py`), not in the rule record.

Dry-run: `POST /api/v1/alert-rules/evaluate` replays up to 200 supplied observations (strictly ascending times) through a
supplied definition and up to 20 sample windows; it reads no store, sends nothing and creates nothing.

Not implemented in the engine: dependency inhibition, silences/acknowledgement-based muting, a supported-metric catalogue (an unknown
metric is accepted and simply never receives observations), and the AI "propose" stub (no AI broker exists yet; any
future proposal must produce a draft that only a human approval can activate).

## Evaluation service (S6 step 2)

Code: `apps/api/src/netsight_api/evaluation/` (the engine in `alerting/` stays pure and I/O-free).
Off by default; `NETSIGHT_EVALUATION_ENABLED=true` starts one bounded cycle every
`NETSIGHT_EVALUATION_INTERVAL_SECONDS` (30-3600, default 60) from the application lifespan. Enabled without
`DATABASE_URL`, or with any invalid channel setting, the application refuses to start. **Exactly one evaluator may run per
database - a hard requirement, enforced in code** (`leader.py`): the scheduler runs cycles only while it holds a PostgreSQL
session-level advisory lock on a dedicated connection (TCP keepalives and a 30 s `tcp_user_timeout` on); every other process
idles and retries each interval. The runner re-verifies the lock before applying a cycle **and again before every incident
write, recovery note and notification send** (the apply phase can run for a minute); a process that loses it (session died,
database restart, a rival holds it) stops at once, sends nothing further and drops its in-memory engine state, so a later
takeover starts clean. The check asks the server (`pg_locks`: an advisory lock granted to this backend with the right key), not
merely whether the session answers, and runs under a 10 s timeout, so a network partition costs seconds, not a TCP
retransmission timeout; `release` never waits for a check in progress. A lock backend failure or timeout means "not the leader"
(fail closed). **`DATABASE_URL` must be a direct or session-mode connection**: PgBouncer in transaction or statement mode
multiplexes sessions and breaks session-level advisory locks (two evaluators could then run).

**Observation source** (`source.py`). `ObservationSource` is a Protocol: `supports(metric)` and
`observe(metric, now) -> ObservationBatch`. A batch is `ok` (observations), `not-connected` (source not configured) or
`unknown` (read failed, timed out, refused or unusable; also more than 5000 entities), and a non-ok batch cannot carry
observations. A reading the source cannot state is an observation with `value = None`, which the engine treats as no data.
Nothing is substituted or interpolated. `LibrenmsObservationSource` (built on the existing read-only adapter) supports
`device.status` (1 up, 0 down, `None` when unknown or when LibreNMS has the device disabled/ignored) and
`device.alert_count` (open, not acknowledged, LibreNMS alerts, 0 for quiet devices so a count can recover). Observations
are scoped to `("device", id)` and `("organisation", "default")`; device names and alert titles are never copied in.

**Runner** (`runner.py`). Per cycle: load `active` (approved) rules, drafts and disabled rules never evaluate; read each
distinct metric once (bounded concurrency 4, per-read timeout 30 s); `not-connected`/`unknown`/timeout means the rule is
not evaluated for that cycle and a gap is recorded (a pending debounce restarts, a firing alert is kept: a gap is not a
recovery); run `evaluate_definition` with the injected clock; then apply effects. Bounds: 500 rules, 200 000 evaluations
(shared fairly: each rule gets the ceiling of the remaining budget over the remaining rules, and a rule's entities are
visited round-robin across cycles, so none starves; **running out of budget is not a data gap** - entities not reached keep
their pending/firing state, only entities absent from the data restart a debounce),
50 000 tracked (rule, version, entity) states (inactive ones are evicted first; pending or firing ones never are, so new
entities are not tracked and the cycle reports `truncated`), 100 incident actions and 50 notifications per cycle
(notifications over the cap, or still unsent when the 60 s notification-phase deadline passes, wait in a backlog of at most
1000, ordered most severe first; overflow drops the least severe, is counted as failed and audited as `notification.send`
`code = BACKLOG_FULL`; incident work is re-derived next cycle). More than 500 live maintenance windows marks the cycle
`truncated`. A store failure
loading rules evaluates nothing. Overlapping `run_cycle` calls return `overlapped` instead of queueing. Engine state is
in memory: after a restart the phase is re-derived from fresh observations, incidents are protected by the durable links
and repeat pages by the delivery ledger (see NOTIFICATION-ENGINE.md).

**Maintenance suppresses availability alerts only.** Windows are passed to the engine only for availability metrics
(`device.status`, `interface.oper_status`, `availability.*`); every other metric ignores them, so planned work never
silences a traffic, security or count-based rule. `retain` holds back both the incident and the notification while the
alert keeps firing (deferred, not lost: both happen at the first cycle after the window, if still firing); `disable` stops
evaluation and leaves state untouched. Cancelled and expired windows never count.

**Incidents** (`incidents.py`, migration 0003 `alert_incident_links`). A firing alert not held back by maintenance, with
`incident_policy` other than `none`, gets exactly one incident per key: `create` keys on the alert fingerprint (one incident
per alert), `group` on the group key (later alerts of the group attach with an `alert-linked` timeline event). A key points
at an incident until a **human** resolves it; then a new firing opens a new one **once the alert has recovered**. The
link records the recovery (`recovered_at`, written when the engine sees the alert resolve; a claim clears it), so a still-firing
alert whose incident a human resolved gets no new incident - in the running process and after a restart alike. If the evaluator
was down for the whole recovery and the re-fire, that one outage is attributed to the old resolved incident (conservative). The incident, its first `alert-linked`
note and the link claim are written by one store operation (`AlertIncidentStore.open_linked`, a single PostgreSQL transaction), so
no failure can leave an open incident without a link and the next cycle never duplicates it. The leader lock prevents two
evaluators; if they raced anyway the loser's transaction is rolled back (no surplus incident is stored), it attaches to the winner
and audits `incident.auto_create` failure with `reason = CLAIM_LOST` (`target` is the incident that carries the alert). Claim
results are checked everywhere. The writer is the service principal `service:alert-evaluator` (no roles,
`PrincipalKind.SERVICE`): it can only open an incident, append `alert-linked`/`comment` notes and read, through a narrow runtime
adapter (`EvaluatorIncidentAdapter`: `open_linked`, `append_event`, `get_incident`) rather than the repository, and the storage
layer independently refuses any `service:` actor for acknowledge/advance/resolve/reopen, assign, evidence and rule edit/approve/disable
(`ScopeViolationError`). A separate database role limited to these operations is a follow-up. It never acknowledges, assigns, resolves,
reopens or closes an incident, and never edits a rule or window (a static test enforces this). Severity maps
`info,low -> low`, `medium`, `high`, `critical`. Audit: `incident.auto_create` / `incident.auto_attach` (success) and
`incident.auto_create` with `reason = <error type>` (failure).

Interpretations to confirm: a recovered alert does **not** resolve or annotate its incident (resolution is a human
judgement); incident creation is tied to the alert firing and not being held back by maintenance, not only to the first
notification; the `webhook` channel is not reachable from rule `actions` (the contract names `create_alert`, `email`, `push`).
