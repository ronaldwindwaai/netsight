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
decides none/create/attach from `incident_policy` and the open incidents (wiring to the incident store is a later slice).
Escalation lives with notification routing (`notifications/dispatcher.py`), not in the rule record.

Dry-run: `POST /api/v1/alert-rules/evaluate` replays up to 200 supplied observations (strictly ascending times) through a
supplied definition and up to 20 sample windows; it reads no store, sends nothing and creates nothing.

Not implemented: dependency inhibition, silences/acknowledgement-based muting, a supported-metric catalogue (an unknown
metric is accepted and simply never receives observations), and the AI "propose" stub (no AI broker exists yet; any
future proposal must produce a draft that only a human approval can activate).
