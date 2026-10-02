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
