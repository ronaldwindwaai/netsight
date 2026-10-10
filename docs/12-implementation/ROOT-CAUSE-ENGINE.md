# Root-Cause / "Why?" Engine

## Objective
Identify the smallest plausible fault domain using structured evidence.

## Diagnostic graph

Target -> Service -> Host -> Interface -> Access Device -> Core -> Firewall -> WAN/DNS/External dependency.

## Workflow
1. Establish requested symptom and time.
2. Resolve target identity.
3. Check source freshness.
4. Check target health.
5. Check name resolution.
6. Check reachability/path from relevant vantage points.
7. Check service port/application health.
8. Check dependencies.
9. Check recent config/change events.
10. Compare historical/baseline state.
11. Produce evidence bundle.
12. Infer probable fault domain.

## Required result shape
- facts[];
- contradictions[];
- unknowns[];
- probable_fault_domain;
- confidence;
- alternative_hypotheses[];
- recommended_next_checks[];
- evidence_ids[].

## Rules
- Temporal correlation is not proof of causation.
- A successful ping does not prove application availability.
- An ICMP failure does not prove host failure.
- External failure + internal success narrows the fault domain but does not automatically prove firewall failure.
- Missing telemetry is an unknown.

## Probe locations (S7 Step 4)

A check carries the **location** of the configured probe source it ran from: `cloud-external`, `user-lan`, `server-vlan`, `branch`, `wifi`, `remote-site` (or none when the prober has no configured location). A location is never inferred from a vantage label or from another location.

- `cloud-external` is the external side; `server-vlan`, `user-lan` and `wifi` are internal evidence. `branch` and `remote-site` reach the service across the WAN, so their results never narrow on their own and never stand in for an internal vantage.
- **Internal ok / external failing** (`firewall` domain, pattern `external-only-failure`): the service answers from an internal location and fails from the external one. It narrows the fault to the path between them; it does not prove a firewall, WAN or upstream fault.
- **Service itself failing** (`service` domain, pattern `service-failure`): a port/service check fails from the server's own VLAN while that VLAN reaches the host. A passing user LAN elsewhere does not mask it.
- Only `server-vlan` (or an unlocated internal vantage) speaks for the target host; a failing user LAN or Wi-Fi alone never names the target.
- A location with no configured source is `not-connected`; one whose checks all went unanswered is `unknown`. Neither is ever healthy. The six locations are always listed.
- Every line of the probable-cause evidence list is labelled `observed` (a probe measured it), `inferred` (reasoned from measurements) or `unknown` (no telemetry). Evidence statements are fixed phrases built from enumerated values and counts; untrusted probe text is never copied into the cause.
- Recent changes (incidents and LibreNMS alerts now; configuration changes once a source exists) are shown as things that **may correlate**, scoped `target` only when the source itself ties the record to the target, otherwise `time-window`. An unconnected source is `not-connected`, an unreadable one `unknown`; neither is "no changes". An incident change is a reference (id, severity, time): its title is never stored and is joined at read time only for a caller holding `incidents:read` (otherwise a placeholder, `title_redacted`). The inferred evidence line of the external-only-failure and service-failure patterns cites only checks that were answered (pass or fail); a check that could not be answered supports neither pattern and is cited only on the per-location lines, where it is shown as unknown.
- The path (User -> access point -> access switch -> core -> firewall -> server) is grown outward from the resolved target one explicit NetBox cable per tier (firewall, core, access switch, access point), by a fixed role vocabulary. A tier with no cable, an unrecognised role or two candidates is `unknown`, and so is everything beyond it. The user end is always unknown. The suspected tier follows the probable domain and is labelled inferred.
