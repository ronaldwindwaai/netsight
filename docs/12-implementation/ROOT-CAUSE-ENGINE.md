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
