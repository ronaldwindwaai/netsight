"""Read-only diagnostic inference and run assembly (S7-2).

Pure and deterministic: a blackbox adapter produces ``Observation``s, this module reasons about
them and assembles the canonical ``DiagnosticRun``. It performs no I/O and never interprets
source text as an instruction.

The inference follows ``docs/12-implementation/ROOT-CAUSE-ENGINE.md``: temporal correlation is
not causation, a passing ping does not prove application availability, an ICMP failure does not
prove host failure, external failure with internal success narrows the fault domain but does not
prove a firewall fault, and missing telemetry is an unknown. It is deliberately conservative:
it names a probable fault domain only for a narrow, well-supported pattern and its confidence is
never above ``low``, because one round of observations cannot establish causation.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from uuid import uuid4

from netsight_api.schemas_diagnostics import (
    MAX_DIAGNOSTIC_EVIDENCE,
    DiagnosticCheckKind,
    DiagnosticCheckStatus,
    DiagnosticConfidence,
    DiagnosticFinding,
    DiagnosticProbeResult,
    DiagnosticRun,
    FaultDomain,
)

# A vantage is a free-form label; these name the two classes the engine can reason about. An
# unknown label is "other": it never contributes to a narrowing, because the engine cannot tell
# which side of the network it sits on.
EXTERNAL_VANTAGES = frozenset({"internet", "external", "wan", "public"})
INTERNAL_VANTAGES = frozenset(
    {"internal", "server-vlan", "lan", "management", "campus", "datacentre", "datacenter"}
)
_PORT_KINDS = frozenset({"tcp", "http", "https", "service"})
_PORT_LABEL_KINDS = frozenset({"tcp", "http", "https"})
_REACHABILITY_KINDS = frozenset({"icmp", "tcp", "http", "https"})


@dataclass(frozen=True)
class Observation:
    """One bounded probe outcome (the input side of the inference)."""

    kind: DiagnosticCheckKind
    label: str
    status: DiagnosticCheckStatus
    vantage: str | None = None
    port: int | None = None
    latency_ms: float | None = None
    detail: str | None = None
    observed_at: datetime | None = None
    evidence_id: str | None = None


@dataclass(frozen=True)
class Inference:
    """The inferred result shape (ROOT-CAUSE-ENGINE "Required result shape")."""

    facts: list[DiagnosticFinding] = field(default_factory=list)
    contradictions: list[DiagnosticFinding] = field(default_factory=list)
    unknowns: list[DiagnosticFinding] = field(default_factory=list)
    probable_fault_domain: FaultDomain | None = None
    confidence: DiagnosticConfidence = "unknown"
    alternative_hypotheses: list[DiagnosticFinding] = field(default_factory=list)
    recommended_next_checks: list[DiagnosticFinding] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)


def _ordered_unique(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _evidence(observation: Observation) -> list[str]:
    return [observation.evidence_id] if observation.evidence_id is not None else []


def _finding(statement: str, evidence: Sequence[str] = ()) -> DiagnosticFinding:
    return DiagnosticFinding(statement=statement, evidence_ids=list(evidence))


def _classify(vantage: str | None) -> str:
    value = (vantage or "").strip().lower()
    if value in EXTERNAL_VANTAGES:
        return "external"
    if value in INTERNAL_VANTAGES:
        return "internal"
    return "other"


def _status_word(status: DiagnosticCheckStatus) -> str:
    if status == "pass":
        return "succeeded"
    if status == "fail":
        return "failed"
    return "could not be established"


def _subject(observation: Observation) -> str:
    """A bounded, operator-facing phrase for one check; never asserts more than it measured."""
    where = observation.vantage or "the platform"
    if observation.kind == "dns":
        return f"Name resolution from {where}"
    if observation.kind == "icmp":
        return f"ICMP echo to the target from {where}"
    if observation.kind in _PORT_LABEL_KINDS:
        port = f" {observation.port}" if observation.port is not None else ""
        return f"{observation.kind.upper()} port{port} from {where}"
    return f"{observation.kind} check from {where}"


def _statement(observation: Observation) -> str:
    return f"{_subject(observation)} {_status_word(observation.status)}"


def _contradictions(observations: Sequence[Observation]) -> list[DiagnosticFinding]:
    """Conflicting evidence: the same check both passed and failed in one round."""
    outcomes: dict[tuple[str, str, int | None], set[str]] = {}
    evidence: dict[tuple[str, str, int | None], list[str]] = {}
    for observation in observations:
        group = (observation.kind, observation.vantage or "", observation.port)
        outcomes.setdefault(group, set()).add(observation.status)
        evidence.setdefault(group, []).extend(_evidence(observation))
    found: list[DiagnosticFinding] = []
    for key, seen in outcomes.items():
        if "pass" in seen and "fail" in seen:
            kind, vantage, port = key
            where = vantage or "the platform"
            port_text = f" {port}" if port is not None else ""
            found.append(
                _finding(
                    f"The {kind}{port_text} check from {where} both passed and failed; "
                    "re-run before drawing a conclusion",
                    _ordered_unique(evidence[key]),
                )
            )
    return found


def infer(observations: Sequence[Observation]) -> Inference:
    """Infer the result shape from bounded probe observations."""
    facts: list[DiagnosticFinding] = []
    unknowns: list[DiagnosticFinding] = []
    for observation in observations:
        if observation.status == "unknown":
            reason = observation.detail or "no data"
            unknowns.append(
                _finding(f"{_subject(observation)} is unknown: {reason}", _evidence(observation))
            )
        else:
            facts.append(_finding(_statement(observation), _evidence(observation)))

    domain: FaultDomain | None = None
    confidence: DiagnosticConfidence = "unknown"
    alternatives: list[DiagnosticFinding] = []
    next_checks: list[DiagnosticFinding] = []

    dns = [o for o in observations if o.kind == "dns"]
    reachability = [o for o in observations if o.kind in _REACHABILITY_KINDS]
    external = [o for o in reachability if _classify(o.vantage) == "external"]
    internal = [o for o in reachability if _classify(o.vantage) == "internal"]
    services = [o for o in observations if o.kind in _PORT_KINDS]

    dns_fail = any(o.status == "fail" for o in dns)
    dns_pass = any(o.status == "pass" for o in dns)
    external_fail = any(o.status == "fail" for o in external)
    internal_pass = any(o.status == "pass" for o in internal)
    internal_all_fail = bool(internal) and all(o.status == "fail" for o in internal)
    icmp_pass = any(o.kind == "icmp" and o.status == "pass" for o in reachability)
    service_fail = any(o.status == "fail" for o in services)

    if not observations:
        unknowns.append(_finding("No diagnostic check could be run against the target"))
    elif dns and dns_fail and not dns_pass:
        domain, confidence = "wan-dns-external", "low"
        alternatives = [
            _finding("The local resolver or forwarder is the failing component"),
            _finding("A split-horizon or policy view answers differently per vantage"),
        ]
        next_checks = [
            _finding("Resolve the name from a second, independent resolver"),
            _finding("Query the authoritative zone directly for the record"),
        ]
    elif external_fail and internal_pass:
        # Narrowing, not proof: ROOT-CAUSE-ENGINE explicitly warns against asserting a firewall.
        domain, confidence = "firewall", "low"
        alternatives = [
            _finding("An upstream or ISP routing change, not the firewall"),
            _finding("An external policy/ACL change or an asymmetric return path"),
        ]
        next_checks = [
            _finding("Compare the firewall and NAT rule set against the last change"),
            _finding("Check the WAN uplink and upstream reachability from the edge"),
            _finding("Repeat the external check from a second vantage"),
        ]
    elif internal_all_fail:
        domain, confidence = "target", "low"
        alternatives = [
            _finding("A host-level firewall or ACL is dropping the probes"),
            _finding("The target is genuinely down (ICMP failure alone does not prove this)"),
        ]
        next_checks = [
            _finding("Confirm the target through an out-of-band management path"),
            _finding("Compare against the last known-good baseline state"),
            _finding("Review recent configuration changes on the target"),
        ]
    elif service_fail and (icmp_pass or internal_pass):
        domain, confidence = "service", "low"
        alternatives = [
            _finding("The application is not listening on the probed port"),
            _finding("A local host firewall filters the port while the host is reachable"),
        ]
        next_checks = [
            _finding("Confirm the listening socket and service state on the host"),
            _finding("Query the service's own health endpoint"),
        ]

    has_failures = any(o.status == "fail" for o in observations)
    if observations and domain is None and not has_failures and not unknowns:
        unknowns.append(
            _finding("The reported symptom was not reproduced by the requested checks")
        )
    elif observations and domain is None and has_failures:
        unknowns.append(
            _finding("The available evidence did not narrow the fault to a single domain")
        )

    evidence_ids = _ordered_unique(
        [
            *[o.evidence_id for o in observations if o.evidence_id is not None],
            *[e for f in (*facts, *alternatives, *next_checks, *unknowns) for e in f.evidence_ids],
        ]
    )[:MAX_DIAGNOSTIC_EVIDENCE]

    return Inference(
        facts=facts,
        contradictions=_contradictions(observations),
        unknowns=unknowns,
        probable_fault_domain=domain,
        confidence=confidence,
        alternative_hypotheses=alternatives,
        recommended_next_checks=next_checks,
        evidence_ids=evidence_ids,
    )


def build_run(
    *,
    target: str,
    target_id: str | None,
    symptom: str | None,
    vantage: str | None,
    observations: Sequence[Observation],
    started_at: datetime,
    completed_at: datetime,
) -> DiagnosticRun:
    """Assemble the canonical run from observations and the inference they support."""
    inference = infer(observations)
    checks = [
        DiagnosticProbeResult(
            id=f"check-{index}-{observation.kind}",
            kind=observation.kind,
            label=observation.label,
            status=observation.status,
            vantage=observation.vantage,
            port=observation.port,
            latency_ms=observation.latency_ms,
            detail=observation.detail,
            observed_at=observation.observed_at,
            evidence_id=observation.evidence_id,
        )
        for index, observation in enumerate(observations)
    ]
    return DiagnosticRun(
        id=f"diagnostic-{uuid4()}",
        target=target,
        target_id=target_id,
        symptom=symptom,
        vantage=vantage,
        started_at=started_at,
        completed_at=completed_at,
        checks=checks,
        facts=inference.facts,
        contradictions=inference.contradictions,
        unknowns=inference.unknowns,
        probable_fault_domain=inference.probable_fault_domain,
        confidence=inference.confidence,
        alternative_hypotheses=inference.alternative_hypotheses,
        recommended_next_checks=inference.recommended_next_checks,
        evidence_ids=inference.evidence_ids,
    )
