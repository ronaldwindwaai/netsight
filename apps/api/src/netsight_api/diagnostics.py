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
    ProbeLocation,
)

# A vantage is a free-form label; these name the two classes the engine can reason about. An
# unknown label is "other": it never contributes to a narrowing, because the engine cannot tell
# which side of the network it sits on.
EXTERNAL_VANTAGES = frozenset({"internet", "external", "wan", "public"})
INTERNAL_VANTAGES = frozenset(
    {"internal", "server-vlan", "lan", "management", "campus", "datacentre", "datacenter"}
)
# A configured probe location is provenance the engine can trust more than a free-form label. Only
# locations on the service's side of the network count as "internal" evidence: a branch or remote
# site reaches the service across the WAN, so its result says little about the service itself and
# never narrows on its own.
EXTERNAL_LOCATIONS: frozenset[ProbeLocation] = frozenset({"cloud-external"})
INTERNAL_LOCATIONS: frozenset[ProbeLocation] = frozenset({"server-vlan", "user-lan", "wifi"})
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
    location: ProbeLocation | None = None
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


def _classify(observation: Observation) -> str:
    """external / internal / other; a configured location wins over a free-form vantage label."""
    if observation.location is not None:
        if observation.location in EXTERNAL_LOCATIONS:
            return "external"
        return "internal" if observation.location in INTERNAL_LOCATIONS else "other"
    value = (observation.vantage or "").strip().lower()
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


@dataclass(frozen=True)
class _Verdict:
    """The outcome of the one rule that matched: a domain with its competing hypotheses."""

    domain: FaultDomain
    alternatives: tuple[str, ...]
    next_checks: tuple[str, ...]


_SERVICE_VERDICT = _Verdict(
    "service",
    (
        "The application is not listening on the probed port",
        "A local host firewall filters the port while the host is reachable",
    ),
    (
        "Confirm the listening socket and service state on the host",
        "Query the service's own health endpoint",
    ),
)
_DNS_VERDICT = _Verdict(
    "wan-dns-external",
    (
        "The local resolver or forwarder is the failing component",
        "A split-horizon or policy view answers differently per vantage",
    ),
    (
        "Resolve the name from a second, independent resolver",
        "Query the authoritative zone directly for the record",
    ),
)
# Narrowing, not proof: ROOT-CAUSE-ENGINE explicitly warns against asserting a firewall.
_FIREWALL_VERDICT = _Verdict(
    "firewall",
    (
        "An upstream or ISP routing change, not the firewall",
        "An external policy/ACL change or an asymmetric return path",
    ),
    (
        "Compare the firewall and NAT rule set against the last change",
        "Check the WAN uplink and upstream reachability from the edge",
        "Repeat the external check from a second vantage",
    ),
)
_TARGET_VERDICT = _Verdict(
    "target",
    (
        "A host-level firewall or ACL is dropping the probes",
        "The target is genuinely down (ICMP failure alone does not prove this)",
    ),
    (
        "Confirm the target through an out-of-band management path",
        "Compare against the last known-good baseline state",
        "Review recent configuration changes on the target",
    ),
)


def _findings(
    observations: Sequence[Observation],
) -> tuple[list[DiagnosticFinding], list[DiagnosticFinding]]:
    """(facts, unknowns): an answered check is a fact, an unanswered one is an explicit unknown."""
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
    return facts, unknowns


def _matching_verdict(observations: Sequence[Observation]) -> _Verdict | None:
    """The first narrow, well-supported pattern the observations match, else None."""
    dns = [o for o in observations if o.kind == "dns"]
    reachability = [o for o in observations if o.kind in _REACHABILITY_KINDS]
    external = [o for o in reachability if _classify(o) == "external"]
    internal = [o for o in reachability if _classify(o) == "internal"]
    # Only the server's own VLAN (or an unlocated internal vantage) speaks for the target itself: a
    # failing user LAN or Wi-Fi says nothing about whether the host is down.
    target_basis = [o for o in internal if o.location in (None, "server-vlan")]
    at_server = [o for o in reachability if o.location == "server-vlan"]
    server_service_fail = any(o.kind in _PORT_KINDS and o.status == "fail" for o in at_server)
    server_reachable = any(o.status == "pass" for o in at_server)
    internal_pass = any(o.status == "pass" for o in internal)
    icmp_pass = any(o.kind == "icmp" and o.status == "pass" for o in reachability)
    service_fail = any(o.kind in _PORT_KINDS and o.status == "fail" for o in observations)

    if dns and any(o.status == "fail" for o in dns) and not any(o.status == "pass" for o in dns):
        return _DNS_VERDICT
    if server_service_fail and server_reachable:
        # The service fails even from its own VLAN while that VLAN reaches the host: the service
        # itself is failing, which an internal pass elsewhere must not mask.
        return _SERVICE_VERDICT
    if any(o.status == "fail" for o in external) and internal_pass:
        return _FIREWALL_VERDICT
    if target_basis and all(o.status == "fail" for o in target_basis):
        return _TARGET_VERDICT
    if service_fail and (icmp_pass or internal_pass):
        return _SERVICE_VERDICT
    return None


def _closing_unknown(
    observations: Sequence[Observation], domain: FaultDomain | None, has_unknowns: bool
) -> DiagnosticFinding | None:
    """The honest closing line when the observations narrowed nothing."""
    if not observations or domain is not None:
        return None
    if any(o.status == "fail" for o in observations):
        return _finding("The available evidence did not narrow the fault to a single domain")
    if not has_unknowns:
        return _finding("The reported symptom was not reproduced by the requested checks")
    return None


def infer(observations: Sequence[Observation]) -> Inference:
    """Infer the result shape from bounded probe observations."""
    facts, unknowns = _findings(observations)
    if not observations:
        unknowns.append(_finding("No diagnostic check could be run against the target"))
    verdict = _matching_verdict(observations)
    domain = None if verdict is None else verdict.domain
    closing = _closing_unknown(observations, domain, bool(unknowns))
    if closing is not None:
        unknowns.append(closing)
    alternatives = [_finding(text) for text in (verdict.alternatives if verdict else ())]
    next_checks = [_finding(text) for text in (verdict.next_checks if verdict else ())]
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
        confidence="unknown" if verdict is None else "low",
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
            location=observation.location,
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
