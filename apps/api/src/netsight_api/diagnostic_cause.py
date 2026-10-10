"""The labelled probable cause of a diagnostic run (S7 Step 4b).

Pure. Every evidence line says how it is known: ``observed`` (a probe measured it), ``inferred``
(reasoned from those measurements) or ``unknown`` (no telemetry; never treated as healthy). The
statements are fixed phrases built from enumerated values and counts only: untrusted probe text
(``detail``, labels) is never copied into the cause, so a hostile source cannot write the
operator's conclusion.
"""

from __future__ import annotations

from collections.abc import Sequence

from netsight_api.diagnostics import EXTERNAL_LOCATIONS, INTERNAL_LOCATIONS
from netsight_api.schemas_diagnostic_session import (
    DiagnosticEvidenceItem,
    DiagnosticLocationResult,
    DiagnosticProbableCause,
    pattern_for,
)
from netsight_api.schemas_diagnostics import DiagnosticRun, FaultDomain, ProbeLocation

LOCATION_LABELS: dict[ProbeLocation, str] = {
    "cloud-external": "the external (cloud) location",
    "user-lan": "the user LAN",
    "server-vlan": "the server VLAN",
    "branch": "the branch",
    "wifi": "Wi-Fi",
    "remote-site": "the remote site",
}
_DOMAIN_LABELS: dict[FaultDomain, str] = {
    "target": "the target host",
    "service": "the service",
    "host": "the host",
    "interface": "an interface",
    "access-device": "the access device",
    "core": "the core network",
    "firewall": "the path between the internal and external locations",
    "wan-dns-external": "external name resolution",
}
_NOT_ASSUMED = "they are not assumed healthy"


def _counts(row: DiagnosticLocationResult) -> str:
    return f"{row.failed} failed, {row.passed} passed, {row.unknown_checks} could not be answered"


def _observed_lines(rows: Sequence[DiagnosticLocationResult]) -> list[DiagnosticEvidenceItem]:
    lines: list[DiagnosticEvidenceItem] = []
    for row in rows:
        label = LOCATION_LABELS[row.location]
        if row.state == "observed":
            lines.append(
                DiagnosticEvidenceItem(
                    basis="observed",
                    statement=f"From {label}: {_counts(row)}",
                    check_ids=list(row.check_ids),
                )
            )
        elif row.state == "unknown":
            lines.append(
                DiagnosticEvidenceItem(
                    basis="unknown",
                    statement=(
                        f"From {label}: a probe source is configured but none of its checks "
                        f"could be answered; {_NOT_ASSUMED}"
                    ),
                    check_ids=list(row.check_ids),
                )
            )
    return lines


def _not_connected_line(rows: Sequence[DiagnosticLocationResult]) -> DiagnosticEvidenceItem | None:
    names = [LOCATION_LABELS[row.location] for row in rows if row.state == "not-connected"]
    if not names:
        return None
    return DiagnosticEvidenceItem(
        basis="unknown",
        statement=f"No probe source is connected for {', '.join(names)}; {_NOT_ASSUMED}",
        check_ids=[],
    )


def _answered_ids_where(
    run: DiagnosticRun,
    rows: Sequence[DiagnosticLocationResult],
    locations: frozenset[ProbeLocation],
) -> list[str]:
    """Ids of the checks at ``locations`` that were answered: an unanswered check supports nothing."""
    answered = {check.id for check in run.checks if check.status != "unknown"}
    return [
        cid for row in rows if row.location in locations for cid in row.check_ids if cid in answered
    ]


def _inferred(
    run: DiagnosticRun, rows: Sequence[DiagnosticLocationResult]
) -> tuple[str, DiagnosticEvidenceItem] | None:
    domain = run.probable_fault_domain
    if domain is None:
        return None
    pattern = pattern_for(domain)
    if pattern == "external-only-failure":
        ids = _answered_ids_where(run, rows, EXTERNAL_LOCATIONS | INTERNAL_LOCATIONS)
        summary = (
            "The service answers from the internal locations but not from the external one, "
            "which narrows the fault to the path between them."
        )
        statement = (
            "Internal success with external failure narrows the fault to the path between them; "
            "it does not prove which device (a firewall, the WAN or an upstream change) is at fault"
        )
    elif pattern == "service-failure":
        ids = _answered_ids_where(run, rows, frozenset({"server-vlan"}))
        summary = (
            "The service check fails even from the server's own VLAN while that VLAN reaches the "
            "host, so the service itself is the likely failing component."
        )
        statement = (
            "The service fails from the server VLAN while the host is reachable there; this is "
            "inferred from the checks and does not prove why the service is failing"
        )
    else:
        ids = [check.id for check in run.checks if check.status == "fail"]
        summary = f"The failed checks narrow the fault to {_DOMAIN_LABELS[domain]}."
        statement = (
            f"The failed checks point at {_DOMAIN_LABELS[domain]}; this is inferred, "
            "not measured, and does not prove causation"
        )
    return summary, DiagnosticEvidenceItem(
        basis="inferred", statement=statement, check_ids=list(dict.fromkeys(ids))
    )


def build_probable_cause(
    run: DiagnosticRun, rows: Sequence[DiagnosticLocationResult]
) -> DiagnosticProbableCause:
    """The run's own conclusion with a labelled evidence list (domain and confidence unchanged)."""
    evidence = _observed_lines(rows)
    inferred = _inferred(run, rows)
    if inferred is None:
        summary = "No probable cause could be named from this run."
        evidence.append(
            DiagnosticEvidenceItem(
                basis="unknown",
                statement="The available evidence did not narrow the fault to a single domain",
                check_ids=[],
            )
        )
    else:
        summary, line = inferred
        evidence.append(line)
    absent = _not_connected_line(rows)
    if absent is not None:
        evidence.append(absent)
    return DiagnosticProbableCause(
        domain=run.probable_fault_domain,
        confidence=run.confidence,
        basis="unknown" if inferred is None else "inferred",
        pattern=pattern_for(run.probable_fault_domain),
        summary=summary,
        evidence=evidence,
    )
