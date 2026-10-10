"""The read-only diagnostic inference (S7-2): conservative, evidence-first, never overstating.

Pure unit tests: no network, no adapter. They pin the ROOT-CAUSE-ENGINE rules the engine must
never break — correlation is not causation, a ping is not availability, an ICMP failure is not
host failure, and missing telemetry is an unknown.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from netsight_api.contracts import validate
from netsight_api.diagnostics import Observation, build_run, infer

START = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)


def observation(
    kind: str,
    status: str,
    *,
    vantage: str = "internal",
    port: int | None = None,
    evidence: str | None = None,
    detail: str | None = None,
) -> Observation:
    return Observation(
        kind=kind,  # type: ignore[arg-type]
        label=f"{kind} check",
        status=status,  # type: ignore[arg-type]
        vantage=vantage,
        port=port,
        detail=detail,
        observed_at=START,
        evidence_id=evidence,
    )


def test_no_observations_is_an_explicit_unknown() -> None:
    result = infer([])
    assert result.probable_fault_domain is None
    assert result.confidence == "unknown"
    assert result.facts == []
    assert any("No diagnostic check could be run" in f.statement for f in result.unknowns)


def test_dns_failure_narrows_to_wan_dns_with_low_confidence() -> None:
    result = infer([observation("dns", "fail", vantage="internet")])
    assert result.probable_fault_domain == "wan-dns-external"
    assert result.confidence == "low"
    assert result.alternative_hypotheses
    assert result.recommended_next_checks


def test_external_failure_with_internal_success_narrows_but_does_not_prove() -> None:
    result = infer(
        [
            observation("icmp", "fail", vantage="internet"),
            observation("icmp", "pass", vantage="internal"),
        ]
    )
    assert result.probable_fault_domain == "firewall"
    assert result.confidence == "low"
    # The engine must keep open that the firewall is not the culprit.
    assert any("firewall" in f.statement.lower() for f in result.alternative_hypotheses)


def test_internal_failure_narrows_to_the_target() -> None:
    result = infer([observation("icmp", "fail", vantage="internal")])
    assert result.probable_fault_domain == "target"
    assert result.confidence == "low"
    # A failed ping never proves the host state on its own.
    assert any("ICMP" in f.statement for f in result.alternative_hypotheses)


def test_service_failure_with_a_reachable_host_narrows_to_the_service() -> None:
    result = infer(
        [
            observation("icmp", "pass", vantage="internal"),
            observation("tcp", "fail", vantage="internal", port=443),
        ]
    )
    assert result.probable_fault_domain == "service"
    assert result.confidence == "low"


def test_all_checks_passing_is_not_a_fault_domain() -> None:
    result = infer(
        [
            observation("dns", "pass", vantage="internal"),
            observation("tcp", "pass", vantage="internal", port=443),
        ]
    )
    assert result.probable_fault_domain is None
    assert result.confidence == "unknown"
    assert any("not reproduced" in f.statement for f in result.unknowns)


def test_unknown_observations_become_unknowns_not_facts() -> None:
    result = infer([observation("icmp", "unknown", detail="probe unavailable")])
    assert result.facts == []
    assert any("unknown" in f.statement for f in result.unknowns)


def test_conflicting_evidence_is_flagged() -> None:
    result = infer(
        [
            observation("tcp", "pass", vantage="internal", port=443),
            observation("tcp", "fail", vantage="internal", port=443),
        ]
    )
    assert len(result.contradictions) == 1
    assert "both passed and failed" in result.contradictions[0].statement


def test_evidence_ids_are_unique_and_preserved() -> None:
    result = infer(
        [
            observation("icmp", "pass", vantage="internal", evidence="e-1"),
            observation("tcp", "pass", vantage="internal", port=443, evidence="e-1"),
            observation("dns", "pass", vantage="internal", evidence="e-2"),
        ]
    )
    assert result.evidence_ids == ["e-1", "e-2"]


def test_every_inference_keeps_domain_and_confidence_consistent() -> None:
    scenarios = [
        [],
        [observation("icmp", "pass")],
        [observation("icmp", "fail", vantage="internal")],
        [observation("dns", "fail", vantage="internet")],
        [observation("tcp", "fail", vantage="internal", port=443)],
    ]
    for observations in scenarios:
        result = infer(observations)
        assert (result.probable_fault_domain is None) == (result.confidence == "unknown")


def test_build_run_produces_a_contract_valid_record() -> None:
    observations = [
        observation("icmp", "fail", vantage="internet", evidence="e-1"),
        observation("tcp", "pass", vantage="internal", port=443, evidence="e-2"),
    ]
    run = build_run(
        target="srv-db-01",
        target_id=None,
        symptom="Intermittent timeouts",
        vantage="internal",
        observations=observations,
        started_at=START,
        completed_at=START + timedelta(seconds=3),
    )
    validate("diagnostic_run", json.loads(run.model_dump_json(by_alias=True)))
    assert run.id.startswith("diagnostic-") and len(run.id) == 47
    assert [c.kind for c in run.checks] == ["icmp", "tcp"]
    assert len({c.id for c in run.checks}) == len(run.checks)
