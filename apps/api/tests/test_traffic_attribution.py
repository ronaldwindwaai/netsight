"""Who is behind a flow's source address: only through the identity service, only with its basis.

An address alone is never identity. The Flow Explorer asks the Step 6 service, shows what it says with
its basis (observed / inferred / unknown), names nobody when the answer is ambiguous or the caller's
role may not see people, and says "not connected" or "unknown" instead of inventing an answer.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from identity_support import (
    ALICE,
    ALICE_ACC,
    BOB,
    IP1,
    IP2,
    MAC_A,
    PC1,
    agent,
    assignment,
    dhcp,
    directory,
    radius,
)

from netsight_api.identity.model import Attribution as EngineAttribution
from netsight_api.identity.model import (
    Basis,
    CorrelationPolicy,
    EntityType,
    EvidenceKind,
    EvidenceRecord,
    EvidenceRef,
    Link,
    Reason,
    Relation,
    Resolution,
    ip_ref,
    person_ref,
)
from netsight_api.identity.service import IdentityService, SnapshotCache
from netsight_api.identity.sources import EvidenceBatch, MemoryEvidenceSource, SourceSlot
from netsight_api.schemas_traffic import TrafficFlow
from netsight_api.traffic.attribution import attribute_flows, flow_attribution

NOW = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)


def ago(hours: float) -> datetime:
    return NOW - timedelta(hours=hours)


def stamp(record: EvidenceRecord) -> EvidenceRecord:
    return EvidenceRecord(
        source="fixture",
        native_id=record.native_id,
        kind=record.kind,
        observed_at=record.observed_at,
        valid_from=record.valid_from,
        valid_to=record.valid_to,
        confidence=record.confidence,
        assertions=record.assertions,
        guest=record.guest,
    )


def evidence() -> list[EvidenceRecord]:
    return [
        directory(ALICE, ALICE_ACC),
        radius(ALICE_ACC, MAC_A, ago(2), None, observed_at=ago(0.1)),
        dhcp(IP1, MAC_A, ago(2), ago(-4)),
        assignment(ALICE, PC1),
        agent(PC1, IP1, ago(3), ago(-3), mac=MAC_A),
    ]


def service(records: list[EvidenceRecord] | None = None, policy: CorrelationPolicy | None = None):
    source = MemoryEvidenceSource("fixture", [stamp(r) for r in (records or evidence())])
    return IdentityService(
        [SourceSlot("fixture", source)], policy or CorrelationPolicy(), cache=SnapshotCache()
    )


def flow(source_ip: str = IP1.id, when: datetime | None = None, **overrides: Any) -> TrafficFlow:
    values: dict[str, Any] = {
        "observed_at": when or ago(0.5),
        "source_ip": source_ip,
        "source_device_id": None,
        "destination_ip": "203.0.113.9",
        "destination_host": None,
        "protocol": "tcp",
        "destination_port": 443,
        "bytes": 1000,
        "packets": None,
        "direction": "outbound",
        "application": None,
        "attribution": None,
    }
    values.update(overrides)
    return TrafficFlow(**values)


# --- the mapper ------------------------------------------------------------------------------------


def evidence_ref(source: str = "fixture") -> EvidenceRef:
    return EvidenceRef(
        f"{source}:x", source, EvidenceKind.RADIUS_SESSION, ago(1), ago(2), None, 0.9
    )


def identity_link(person: Any, basis: Basis, confidence: float, reason: Reason | None) -> Link:
    return Link(
        Relation.IDENTITY,
        ip_ref("10.0.0.10"),
        person,
        basis,
        confidence,
        ago(2),
        ago(-1),
        NOW,
        reason,
        (evidence_ref(),),
    )


def resolution(
    *links: Link,
    basis: Basis = Basis.OBSERVED,
    reason: Reason | None = None,
    ambiguous: bool = False,
    endpoint: tuple[Link, ...] = (),
) -> Resolution:
    attribution = EngineAttribution(basis, reason, ambiguous, tuple(links), ())
    return Resolution(ip_ref("10.0.0.10"), NOW, attribution, endpoint)


def test_a_single_observed_person_is_named_with_basis_and_confidence() -> None:
    alice = person_ref("directory", "alice", "Alice Example")
    result = flow_attribution(
        resolution(identity_link(alice, Basis.OBSERVED, 0.9, None)), level="person"
    )
    assert result.basis == "observed" and result.reason is None
    assert result.confidence == 0.9 and result.ambiguous is False
    assert result.person is not None and result.person.id == alice.id
    assert result.person.label == "Alice Example"


def test_an_inferred_person_keeps_its_reason_and_its_cap() -> None:
    alice = person_ref("directory", "alice")
    result = flow_attribution(
        resolution(
            identity_link(alice, Basis.INFERRED, 0.6, Reason.DECLARED_ASSIGNMENT),
            basis=Basis.INFERRED,
            reason=Reason.DECLARED_ASSIGNMENT,
        ),
        level="person",
    )
    assert (result.basis, result.reason, result.confidence) == (
        "inferred",
        "declared-assignment",
        0.6,
    )


def test_two_persons_are_never_resolved_by_picking_one() -> None:
    alice, bob = person_ref("directory", "alice"), person_ref("directory", "bob")
    result = flow_attribution(
        resolution(
            identity_link(alice, Basis.OBSERVED, 0.9, None),
            identity_link(bob, Basis.INFERRED, 0.5, Reason.NAME_MATCH),
        ),
        level="person",
    )
    assert result.basis == "unknown" and result.person is None and result.confidence is None
    assert result.ambiguous is True and result.reason == "multiple-candidates"


def test_an_ambiguous_engine_answer_names_nobody() -> None:
    result = flow_attribution(
        resolution(basis=Basis.UNKNOWN, reason=Reason.SHARED_ADDRESS, ambiguous=True),
        level="person",
    )
    assert (result.basis, result.reason, result.ambiguous, result.person) == (
        "unknown",
        "shared-address",
        True,
        None,
    )


def test_an_unknown_answer_carries_its_reason() -> None:
    for reason in (Reason.NO_EVIDENCE, Reason.EXPIRED, Reason.GUEST_NETWORK, Reason.VPN_NO_SESSION):
        result = flow_attribution(resolution(basis=Basis.UNKNOWN, reason=reason), level="person")
        assert result.basis == "unknown" and result.reason == reason.value and result.person is None


def test_the_endpoint_level_withholds_the_person_and_says_so() -> None:
    alice = person_ref("directory", "alice", "Alice Example")
    result = flow_attribution(
        resolution(identity_link(alice, Basis.OBSERVED, 0.9, None)), level="endpoint"
    )
    assert result.basis == "unknown" and result.reason == "restricted"
    assert result.person is None and result.confidence is None and result.ambiguous is False


def test_no_resolution_at_all_is_unknown_not_empty() -> None:
    result = flow_attribution(None, level="person")
    assert (result.basis, result.reason, result.person) == ("unknown", "source-unavailable", None)


# --- the service ---------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_current_lease_and_session_attribute_the_flow_as_observed() -> None:
    outcome = await attribute_flows(service(), [flow()], level="person", now=NOW)

    assert outcome.status.level == "person" and outcome.status.state == "ok"
    assert outcome.status.as_of == NOW
    (row,) = outcome.flows
    assert row.attribution is not None and row.attribution.basis in ("observed", "inferred")
    assert row.attribution.person is not None and row.attribution.person.id == ALICE.id
    assert row.attribution.person.label == "Alice Example"
    assert row.attribution.device is not None and row.attribution.device.id == PC1.id
    assert row.bytes == 1000 and row.source_ip == IP1.id  # nothing else changes


@pytest.mark.asyncio
async def test_the_endpoint_level_returns_the_device_but_never_the_person() -> None:
    outcome = await attribute_flows(service(), [flow()], level="endpoint", now=NOW)
    (row,) = outcome.flows
    assert outcome.status.level == "endpoint" and outcome.status.state == "ok"
    assert row.attribution is not None
    assert row.attribution.person is None and row.attribution.reason == "restricted"
    assert row.attribution.device is not None and row.attribution.device.id == PC1.id
    assert "Alice" not in outcome.flows[0].model_dump_json()


@pytest.mark.asyncio
async def test_an_address_with_no_evidence_is_unknown() -> None:
    outcome = await attribute_flows(service(), [flow(IP2.id)], level="person", now=NOW)
    (row,) = outcome.flows
    assert row.attribution is not None
    assert (row.attribution.basis, row.attribution.person) == ("unknown", None)


@pytest.mark.asyncio
async def test_an_external_address_is_never_attributed() -> None:
    outcome = await attribute_flows(service(), [flow("203.0.113.50")], level="person", now=NOW)
    row = outcome.flows[0]
    assert row.attribution is not None
    assert row.attribution.basis == "unknown" and row.attribution.person is None


@pytest.mark.asyncio
async def test_a_shared_address_is_ambiguous_and_names_nobody() -> None:
    policy = CorrelationPolicy(shared_cidrs=("10.0.0.10/32",))
    outcome = await attribute_flows(service(policy=policy), [flow()], level="person", now=NOW)
    row = outcome.flows[0]
    assert row.attribution is not None
    assert row.attribution.person is None and row.attribution.reason == "shared-address"


@pytest.mark.asyncio
async def test_the_answer_is_as_of_the_time_of_the_flow() -> None:
    # The lease began two hours ago: a flow from three hours ago was not Alice's by that evidence.
    early = flow(when=ago(3))
    outcome = await attribute_flows(service(), [early], level="person", now=NOW)
    row = outcome.flows[0]
    assert row.attribution is not None
    assert row.attribution.person is None or row.attribution.basis != "observed"


@pytest.mark.asyncio
async def test_a_flow_older_than_the_evidence_window_is_not_attributed() -> None:
    old = flow(when=NOW - timedelta(days=3))
    outcome = await attribute_flows(service(), [old], level="person", now=NOW)
    row = outcome.flows[0]
    assert row.attribution is not None
    assert (row.attribution.basis, row.attribution.reason) == ("unknown", "source-unavailable")


@pytest.mark.asyncio
async def test_an_unparseable_address_is_unknown_and_does_not_break_the_rest() -> None:
    rows = [flow("not-an-ip"), flow()]
    outcome = await attribute_flows(service(), rows, level="person", now=NOW)
    assert outcome.flows[0].attribution is not None
    assert outcome.flows[0].attribution.basis == "unknown"
    assert outcome.flows[1].attribution is not None
    assert outcome.flows[1].attribution.person is not None


@pytest.mark.asyncio
async def test_identity_not_connected_leaves_rows_unattributed_and_says_so() -> None:
    unconnected = IdentityService(
        [SourceSlot("wazuh", None), SourceSlot("netbox", None)], CorrelationPolicy()
    )
    outcome = await attribute_flows(unconnected, [flow()], level="person", now=NOW)
    assert outcome.status.state == "not-connected" and outcome.status.as_of is None
    assert outcome.flows[0].attribution is None


@pytest.mark.asyncio
async def test_no_identity_service_at_all_is_not_connected() -> None:
    outcome = await attribute_flows(None, [flow()], level="person", now=NOW)
    assert outcome.status.state == "not-connected"
    assert outcome.flows[0].attribution is None


class _Failing:
    name = "fixture"
    kinds = frozenset(EvidenceKind)

    async def fetch(self, **_: Any) -> EvidenceBatch:
        raise RuntimeError("indexer exploded: password=hunter2")


@pytest.mark.asyncio
async def test_a_failing_identity_source_is_unknown_and_leaks_nothing() -> None:
    failing = IdentityService([SourceSlot("fixture", _Failing())], CorrelationPolicy())
    outcome = await attribute_flows(failing, [flow()], level="person", now=NOW)
    assert outcome.status.state == "unknown"
    assert outcome.flows[0].attribution is None
    assert "hunter2" not in outcome.status.model_dump_json()


@pytest.mark.asyncio
async def test_no_rows_means_the_service_is_not_even_asked() -> None:
    class Boom:
        async def resolve_many(self, *_: Any, **__: Any) -> Any:
            raise AssertionError("must not be called")

    outcome = await attribute_flows(Boom(), [], level="person", now=NOW)  # type: ignore[arg-type]
    assert outcome.status.state == "not-evaluated" and outcome.flows == ()


@pytest.mark.asyncio
async def test_each_distinct_question_is_asked_once() -> None:
    asked: list[Any] = []

    class Spy(IdentityService):
        async def resolve_many(self, now: datetime, questions: Any) -> Any:
            asked.extend(questions)
            return await super().resolve_many(now, questions)

    source = MemoryEvidenceSource("fixture", [stamp(r) for r in evidence()])
    spy = Spy([SourceSlot("fixture", source)], CorrelationPolicy(), cache=SnapshotCache())
    same_moment = ago(0.5)
    rows = [flow(when=same_moment), flow(when=same_moment, bytes=5), flow(IP2.id, when=same_moment)]
    outcome = await attribute_flows(spy, rows, level="person", now=NOW)
    assert len(asked) == 2
    assert outcome.flows[0].attribution == outcome.flows[1].attribution


@pytest.mark.asyncio
async def test_the_work_is_bounded_to_the_row_limit() -> None:
    rows = [flow(f"10.0.{n // 250}.{n % 250 + 1}", when=ago(0.5)) for n in range(500)]
    outcome = await attribute_flows(service(), rows, level="person", now=NOW)
    assert len(outcome.flows) == 500 and outcome.status.state == "ok"
    with pytest.raises(ValueError):
        await attribute_flows(service(), rows + [flow()], level="person", now=NOW)


@pytest.mark.asyncio
async def test_rows_keep_their_order_and_values() -> None:
    rows = [flow(IP2.id, bytes=1), flow(IP1.id, bytes=2)]
    outcome = await attribute_flows(service(), rows, level="person", now=NOW)
    assert [r.bytes for r in outcome.flows] == [1, 2]
    assert [r.source_ip for r in outcome.flows] == [IP2.id, IP1.id]


def test_bob_is_not_alice() -> None:
    assert BOB.id != ALICE.id
    assert EntityType.PERSON.value == "person"
