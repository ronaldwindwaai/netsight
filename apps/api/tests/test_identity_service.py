"""The identity service (Step 6c): bounded evidence gathering, compute-on-read and the API views.

Sources are fakes; nothing here touches a network. Every response a view builds is validated
against the canonical JSON Schema as well as the pydantic model.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from typing import Any

import pytest
from identity_support import (
    ALICE,
    ALICE_ACC,
    BOB,
    BOB_ACC,
    IP1,
    IP2,
    MAC_A,
    MAC_B,
    PC1,
    PORT1,
    T0,
    VLAN10,
    agent,
    assignment,
    dhcp,
    directory,
    radius,
    vpn,
)

from netsight_api.contracts import validate
from netsight_api.identity.model import (
    CorrelationPolicy,
    EntityType,
    EvidenceKind,
    EvidenceRecord,
    ip_ref,
)
from netsight_api.identity.service import (
    EVIDENCE_LOOKBACK,
    IdentityService,
    SnapshotCache,
)
from netsight_api.identity.sources import EvidenceBatch, MemoryEvidenceSource, SourceSlot
from netsight_api.schemas import SecurityEvent, TrafficItem

NOW = T0 + timedelta(hours=3)  # 12:00 UTC


def hours_ago(hours: float) -> datetime:
    return NOW - timedelta(hours=hours)


class Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


class CountingSource:
    """A source that counts its reads and can be told to fail, stall or return odd batches."""

    def __init__(
        self,
        name: str,
        records: list[EvidenceRecord],
        *,
        kinds: frozenset[EvidenceKind] | None = None,
        error: Exception | None = None,
        delay: float = 0.0,
        truncated: bool = False,
    ) -> None:
        self.name = name
        self.kinds = kinds or frozenset(EvidenceKind)
        self._records = records
        self._error = error
        self._delay = delay
        self._truncated = truncated
        self.calls: list[dict[str, Any]] = []

    async def fetch(self, *, start: datetime, end: datetime, limit: int) -> EvidenceBatch:
        self.calls.append({"start": start, "end": end, "limit": limit})
        if self._delay:
            await asyncio.sleep(self._delay)
        if self._error is not None:
            raise self._error
        return EvidenceBatch(tuple(self._records), truncated=self._truncated)


def stamped(record: EvidenceRecord, source: str) -> EvidenceRecord:
    return EvidenceRecord(
        source=source,
        native_id=record.native_id,
        kind=record.kind,
        observed_at=record.observed_at,
        valid_from=record.valid_from,
        valid_to=record.valid_to,
        confidence=record.confidence,
        assertions=record.assertions,
        guest=record.guest,
    )


def alice_records() -> list[EvidenceRecord]:
    return [
        directory(ALICE, ALICE_ACC),
        radius(
            ALICE_ACC,
            MAC_A,
            hours_ago(2),
            None,
            port=PORT1,
            vlan=VLAN10,
            observed_at=hours_ago(0.1),
        ),
        dhcp(IP1, MAC_A, hours_ago(2), hours_ago(-4)),
        assignment(ALICE, PC1),
    ]


def make_service(
    *sources: Any, policy: CorrelationPolicy | None = None, **kwargs: Any
) -> IdentityService:
    slots = [SourceSlot(s.name, s) for s in sources]
    return IdentityService(slots, policy or CorrelationPolicy(), **kwargs)


def memory(name: str, records: list[EvidenceRecord]) -> MemoryEvidenceSource:
    return MemoryEvidenceSource(name, [stamped(r, name) for r in records])


def whole_world() -> MemoryEvidenceSource:
    """One source named for every record's source: tests that do not care about slots."""
    return _Multi(alice_records())


class _Multi(CountingSource):
    """A source allowed to speak for several names (stands in for a bundle of adapters)."""

    def __init__(self, records: list[EvidenceRecord]) -> None:
        super().__init__("fixture", records)

    async def fetch(self, *, start: datetime, end: datetime, limit: int) -> EvidenceBatch:
        batch = await super().fetch(start=start, end=end, limit=limit)
        return EvidenceBatch(tuple(stamped(r, "fixture") for r in batch.records))


def fixture_service(records: list[EvidenceRecord] | None = None, **kwargs: Any) -> IdentityService:
    return make_service(_Multi(records if records is not None else alice_records()), **kwargs)


def check(name: str, body: Any) -> dict[str, Any]:
    payload = body.model_dump(mode="json", by_alias=True)
    validate(name, payload)
    return payload  # type: ignore[no-any-return]


# --- state ---------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_configured_source_is_not_connected_with_nothing_estimated() -> None:
    service = IdentityService(
        [SourceSlot("wazuh", None), SourceSlot("netbox", None)], CorrelationPolicy()
    )
    body = check("user_list", await service.list_users(NOW, page=1, page_size=25))
    assert body["state"] == "not-connected" and body["items"] == [] and body["total"] == 0
    assert [(s["source"], s["state"]) for s in body["sources"]] == [
        ("wazuh", "not-connected"),
        ("netbox", "not-connected"),
    ]


@pytest.mark.asyncio
async def test_a_source_that_fails_is_unknown_and_never_an_empty_success() -> None:
    failing = CountingSource("wazuh", [], error=RuntimeError("boom: secret-token-123"))
    service = make_service(failing)
    body = check("user_list", await service.list_users(NOW, page=1, page_size=25))
    assert body["state"] == "unknown" and body["items"] == []
    assert body["sources"][0]["state"] == "unknown" and body["sources"][0]["record_count"] == 0
    assert "secret-token-123" not in str(body)


@pytest.mark.asyncio
async def test_one_failing_source_degrades_the_answer_but_does_not_hide_the_other() -> None:
    good = memory("directory", [directory(ALICE, ALICE_ACC)])
    bad = CountingSource("wazuh", [], error=RuntimeError("down"))
    body = check("user_list", await make_service(good, bad).list_users(NOW, page=1, page_size=25))
    assert body["state"] == "ok" and body["total"] == 1
    assert {s["source"]: s["state"] for s in body["sources"]} == {
        "directory": "ok",
        "wazuh": "unknown",
    }


@pytest.mark.asyncio
async def test_silence_from_a_failed_source_is_source_unavailable_not_no_evidence() -> None:
    good = memory("dhcp", [dhcp(IP1, MAC_A, hours_ago(2), hours_ago(-4))])
    bad = CountingSource("radius", [], error=RuntimeError("down"))
    body = check(
        "identity_resolve",
        await make_service(good, bad).resolve(NOW, None, "ip", IP1.id, redact_person=False),
    )
    assert body["attribution"]["reason"] == "source-unavailable"
    unreachable = check(
        "identity_resolve",
        await make_service(good).resolve(NOW, None, "ip", IP1.id, redact_person=False),
    )
    assert unreachable["attribution"]["reason"] == "ip-only"  # no failed source: just no account


@pytest.mark.asyncio
async def test_a_source_may_only_speak_for_itself() -> None:
    spoof = CountingSource("wazuh", [directory(ALICE, ALICE_ACC)])  # claims source "directory"
    body = check("user_list", await make_service(spoof).list_users(NOW, page=1, page_size=25))
    assert body["state"] == "unknown" and body["total"] == 0


@pytest.mark.asyncio
async def test_a_source_may_only_emit_the_kinds_it_is_declared_for() -> None:
    only_agents = CountingSource(
        "wazuh",
        [stamped(assignment(ALICE, PC1), "wazuh")],
        kinds=frozenset({EvidenceKind.ENDPOINT_AGENT}),
    )
    body = check("user_list", await make_service(only_agents).list_users(NOW, page=1, page_size=25))
    assert body["state"] == "unknown" and body["total"] == 0


@pytest.mark.asyncio
async def test_a_truncated_source_fails_closed_because_missing_evidence_hides_conflicts() -> None:
    cut = CountingSource(
        "directory", [stamped(directory(ALICE, ALICE_ACC), "directory")], truncated=True
    )
    body = check("user_list", await make_service(cut).list_users(NOW, page=1, page_size=25))
    assert body["state"] == "unknown" and body["total"] == 0


@pytest.mark.asyncio
async def test_a_source_that_ignores_its_limit_fails_closed() -> None:
    many = [
        stamped(dhcp(IP1, MAC_A, hours_ago(2), hours_ago(1), native_id=f"l-{n}"), "dhcp")
        for n in range(11)
    ]
    service = make_service(CountingSource("dhcp", many), per_source_limit=10)
    body = check("user_list", await service.list_users(NOW, page=1, page_size=25))
    assert body["state"] == "unknown"


@pytest.mark.asyncio
async def test_a_slow_source_times_out_as_unknown() -> None:
    slow = CountingSource("wazuh", [], delay=5)
    service = make_service(slow, source_timeout_seconds=0.05)
    body = check("user_list", await service.list_users(NOW, page=1, page_size=25))
    assert body["state"] == "unknown"


@pytest.mark.asyncio
async def test_sources_are_asked_for_a_bounded_window_and_a_bounded_count() -> None:
    source = CountingSource("directory", [])
    await make_service(source).list_users(NOW, page=1, page_size=25)
    (call,) = source.calls
    assert call["end"] == NOW and call["end"] - call["start"] == EVIDENCE_LOOKBACK
    assert 0 < call["limit"] <= 5000


@pytest.mark.asyncio
async def test_the_total_evidence_across_sources_is_bounded() -> None:
    def lease_set(name: str, count: int) -> CountingSource:
        return CountingSource(
            name,
            [
                stamped(dhcp(IP1, MAC_A, hours_ago(2), hours_ago(1), native_id=f"{name}-{n}"), name)
                for n in range(count)
            ],
        )

    first, second = lease_set("dhcp", 3000), lease_set("radius", 3000)
    service = make_service(first, second, per_source_limit=3000)
    body = check("user_list", await service.list_users(NOW, page=1, page_size=25))
    states = {s["source"]: s["state"] for s in body["sources"]}
    assert states == {
        "dhcp": "ok",
        "radius": "unknown",
    }  # the one that would exceed 5000 is refused


# --- the cache -------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_current_read_is_cached_briefly_and_only_for_the_ttl() -> None:
    clock = Clock()
    source = CountingSource("directory", [stamped(directory(ALICE, ALICE_ACC), "directory")])
    service = make_service(source, cache=SnapshotCache(ttl_seconds=30, clock=clock))
    await service.list_users(NOW, page=1, page_size=25)
    clock.value = 29
    await service.list_users(NOW, page=1, page_size=25)
    assert len(source.calls) == 1
    clock.value = 31
    await service.list_users(NOW + timedelta(seconds=31), page=1, page_size=25)
    assert len(source.calls) == 2


@pytest.mark.asyncio
async def test_a_historical_question_never_uses_or_fills_the_cache() -> None:
    source = CountingSource("directory", [stamped(directory(ALICE, ALICE_ACC), "directory")])
    service = make_service(source, cache=SnapshotCache(ttl_seconds=30, clock=Clock()))
    past = NOW - timedelta(days=2)
    await service.resolve(NOW, past, "ip", IP1.id, redact_person=False)
    await service.resolve(NOW, past, "ip", IP1.id, redact_person=False)
    await service.list_users(NOW, page=1, page_size=25)
    assert len(source.calls) == 3
    assert source.calls[0]["end"] == past


@pytest.mark.asyncio
async def test_concurrent_current_reads_share_one_upstream_read() -> None:
    source = CountingSource(
        "directory", [stamped(directory(ALICE, ALICE_ACC), "directory")], delay=0.05
    )
    service = make_service(source, cache=SnapshotCache(ttl_seconds=30, clock=Clock()))
    await asyncio.gather(*(service.list_users(NOW, page=1, page_size=25) for _ in range(5)))
    assert len(source.calls) == 1


# --- the list --------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_list_is_paged_sorted_and_bounded() -> None:
    records = [directory(p, a) for p, a in ((ALICE, ALICE_ACC), (BOB, BOB_ACC))]
    service = fixture_service(records)
    first = check("user_list", await service.list_users(NOW, page=1, page_size=1))
    second = check("user_list", await service.list_users(NOW, page=2, page_size=1))
    assert first["total"] == second["total"] == 2
    assert [first["items"][0]["display_name"], second["items"][0]["display_name"]] == [
        "Alice Example",
        "Bob Example",
    ]
    beyond = check("user_list", await service.list_users(NOW, page=3, page_size=1))
    assert beyond["items"] == [] and beyond["total"] == 2 and beyond["state"] == "ok"


@pytest.mark.asyncio
async def test_a_person_row_states_the_basis_of_their_presence() -> None:
    body = check("user_list", await fixture_service().list_users(NOW, page=1, page_size=25))
    (row,) = body["items"]
    assert row["presence"] == "observed" and row["session_count"] == 1
    assert row["assigned_device_count"] == 1 and row["account_count"] == 1
    assert "@" not in row["id"]  # never keyed by an address


# --- the detail ---------------------------------------------------------------------------------------------


class FakeTraffic:
    def __init__(self, rows: dict[str, int] | Exception) -> None:
        self.rows = rows
        self.calls: list[dict[str, Any]] = []

    async def top(self, *, dimension: str, start: datetime, end: datetime, limit: int) -> Any:
        self.calls.append({"dimension": dimension, "start": start, "end": end, "limit": limit})
        if isinstance(self.rows, Exception):
            raise self.rows
        items = [
            TrafficItem(
                rank=n + 1,
                subject_kind="ip",
                subject_id=None,
                label=address,
                bytes=size,
                packets=None,
                share=None,
            )
            for n, (address, size) in enumerate(self.rows.items())
        ]
        return items, end


class FakeSecurity:
    def __init__(self, events: list[SecurityEvent] | Exception) -> None:
        self.events_ = events
        self.calls: list[dict[str, Any]] = []

    async def events(self, *, start: datetime, end: datetime, limit: int) -> Any:
        self.calls.append({"start": start, "end": end, "limit": limit})
        if isinstance(self.events_, Exception):
            raise self.events_
        return self.events_, (self.events_[0].observed_at if self.events_ else None)


def event(
    identifier: str, when: datetime, ip: str | None, dest: str | None = None
) -> SecurityEvent:
    return SecurityEvent(
        id=identifier,
        observed_at=when,
        source="wazuh",
        severity="high",
        category=None,
        signature="ET SCAN <script>alert(1)</script>",
        source_ip=ip,
        destination_ip=dest,
        device_id=None,
    )


@pytest.mark.asyncio
async def test_the_detail_shows_profile_sessions_and_basis_for_every_link() -> None:
    body = check(
        "user_detail",
        await fixture_service().user_detail(NOW, ALICE.id, traffic=None, security=None),
    )
    user = body["user"]
    assert user["display_name"] == "Alice Example"
    (session,) = user["sessions"]
    assert session["kind"] == "wired" and session["basis"] == "observed"
    assert {link["relation"] for link in session["links"]} >= {
        "person-account",
        "account-mac",
        "ip-mac",
    }
    assert all(link["evidence"] for link in session["links"])
    (assigned,) = user["assigned_devices"]
    assert assigned["basis"] == "inferred" and assigned["reason"] == "declared-assignment"


@pytest.mark.asyncio
async def test_an_unknown_person_is_none_so_the_route_can_answer_404() -> None:
    assert await fixture_service().user_detail(NOW, BOB.id, traffic=None, security=None) is None


@pytest.mark.asyncio
async def test_without_a_traffic_or_security_source_those_blocks_are_not_connected() -> None:
    body = check(
        "user_detail",
        await fixture_service().user_detail(NOW, ALICE.id, traffic=None, security=None),
    )
    assert body["traffic"]["state"] == "not-connected" and body["traffic"]["items"] == []
    assert body["security"]["state"] == "not-connected" and body["security"]["items"] == []


@pytest.mark.asyncio
async def test_traffic_is_attributed_by_address_inferred_and_only_where_the_link_covers_the_window() -> (
    None
):
    # Alice's lease began two hours ago, so it covers the whole last hour.
    traffic = FakeTraffic({IP1.id: 5_000_000, "10.0.0.99": 7})
    body = check(
        "user_detail",
        await fixture_service().user_detail(NOW, ALICE.id, traffic=traffic, security=None),
    )
    block = body["traffic"]
    assert block["state"] == "ok" and block["basis"] == "inferred"
    assert block["items"] == [{"address": IP1.id, "bytes": 5_000_000, "covers_window": True}]
    (call,) = traffic.calls
    assert call["dimension"] == "talkers" and call["end"] - call["start"] == timedelta(hours=1)
    assert 0 < call["limit"] <= 100


@pytest.mark.asyncio
async def test_an_address_missing_from_the_talkers_is_null_not_zero() -> None:
    traffic = FakeTraffic({"10.0.0.99": 7})
    body = check(
        "user_detail",
        await fixture_service().user_detail(NOW, ALICE.id, traffic=traffic, security=None),
    )
    assert body["traffic"]["items"] == [{"address": IP1.id, "bytes": None, "covers_window": True}]


@pytest.mark.asyncio
async def test_an_address_bound_only_recently_does_not_cover_the_window() -> None:
    recent = [
        directory(ALICE, ALICE_ACC),
        radius(ALICE_ACC, MAC_A, hours_ago(0.5), None, observed_at=hours_ago(0.1)),
        dhcp(IP1, MAC_A, hours_ago(0.5), hours_ago(-4)),
    ]
    traffic = FakeTraffic({IP1.id: 9})
    body = check(
        "user_detail",
        await fixture_service(recent).user_detail(NOW, ALICE.id, traffic=traffic, security=None),
    )
    assert body["traffic"]["items"] == [{"address": IP1.id, "bytes": None, "covers_window": False}]


@pytest.mark.asyncio
async def test_a_failing_traffic_source_is_unknown_and_shows_no_numbers() -> None:
    body = check(
        "user_detail",
        await fixture_service().user_detail(
            NOW, ALICE.id, traffic=FakeTraffic(RuntimeError("clickhouse down")), security=None
        ),
    )
    assert body["traffic"]["state"] == "unknown" and body["traffic"]["items"] == []
    assert body["user"] is not None  # the profile itself is unaffected


@pytest.mark.asyncio
async def test_security_events_are_attributed_by_the_address_at_the_time_of_the_event() -> None:
    swapped = [
        directory(ALICE, ALICE_ACC),
        directory(BOB, BOB_ACC),
        dhcp(IP1, MAC_A, hours_ago(5), hours_ago(3), native_id="a"),
        radius(ALICE_ACC, MAC_A, hours_ago(5), hours_ago(3), native_id="ra"),
        dhcp(IP1, MAC_B, hours_ago(3), hours_ago(-1), native_id="b"),
        radius(BOB_ACC, MAC_B, hours_ago(3), None, native_id="rb", observed_at=hours_ago(0.1)),
    ]
    events = [
        event("evt-alice", hours_ago(4), IP1.id),
        event("evt-bob", hours_ago(1), IP1.id),
        event("evt-gap", hours_ago(3), "10.0.0.250"),
        event("evt-public", hours_ago(2), "203.0.113.5", IP1.id),
    ]
    service = fixture_service(swapped)
    alice = check(
        "user_detail",
        await service.user_detail(NOW, ALICE.id, traffic=None, security=FakeSecurity(events)),
    )
    bob = check(
        "user_detail",
        await service.user_detail(NOW, BOB.id, traffic=None, security=FakeSecurity(events)),
    )
    assert [item["event_id"] for item in alice["security"]["items"]] == ["evt-alice"]
    assert [item["event_id"] for item in bob["security"]["items"]] == ["evt-bob", "evt-public"]
    only = alice["security"]["items"][0]
    assert only["link"]["basis"] == "observed" and only["link"]["evidence"]
    assert only["signature"] == "ET SCAN <script>alert(1)</script>"  # data, untouched


@pytest.mark.asyncio
async def test_security_events_on_an_ambiguous_address_are_not_attributed_to_anyone() -> None:
    clash = [
        directory(ALICE, ALICE_ACC),
        directory(BOB, BOB_ACC),
        dhcp(IP1, MAC_A, hours_ago(5), hours_ago(-1), native_id="a"),
        dhcp(IP1, MAC_B, hours_ago(5), hours_ago(-1), native_id="b"),
        radius(ALICE_ACC, MAC_A, hours_ago(5), None, native_id="ra", observed_at=hours_ago(0.1)),
        radius(BOB_ACC, MAC_B, hours_ago(5), None, native_id="rb", observed_at=hours_ago(0.1)),
    ]
    events = [event("evt-1", hours_ago(1), IP1.id)]
    service = fixture_service(clash)
    for person in (ALICE, BOB):
        body = check(
            "user_detail",
            await service.user_detail(NOW, person.id, traffic=None, security=FakeSecurity(events)),
        )
        assert body["security"]["items"] == []


@pytest.mark.asyncio
async def test_security_matches_are_capped_and_marked_truncated() -> None:
    events = [event(f"evt-{n}", hours_ago(1) - timedelta(seconds=n), IP1.id) for n in range(25)]
    body = check(
        "user_detail",
        await fixture_service().user_detail(
            NOW, ALICE.id, traffic=None, security=FakeSecurity(events)
        ),
    )
    assert len(body["security"]["items"]) == 20 and body["security"]["truncated"] is True


@pytest.mark.asyncio
async def test_a_failing_security_source_is_unknown() -> None:
    body = check(
        "user_detail",
        await fixture_service().user_detail(
            NOW, ALICE.id, traffic=None, security=FakeSecurity(RuntimeError("indexer down"))
        ),
    )
    assert body["security"]["state"] == "unknown" and body["security"]["items"] == []


@pytest.mark.asyncio
async def test_the_security_read_is_bounded() -> None:
    security = FakeSecurity([])
    await fixture_service().user_detail(NOW, ALICE.id, traffic=None, security=security)
    (call,) = security.calls
    assert call["end"] - call["start"] <= EVIDENCE_LOOKBACK and 0 < call["limit"] <= 500


# --- resolve ----------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_names_the_person_with_basis_and_evidence() -> None:
    body = check(
        "identity_resolve",
        await fixture_service().resolve(NOW, None, "ip", IP1.id, redact_person=False),
    )
    assert body["state"] == "ok" and body["subject"] == {"kind": "ip", "value": IP1.id}
    assert body["attribution"]["basis"] == "observed"
    (link,) = [x for x in body["attribution"]["links"] if x["basis"] == "observed"]
    assert link["target"]["label"] == "Alice Example" and link["evidence"]
    assert body["as_of"].startswith("2026-10-11T12:00:00")


@pytest.mark.asyncio
async def test_a_restricted_caller_gets_the_endpoint_but_not_the_person() -> None:
    full = check(
        "identity_resolve",
        await fixture_service().resolve(NOW, None, "ip", IP1.id, redact_person=False),
    )
    limited = check(
        "identity_resolve",
        await fixture_service().resolve(NOW, None, "ip", IP1.id, redact_person=True),
    )
    assert limited["attribution"] == {
        "basis": "unknown",
        "reason": "restricted",
        "ambiguous": False,
        "links": [],
        "candidates": [],
    }
    assert [(x["relation"], x["basis"]) for x in limited["endpoint"]] == [
        (x["relation"], x["basis"]) for x in full["endpoint"]
    ]
    text = str(limited)
    assert "Alice" not in text and "person-" not in text
    # A source's own record ids can embed a user name or an account id: they are made opaque, still
    # stable (the same record keeps the same id) so two links can be seen to rest on one record.
    assert "account-" not in text and "radius-" not in text.replace("radius-session", "")
    full_ids = {e["id"] for x in full["endpoint"] for e in x["evidence"]}
    limited_ids = {e["id"] for x in limited["endpoint"] for e in x["evidence"]}
    assert limited_ids and not (limited_ids & full_ids)
    again = check(
        "identity_resolve",
        await fixture_service().resolve(NOW, None, "ip", IP1.id, redact_person=True),
    )
    assert {e["id"] for x in again["endpoint"] for e in x["evidence"]} == limited_ids


@pytest.mark.asyncio
async def test_resolve_for_a_time_in_the_past_reads_the_window_ending_then() -> None:
    source = _Multi(alice_records())
    service = make_service(source)
    past = NOW - timedelta(days=1)
    body = check(
        "identity_resolve", await service.resolve(NOW, past, "ip", IP1.id, redact_person=False)
    )
    assert body["as_of"].startswith("2026-10-10T12:00:00")
    assert body["attribution"]["basis"] == "unknown"  # the lease did not exist yet
    assert source.calls[0]["end"] == past


@pytest.mark.asyncio
async def test_resolve_accepts_mac_and_hostname_subjects() -> None:
    service = fixture_service(alice_records() + [agent(PC1, IP1, hours_ago(1), None, mac=MAC_A)])
    by_mac = check(
        "identity_resolve", await service.resolve(NOW, None, "mac", MAC_A.id, redact_person=False)
    )
    assert by_mac["attribution"]["basis"] == "observed"
    by_name = check(
        "identity_resolve",
        await service.resolve(NOW, None, "hostname", "pc-001", redact_person=False),
    )
    assert by_name["attribution"]["basis"] == "inferred"
    assert by_name["attribution"]["reason"] == "name-match"


@pytest.mark.asyncio
async def test_resolve_obeys_the_policy_for_shared_addresses() -> None:
    policy = CorrelationPolicy(shared_cidrs=("10.0.0.0/24",))
    body = check(
        "identity_resolve",
        await fixture_service(policy=policy).resolve(NOW, None, "ip", IP1.id, redact_person=False),
    )
    assert body["attribution"]["reason"] == "shared-address"


@pytest.mark.asyncio
async def test_a_hostile_subject_is_echoed_as_data() -> None:
    body = check(
        "identity_resolve",
        await fixture_service().resolve(NOW, None, "hostname", "x" * 128, redact_person=False),
    )
    assert body["subject"]["value"] == "x" * 128


# --- summary ------------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_summary_carries_counts_and_no_names_or_ids() -> None:
    records = alice_records() + [
        directory(BOB, BOB_ACC),
        vpn(BOB_ACC, ip_ref("10.200.0.5"), hours_ago(1), hours_ago(-1)),
    ]
    body = check("users_aggregate", await fixture_service(records).summary(NOW))
    assert body["people_total"] == 2
    assert body["with_observed_session"] == 2 and body["with_inferred_session"] == 0
    assert body["without_session_evidence"] == 0 and body["vpn_sessions"] == 1
    text = str(body)
    assert "Alice" not in text and "person-" not in text and "account-" not in text


@pytest.mark.asyncio
async def test_an_empty_summary_is_not_connected_not_zero_people() -> None:
    body = check(
        "users_aggregate",
        await IdentityService([SourceSlot("wazuh", None)], CorrelationPolicy()).summary(NOW),
    )
    assert body["state"] == "not-connected" and body["people_total"] is None


# --- the memory source -----------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_memory_source_returns_only_records_that_overlap_the_window() -> None:
    inside = stamped(dhcp(IP1, MAC_A, hours_ago(2), hours_ago(1)), "fixture")
    outside = stamped(dhcp(IP2, MAC_B, hours_ago(100), hours_ago(99)), "fixture")
    batch = await MemoryEvidenceSource("fixture", [inside, outside]).fetch(
        start=hours_ago(24), end=NOW, limit=10
    )
    assert batch.records == (inside,) and batch.truncated is False


@pytest.mark.asyncio
async def test_the_memory_source_reports_truncation() -> None:
    records = [
        stamped(dhcp(IP1, MAC_A, hours_ago(2), hours_ago(1), native_id=f"l-{n}"), "fixture")
        for n in range(5)
    ]
    batch = await MemoryEvidenceSource("fixture", records).fetch(
        start=hours_ago(24), end=NOW, limit=3
    )
    assert len(batch.records) == 3 and batch.truncated is True


def test_entity_types_are_exposed_for_the_views() -> None:
    assert EntityType.PERSON.value == "person"


# --- review fixes: people() once per snapshot, off the loop; skipped rows; the register note -----------


@pytest.mark.asyncio
async def test_people_is_computed_once_per_snapshot_and_off_the_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threading

    from netsight_api.identity.engine import CorrelationIndex

    threads: list[int] = []
    real = CorrelationIndex.people

    def spy(self: CorrelationIndex, when: datetime) -> Any:
        threads.append(threading.get_ident())
        return real(self, when)

    monkeypatch.setattr(CorrelationIndex, "people", spy)
    service = fixture_service(cache=SnapshotCache())
    listed = await service.list_users(NOW, page=1, page_size=25)
    await service.list_users(NOW, page=1, page_size=1)
    summary = await service.summary(NOW)
    assert len(threads) == 1, "list, a second page and the summary share one computation"
    assert threads[0] != threading.get_ident(), "the heavy walk must not run on the event loop"
    assert listed.total == summary.people_total == 1


@pytest.mark.asyncio
async def test_concurrent_list_and_summary_requests_share_one_computation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from netsight_api.identity.engine import CorrelationIndex

    calls: list[int] = []
    real = CorrelationIndex.people

    def spy(self: CorrelationIndex, when: datetime) -> Any:
        calls.append(1)
        return real(self, when)

    monkeypatch.setattr(CorrelationIndex, "people", spy)
    service = fixture_service(cache=SnapshotCache())
    await asyncio.gather(
        *(service.list_users(NOW, page=1, page_size=25) for _ in range(4)),
        *(service.summary(NOW) for _ in range(4)),
    )
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_a_failed_people_computation_is_not_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    from netsight_api.identity.engine import CorrelationIndex

    state = {"fail": True}
    real = CorrelationIndex.people

    def flaky(self: CorrelationIndex, when: datetime) -> Any:
        if state["fail"]:
            raise RuntimeError("boom")
        return real(self, when)

    monkeypatch.setattr(CorrelationIndex, "people", flaky)
    service = fixture_service(cache=SnapshotCache())
    with pytest.raises(RuntimeError):
        await service.summary(NOW)
    state["fail"] = False
    assert (await service.summary(NOW)).people_total == 1


@pytest.mark.asyncio
async def test_skipped_source_rows_are_logged_with_a_count_and_do_not_blank_the_source(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class Skipping(CountingSource):
        async def fetch(self, *, start: datetime, end: datetime, limit: int) -> EvidenceBatch:
            return EvidenceBatch(tuple(stamped(r, self.name) for r in self._records), skipped=3)

    caplog.set_level("WARNING", logger="netsight_api")
    source = Skipping("fixture", alice_records())
    body = check("user_list", await make_service(source).list_users(NOW, page=1, page_size=25))
    assert body["state"] == "ok" and body["total"] == 1
    messages = [r for r in caplog.records if "skipped" in r.getMessage()]
    assert messages and getattr(messages[0], "skipped_rows", None) == 3
    assert getattr(messages[0], "source", None) == "fixture"


@pytest.mark.asyncio
async def test_a_historical_answer_that_leans_on_the_register_says_it_is_current_state() -> None:
    register = [assignment(ALICE, PC1), agent(PC1, IP1, hours_ago(30), None)]
    past = NOW - timedelta(hours=2)
    service = fixture_service(register)
    historical = check(
        "identity_resolve", await service.resolve(NOW, past, "ip", IP1.id, redact_person=False)
    )
    current = check(
        "identity_resolve", await service.resolve(NOW, None, "ip", IP1.id, redact_person=False)
    )
    assert historical["notes"] == ["register-is-current-state"]
    assert current["notes"] == []


@pytest.mark.asyncio
async def test_a_historical_answer_without_any_register_evidence_carries_no_note() -> None:
    service = fixture_service([dhcp(IP1, MAC_A, hours_ago(5), hours_ago(1))])
    body = check(
        "identity_resolve",
        await service.resolve(NOW, NOW - timedelta(hours=2), "ip", IP1.id, redact_person=False),
    )
    assert body["notes"] == []
