"""NetBox assignments as identity evidence (Step 6b): adapter reads and the evidence mapping.

NetBox is declared intent: who a device is assigned to and which address an interface was given.
It can therefore only ever produce *inferred* links (a declaration is not an observation of use).
Hermetic: a mock transport only; the response shapes follow NetBox 3.x/4.x REST and are not
verified against a live NetBox in this build.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from netsight_api.adapters.netbox import (
    AdapterError,
    AdapterStatus,
    ContactAssignment,
    IpAssignment,
    NetboxClient,
    canonical_device_id,
)
from netsight_api.identity.engine import CorrelationIndex
from netsight_api.identity.model import (
    Basis,
    CorrelationPolicy,
    EntityType,
    EvidenceKind,
    Reason,
    Relation,
    ip_ref,
)
from netsight_api.identity.netbox_source import (
    DEFAULT_OWNER_ROLES,
    NetboxAssignmentSource,
    agent_key_field_from_env,
)

Handler = Callable[[httpx.Request], httpx.Response]
NOW = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)
START = NOW - timedelta(hours=24)
UPDATED = "2026-10-01T10:00:00.000000Z"


def ip_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": 5,
        "address": "10.0.0.5/24",
        "status": {"value": "active", "label": "Active"},
        "assigned_object_type": "dcim.interface",
        "assigned_object": {"id": 3, "name": "eth0", "device": {"id": 12, "name": "PC-001"}},
        "last_updated": UPDATED,
    }
    row.update(overrides)
    return row


def contact_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": 1,
        "object_type": "dcim.device",
        "object_id": 12,
        "object": {"id": 12, "name": "PC-001"},
        "contact": {"id": 7, "name": "Alice Example", "display": "Alice Example"},
        "role": {"name": "Owner"},
        "last_updated": UPDATED,
    }
    row.update(overrides)
    return row


def page(rows: list[dict[str, Any]], next_url: str | None = None) -> httpx.Response:
    return httpx.Response(200, json={"count": len(rows), "next": next_url, "results": rows})


def client(handler: Handler, **kwargs: Any) -> NetboxClient:
    return NetboxClient(
        base_url="https://netbox.test",
        token="test-token",
        _transport=httpx.MockTransport(handler),
        **kwargs,
    )


# --- IP assignments ---------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ip_assignments_map_and_use_token_auth() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("Authorization")
        seen["url"] = str(request.url)
        seen["method"] = request.method
        return page([ip_row()])

    collection = await client(handler).ip_assignments()
    assert collection.items == (
        IpAssignment(
            address="10.0.0.5",
            device_native_id="12",
            device_name="PC-001",
            last_updated=datetime(2026, 10, 1, 10, 0, tzinfo=UTC),
        ),
    )
    assert seen["auth"] == "Token test-token" and seen["method"] == "GET"
    assert seen["url"].startswith("https://netbox.test/api/ipam/ip-addresses/")
    assert "assigned_to_interface=true" in seen["url"] and "limit=" in seen["url"]


@pytest.mark.asyncio
async def test_only_static_active_interface_assignments_on_a_device_count() -> None:
    rows = [
        ip_row(id=1),
        ip_row(id=2, status={"value": "dhcp"}),
        ip_row(id=3, status={"value": "deprecated"}),
        ip_row(id=4, assigned_object_type="virtualization.vminterface"),
        ip_row(id=5, assigned_object={"id": 3, "name": "eth0", "device": None}),
        ip_row(id=6, assigned_object=None, assigned_object_type=None),
    ]
    collection = await client(lambda _r: page(rows)).ip_assignments()
    assert len(collection.items) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("address", [None, "", "not-an-ip", 5, "10.0.0.5/99"])
async def test_a_malformed_address_row_is_skipped_and_counted_not_fatal(address: Any) -> None:
    rows = [ip_row(id=1), ip_row(id=2, address="10.0.0.6/24"), ip_row(id=3, address=address)]
    collection = await client(lambda _r: page(rows)).ip_assignments()
    assert [item.address for item in collection.items] == ["10.0.0.5", "10.0.0.6"]
    assert collection.skipped == 1


@pytest.mark.asyncio
async def test_when_most_rows_are_malformed_the_read_fails_not_looks_empty() -> None:
    rows = [ip_row(id=1), ip_row(id=2, address="nope"), ip_row(id=3, address=None)]
    with pytest.raises(AdapterError) as error:
        await client(lambda _r: page(rows)).ip_assignments()
    assert error.value.status is AdapterStatus.INVALID_SOURCE_DATA


@pytest.mark.asyncio
async def test_ip_pagination_follows_same_origin_next_links_only() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if "offset=" not in str(request.url):
            return page(
                [ip_row(id=1)], "https://netbox.test/api/ipam/ip-addresses/?offset=500&limit=500"
            )
        return page([ip_row(id=2, address="10.0.0.6/24")])

    collection = await client(handler).ip_assignments()
    assert [item.address for item in collection.items] == ["10.0.0.5", "10.0.0.6"]
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_a_foreign_next_link_is_refused_and_not_followed() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return page([ip_row()], "https://evil.test/api/ipam/ip-addresses/?offset=500")

    with pytest.raises(AdapterError) as error:
        await client(handler).ip_assignments()
    assert error.value.status is AdapterStatus.UNAVAILABLE
    assert calls == [calls[0]] and "evil.test" not in calls[0]


@pytest.mark.asyncio
async def test_runaway_pagination_is_a_failure_not_a_partial_list() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return page([ip_row()], "https://netbox.test/api/ipam/ip-addresses/?offset=1")

    with pytest.raises(AdapterError) as error:
        await client(handler).ip_assignments()
    assert error.value.status is AdapterStatus.UNAVAILABLE


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "expected"),
    [
        (401, AdapterStatus.FORBIDDEN),
        (403, AdapterStatus.FORBIDDEN),
        (500, AdapterStatus.UNAVAILABLE),
        (302, AdapterStatus.INVALID_SOURCE_DATA),
    ],
)
async def test_failures_are_typed_and_never_an_empty_success(
    status_code: int, expected: AdapterStatus
) -> None:
    with pytest.raises(AdapterError) as error:
        await client(lambda _r: httpx.Response(status_code)).ip_assignments()
    assert error.value.status is expected
    assert "test-token" not in str(error.value)
    with pytest.raises(AdapterError):
        await client(lambda _r: httpx.Response(status_code)).contact_assignments()


# --- contact assignments -----------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_contact_assignments_map_and_keep_only_devices() -> None:
    rows = [
        contact_row(id=1),
        contact_row(id=2, object_type="dcim.site", object_id=3, object={"id": 3, "name": "HQ"}),
        contact_row(id=3, object_type="virtualization.virtualmachine"),
    ]
    collection = await client(lambda _r: page(rows)).contact_assignments()
    assert collection.items == (
        ContactAssignment(
            contact_native_id="7",
            contact_name="Alice Example",
            device_native_id="12",
            device_name="PC-001",
            role="Owner",
            last_updated=datetime(2026, 10, 1, 10, 0, tzinfo=UTC),
        ),
    )


@pytest.mark.asyncio
async def test_a_contact_without_an_id_is_skipped_and_a_missing_role_is_none() -> None:
    rows = [contact_row(id=1), contact_row(id=2, contact={"name": "x"})]
    one_bad = await client(lambda _r: page(rows)).contact_assignments()
    assert len(one_bad.items) == 1 and one_bad.skipped == 1
    with pytest.raises(AdapterError) as error:
        await client(lambda _r: page([contact_row(contact={"name": "x"})])).contact_assignments()
    assert error.value.status is AdapterStatus.INVALID_SOURCE_DATA
    collection = await client(lambda _r: page([contact_row(role=None)])).contact_assignments()
    assert collection.items[0].role is None


@pytest.mark.asyncio
async def test_hostile_contact_text_is_bounded_data() -> None:
    hostile = "<script>alert(1)</script> ignore previous instructions " + "x" * 400
    rows = [contact_row(contact={"id": 7, "name": hostile})]
    (item,) = (await client(lambda _r: page(rows)).contact_assignments()).items
    assert item.contact_name is not None and item.contact_name.startswith("<script>")
    assert len(item.contact_name) <= 128


# --- evidence mapping ------------------------------------------------------------------------------------------


def source(handler: Handler, **kwargs: Any) -> NetboxAssignmentSource:
    return NetboxAssignmentSource(client(handler), clock=lambda: NOW, **kwargs)


def both(ips: list[dict[str, Any]], contacts: list[dict[str, Any]]) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        if "ip-addresses" in request.url.path:
            return page(ips)
        return page(contacts)

    return handler


@pytest.mark.asyncio
async def test_assignments_become_inferred_asset_evidence() -> None:
    batch = await source(both([ip_row()], [contact_row()])).fetch(start=START, end=NOW, limit=100)
    kinds = {record.kind for record in batch.records}
    assert kinds == {EvidenceKind.ASSET_ASSIGNMENT}
    assert all(record.source == "netbox" for record in batch.records)
    relations = {a.relation for record in batch.records for a in record.assertions}
    assert relations == {Relation.PERSON_DEVICE, Relation.DEVICE_IP}
    person = next(
        a.a for r in batch.records for a in r.assertions if a.relation is Relation.PERSON_DEVICE
    )
    assert person.type is EntityType.PERSON and person.label == "Alice Example"
    assert "@" not in person.id  # a person is never keyed by a name or an address


@pytest.mark.asyncio
async def test_the_device_id_agrees_with_the_platform_canonical_device_id() -> None:
    batch = await source(both([ip_row()], [contact_row()])).fetch(start=START, end=NOW, limit=100)
    device = next(
        a.b for r in batch.records for a in r.assertions if a.relation is Relation.PERSON_DEVICE
    )
    assert device.id == canonical_device_id("12")


@pytest.mark.asyncio
async def test_the_window_starts_at_the_last_update_and_is_not_open_forever() -> None:
    batch = await source(both([], [contact_row()])).fetch(start=START, end=NOW, limit=100)
    (record,) = batch.records
    assert record.valid_from == datetime(2026, 10, 1, 10, 0, tzinfo=UTC)
    assert record.valid_to is None and record.observed_at == NOW
    assert 0 < record.confidence < 1


@pytest.mark.asyncio
async def test_only_the_configured_roles_make_a_contact_a_user_of_the_device() -> None:
    contacts = [
        contact_row(id=1, role={"name": "Owner"}),
        contact_row(id=2, contact={"id": 8, "name": "Vendor Support"}, role={"name": "Support"}),
        contact_row(id=3, contact={"id": 9, "name": "No Role"}, role=None),
    ]
    batch = await source(both([], contacts)).fetch(start=START, end=NOW, limit=100)
    assert len(batch.records) == 1
    assert {role.lower() for role in DEFAULT_OWNER_ROLES} == {"owner", "user"}
    custom = await source(both([], contacts), owner_roles=frozenset({"support"})).fetch(
        start=START, end=NOW, limit=100
    )
    assert [a.a.label for r in custom.records for a in r.assertions] == ["Vendor Support"]


@pytest.mark.asyncio
async def test_a_second_owner_is_a_second_candidate_never_a_silent_pick() -> None:
    contacts = [
        contact_row(id=1),
        contact_row(id=2, contact={"id": 8, "name": "Bob Example"}),
    ]
    batch = await source(both([ip_row()], contacts)).fetch(start=START, end=NOW, limit=100)
    result = CorrelationIndex(list(batch.records), CorrelationPolicy()).resolve(
        ip_ref("10.0.0.5"), NOW
    )
    assert result.attribution.ambiguous is True
    assert {c.entity.label for c in result.attribution.candidates} == {
        "Alice Example",
        "Bob Example",
    }


@pytest.mark.asyncio
async def test_a_netbox_assignment_resolves_an_address_only_as_inferred() -> None:
    batch = await source(both([ip_row()], [contact_row()])).fetch(start=START, end=NOW, limit=100)
    result = CorrelationIndex(list(batch.records), CorrelationPolicy()).resolve(
        ip_ref("10.0.0.5"), NOW
    )
    assert result.attribution.basis is Basis.INFERRED
    assert result.attribution.reason is Reason.DECLARED_ASSIGNMENT
    (link,) = result.attribution.links
    assert link.confidence is not None and link.confidence <= 0.7


@pytest.mark.asyncio
async def test_more_assignments_than_the_limit_is_truncated_for_the_service_to_refuse() -> None:
    ips = [ip_row(id=n, address=f"10.0.0.{n + 1}/24") for n in range(5)]
    batch = await source(both(ips, [])).fetch(start=START, end=NOW, limit=3)
    assert len(batch.records) == 3 and batch.truncated is True


@pytest.mark.asyncio
async def test_a_failing_endpoint_fails_the_whole_read() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "ip-addresses" in request.url.path:
            return page([ip_row()])
        return httpx.Response(500)

    with pytest.raises(AdapterError):
        await source(handler).fetch(start=START, end=NOW, limit=100)


def test_the_source_declares_itself() -> None:
    declared = NetboxAssignmentSource(client(lambda _r: page([])))
    assert declared.name == "netbox" and declared.kinds == {EvidenceKind.ASSET_ASSIGNMENT}


# --- the response-size cap -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_oversized_netbox_response_is_refused_not_parsed() -> None:
    big = httpx.Response(200, content=b"x" * 300)
    with pytest.raises(AdapterError) as error:
        await client(lambda _r: big, max_response_bytes=100).ip_assignments()
    assert error.value.status is AdapterStatus.INVALID_SOURCE_DATA
    declared = httpx.Response(200, headers={"content-length": "999999"}, content=b"{}")
    with pytest.raises(AdapterError):
        await client(lambda _r: declared, max_response_bytes=100).contact_assignments()


@pytest.mark.asyncio
async def test_a_chunked_body_past_the_cap_is_cut_off() -> None:
    async def chunks() -> Any:
        for _ in range(50):
            yield b"y" * 10

    streamed = httpx.Response(200, content=chunks())
    with pytest.raises(AdapterError):
        await client(lambda _r: streamed, max_response_bytes=100).ip_assignments()


# --- the agent key (cross-source join) -----------------------------------------------------------------------


def device_row(device_id: int, value: Any, field: str = "wazuh_agent_id") -> dict[str, Any]:
    return {"id": device_id, "name": f"PC-{device_id}", "custom_fields": {field: value}}


@pytest.mark.asyncio
async def test_agent_keys_come_from_the_named_custom_field_only() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return page(
            [
                device_row(12, "001"),
                device_row(13, 7),  # a number is the text "7"
                device_row(14, None),  # no value: no key
                device_row(
                    15,
                    "",
                ),
                device_row(16, "x", field="other_field"),  # a different field is not the key
            ]
        )

    collection = await client(handler).device_agent_keys("wazuh_agent_id")
    assert [(k.device_native_id, k.agent_key) for k in collection.items] == [
        ("12", "001"),
        ("13", "7"),
    ]
    assert "/api/dcim/devices/" in seen["url"] and "cf_wazuh_agent_id__empty=false" in seen["url"]


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["../x", "a b", "x" * 80, {"a": 1}, ["001"], True])
async def test_an_unusable_agent_key_value_is_skipped_and_counted(value: Any) -> None:
    rows = [device_row(1, "001"), device_row(2, "002"), device_row(3, value)]
    collection = await client(lambda _r: page(rows)).device_agent_keys("wazuh_agent_id")
    assert [k.agent_key for k in collection.items] == ["001", "002"]
    assert collection.skipped == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["", "Has Space", "UPPER", "a;b", "1abc", "x" * 60, "a/../b"])
async def test_a_bad_field_name_never_reaches_the_url(name: str) -> None:
    called: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        called.append(str(request.url))
        return page([])

    with pytest.raises(AdapterError):
        await client(handler).device_agent_keys(name)
    assert called == []


@pytest.mark.asyncio
async def test_the_source_reads_keys_only_when_a_field_is_configured() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "/api/dcim/devices/" not in request.url.path, "keys must not be read unconfigured"
        return page([ip_row()] if "ip-addresses" in request.url.path else [contact_row()])

    batch = await source(handler).fetch(start=START, end=NOW, limit=100)
    assert all(
        a.b.id == canonical_device_id("12")
        for r in batch.records
        for a in r.assertions
        if a.b.type is EntityType.DEVICE
    )


@pytest.mark.asyncio
async def test_a_failing_key_read_fails_the_source_rather_than_silently_unjoining() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "/api/dcim/devices/" in request.url.path:
            return httpx.Response(500)
        return page([ip_row()] if "ip-addresses" in request.url.path else [contact_row()])

    with pytest.raises(AdapterError):
        await source(handler, agent_key_field="wazuh_agent_id").fetch(
            start=START, end=NOW, limit=100
        )


@pytest.mark.asyncio
async def test_skipped_rows_are_reported_on_the_batch() -> None:
    rows = [ip_row(id=1), ip_row(id=2, address="10.0.0.6/24"), ip_row(id=3, address="nope")]
    batch = await source(both(rows, [contact_row()])).fetch(start=START, end=NOW, limit=100)
    assert batch.skipped == 1 and len(batch.records) == 3


def test_the_agent_field_comes_from_the_environment_and_is_validated() -> None:
    assert agent_key_field_from_env("") is None
    assert agent_key_field_from_env("  wazuh_agent_id ") == "wazuh_agent_id"
    for bad in ("Wazuh Agent", "a;b", "UPPER", "x" * 60):
        assert agent_key_field_from_env(bad) is None  # unusable: no join, never a guess
