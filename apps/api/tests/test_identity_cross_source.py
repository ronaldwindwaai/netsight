"""Wazuh and NetBox evidence about the same host (Step 6 review H1, M2).

The two sources mint different device entities (the Wazuh agent id vs the NetBox device id), and an
address has one device at a time, so without more the same host always conflicts. The only thing
that may join them is an explicit, operator-controlled key: a NetBox custom field carrying the
Wazuh agent id (manager-assigned, not chosen by the agent). A hostname or an agent name is spoofable
telemetry and never merges anything. Absent the key, the answer stays ``conflicting-evidence``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from netsight_api.adapters.netbox import (
    ContactAssignment,
    ContactAssignmentCollection,
    DeviceAgentKey,
    DeviceAgentKeyCollection,
    IpAssignment,
    IpAssignmentCollection,
    canonical_device_id,
)
from netsight_api.adapters.wazuh import AgentInventory, WazuhAgent
from netsight_api.identity.engine import CorrelationIndex
from netsight_api.identity.model import (
    Basis,
    CorrelationPolicy,
    EvidenceRecord,
    Reason,
    Resolution,
    device_ref,
    hostname_ref,
    ip_ref,
)
from netsight_api.identity.netbox_source import NetboxAssignmentSource
from netsight_api.identity.wazuh_source import WazuhAgentSource

NOW = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)
START = NOW - timedelta(hours=24)
FIELD = "wazuh_agent_id"
VICTIM_IP = "10.0.0.10"


def agent(agent_id: str, name: str, ip: str) -> WazuhAgent:
    return WazuhAgent(
        agent_id=agent_id,
        name=name,
        ip=ip,
        status="active",
        observed_at=NOW - timedelta(minutes=5),
        last_keep_alive=NOW - timedelta(minutes=5),
    )


def ip_row(device: str, name: str, address: str) -> IpAssignment:
    return IpAssignment(address, device, name, NOW - timedelta(days=10))


def owner(
    device: str, name: str, contact: str = "7", person: str = "Alice Example"
) -> ContactAssignment:
    return ContactAssignment(contact, person, device, name, "Owner", NOW - timedelta(days=10))


class FakeWazuh:
    def __init__(self, agents: list[WazuhAgent]) -> None:
        self._agents = agents

    async def agents(self, *, start: datetime, end: datetime, limit: int) -> AgentInventory:
        return AgentInventory(tuple(self._agents), False, 0)


class FakeNetbox:
    def __init__(
        self,
        ips: list[IpAssignment],
        contacts: list[ContactAssignment],
        keys: list[tuple[str, str]] | None = None,
    ) -> None:
        self._ips, self._contacts = ips, contacts
        self._keys = keys or []
        self.key_reads: list[str] = []

    async def ip_assignments(self) -> IpAssignmentCollection:
        return IpAssignmentCollection(tuple(self._ips), NOW)

    async def contact_assignments(self) -> ContactAssignmentCollection:
        return ContactAssignmentCollection(tuple(self._contacts), NOW)

    async def device_agent_keys(self, field: str) -> DeviceAgentKeyCollection:
        self.key_reads.append(field)
        return DeviceAgentKeyCollection(
            tuple(DeviceAgentKey(device, key) for device, key in self._keys), NOW
        )


async def evidence(
    agents: list[WazuhAgent],
    netbox: FakeNetbox,
    *,
    field: str | None = None,
) -> list[EvidenceRecord]:
    wazuh = await WazuhAgentSource(FakeWazuh(agents)).fetch(start=START, end=NOW, limit=100)
    register = await NetboxAssignmentSource(netbox, clock=lambda: NOW, agent_key_field=field).fetch(
        start=START, end=NOW, limit=100
    )
    return [*wazuh.records, *register.records]


def legit_netbox(keys: list[tuple[str, str]] | None = None) -> FakeNetbox:
    return FakeNetbox([ip_row("12", "PC-001", VICTIM_IP)], [owner("12", "PC-001")], keys)


def legit_agent() -> WazuhAgent:
    return agent("001", "PC-001", VICTIM_IP)


def resolve(
    records: list[EvidenceRecord],
    subject: str,
    policy: CorrelationPolicy | None = None,
) -> Resolution:
    return CorrelationIndex(records, policy or CorrelationPolicy()).resolve(ip_ref(subject), NOW)


# --- keyed: one host, one device ------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_keyed_host_is_one_device_and_resolves_as_a_declared_assignment() -> None:
    netbox = legit_netbox(keys=[("12", "001")])
    records = await evidence([legit_agent()], netbox, field=FIELD)
    result = resolve(records, VICTIM_IP)
    attribution = result.attribution
    assert netbox.key_reads == [FIELD]
    assert attribution.basis is Basis.INFERRED and attribution.reason is Reason.DECLARED_ASSIGNMENT
    assert not attribution.ambiguous
    (link,) = attribution.links
    assert link.target is not None and link.target.label == "Alice Example"
    assert link.confidence is not None and link.confidence <= 0.7
    # the endpoint shows one device-address link backed by both sources, not a conflict
    device_links = [item for item in result.endpoint if item.relation.value == "device-ip"]
    assert len(device_links) == 1 and not device_links[0].ambiguous
    assert {ref.source for ref in device_links[0].evidence} == {"wazuh", "netbox"}


@pytest.mark.asyncio
async def test_the_key_joins_by_the_agent_id_only_never_by_the_name() -> None:
    netbox = legit_netbox(keys=[("12", "001")])
    records = await evidence(
        [agent("001", "totally-different-name", VICTIM_IP)], netbox, field=FIELD
    )
    assert resolve(records, VICTIM_IP).attribution.reason is Reason.DECLARED_ASSIGNMENT


# --- unkeyed: never merged, never a wrong pick -----------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("configured", [None, FIELD])
async def test_without_a_key_the_same_host_stays_conflicting(configured: str | None) -> None:
    # No field configured, or configured but this device carries no value: no merge.
    records = await evidence([legit_agent()], legit_netbox(), field=configured)
    attribution = resolve(records, VICTIM_IP).attribution
    assert attribution.reason is Reason.CONFLICTING
    assert attribution.basis is not Basis.OBSERVED
    assert all(link.reason is Reason.CONFLICTING for link in attribution.links)
    assert all(link.confidence is not None and link.confidence <= 0.7 for link in attribution.links)


@pytest.mark.asyncio
async def test_a_key_claimed_by_two_netbox_devices_merges_neither() -> None:
    netbox = FakeNetbox(
        [ip_row("12", "PC-001", VICTIM_IP), ip_row("13", "PC-013", "10.0.0.13")],
        [owner("12", "PC-001"), owner("13", "PC-013", "8", "Bob Example")],
        keys=[("12", "001"), ("13", "001")],
    )
    records = await evidence([legit_agent()], netbox, field=FIELD)
    ids = {a.b.id for r in records for a in r.assertions if a.relation.value == "person-device"}
    assert ids == {canonical_device_id("12"), canonical_device_id("13")}
    assert device_ref("wazuh", "001").id not in ids
    assert resolve(records, VICTIM_IP).attribution.reason is Reason.CONFLICTING


@pytest.mark.asyncio
async def test_an_unusable_key_value_is_ignored_not_trusted() -> None:
    netbox = legit_netbox(keys=[("12", "../001; DROP")])
    records = await evidence([legit_agent()], netbox, field=FIELD)
    assert resolve(records, VICTIM_IP).attribution.reason is Reason.CONFLICTING


# --- hostile names ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_agent_named_like_a_register_device_does_not_merge_with_it() -> None:
    rogue = agent("666", "PC-001", "10.0.0.66")
    records = await evidence(
        [legit_agent(), rogue], legit_netbox(keys=[("12", "001")]), field=FIELD
    )
    assert device_ref("wazuh", "666", "PC-001").id != canonical_device_id("12")
    # the rogue's own address names nobody
    assert resolve(records, "10.0.0.66").attribution.basis is Basis.UNKNOWN
    assert resolve(records, "10.0.0.66").attribution.links == ()
    # the owner's address still resolves, undisturbed
    assert resolve(records, VICTIM_IP).attribution.reason is Reason.DECLARED_ASSIGNMENT


@pytest.mark.asyncio
async def test_a_hostile_name_cannot_steal_the_registered_owner_unkeyed() -> None:
    rogue = agent("666", "PC-001", "10.0.0.66")
    records = await evidence([rogue], legit_netbox())  # unkeyed
    index = CorrelationIndex(records, CorrelationPolicy())
    assert index.resolve(ip_ref("10.0.0.66"), NOW).attribution.links == ()
    # a name lookup is only ever a name match, never better than inferred, and names the owner
    by_name = index.resolve(hostname_ref("pc-001"), NOW).attribution
    assert by_name.reason in (Reason.NAME_MATCH, Reason.MULTIPLE_CANDIDATES)
    assert all(link.basis is Basis.INFERRED for link in by_name.links)


@pytest.mark.asyncio
async def test_the_name_match_does_not_cite_person_device_records_as_endpoint_evidence() -> None:
    records = await evidence([legit_agent()], legit_netbox(keys=[("12", "001")]), field=FIELD)
    result = CorrelationIndex(records, CorrelationPolicy()).resolve(hostname_ref("pc-001"), NOW)
    owner_ids = {r.id for r in records if r.native_id.startswith("owner-")}
    assert owner_ids
    for link in result.endpoint:
        assert not owner_ids & {ref.id for ref in link.evidence}


# --- M2: a rogue agent reporting a registered address ---------------------------------------------


@pytest.mark.asyncio
async def test_a_rogue_agent_on_a_registered_address_weakens_it_unless_the_range_is_static() -> (
    None
):
    rogue = agent("666", "whatever", VICTIM_IP)
    keyed = legit_netbox(keys=[("12", "001")])
    records = await evidence([rogue], keyed, field=FIELD)
    # no static range configured: the claim is a conflict (honest, never the rogue's pick)
    weakened = resolve(records, VICTIM_IP).attribution
    assert weakened.reason is Reason.CONFLICTING
    assert all(
        link.target is not None and link.target.label == "Alice Example" for link in weakened.links
    )
    # with the server range configured the agent's claim about it is ignored
    policy = CorrelationPolicy(static_cidrs=("10.0.0.0/28",))
    held = resolve(records, VICTIM_IP, policy)
    assert held.attribution.reason is Reason.DECLARED_ASSIGNMENT
    assert not held.attribution.ambiguous
    assert all("wazuh" not in {ref.source for ref in link.evidence} for link in held.endpoint)


@pytest.mark.asyncio
async def test_agent_claims_outside_the_static_ranges_still_count() -> None:
    policy = CorrelationPolicy(static_cidrs=("10.0.1.0/24",))
    records = await evidence([legit_agent()], legit_netbox(keys=[("12", "001")]), field=FIELD)
    result = resolve(records, VICTIM_IP, policy)
    device_links = [item for item in result.endpoint if item.relation.value == "device-ip"]
    assert {ref.source for ref in device_links[0].evidence} == {"wazuh", "netbox"}


def test_the_static_ranges_are_validated_and_classify_addresses() -> None:
    policy = CorrelationPolicy(static_cidrs=("10.0.0.0/28", "fd00::/64"))
    assert policy.is_static_address("10.0.0.5") and policy.is_static_address("fd00::7")
    assert not policy.is_static_address("10.0.0.99")
    with pytest.raises(ValueError):
        CorrelationPolicy(static_cidrs=("nope",))
    env = {"NETSIGHT_IDENTITY_STATIC_CIDRS": "10.0.0.0/28, 10.9.0.0/24"}
    assert CorrelationPolicy.from_env(env).static_cidrs == ("10.0.0.0/28", "10.9.0.0/24")
