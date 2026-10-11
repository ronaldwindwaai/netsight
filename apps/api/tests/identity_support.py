"""Builders for identity-correlation tests: evidence records with readable defaults.

Every helper takes explicit times so a test states the window it is about. Entity references are
minted the way adapters mint them (canonical, source-scoped ids), so tests exercise real ids.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from netsight_api.identity.model import (
    Assertion,
    EntityRef,
    EvidenceKind,
    EvidenceRecord,
    Relation,
    account_ref,
    ap_ref,
    device_ref,
    ip_ref,
    mac_ref,
    person_ref,
    port_ref,
    switch_ref,
    vlan_ref,
)

T0 = datetime(2026, 10, 11, 9, 0, tzinfo=UTC)
NOW = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)


def at(hours: float) -> datetime:
    """``T0`` plus a number of hours (09:00 UTC on the test day is hour 0)."""
    return T0 + timedelta(hours=hours)


ALICE = person_ref("directory", "alice", "Alice Example")
BOB = person_ref("directory", "bob", "Bob Example")
ALICE_ACC = account_ref("directory", "alice@example", "alice")
BOB_ACC = account_ref("directory", "bob@example", "bob")
PC1 = device_ref("wazuh", "001", "PC-001")
PC2 = device_ref("wazuh", "002", "PC-002")
AP1 = ap_ref("netbox", "ap1", "AP-LOBBY")
SW1 = switch_ref("netbox", "sw1", "SW-ACCESS-1")
PORT1 = port_ref(SW1.id, "Gi1/0/12")
VLAN10 = vlan_ref(10, "STAFF")
VLAN99 = vlan_ref(99, "GUEST")
IP1 = ip_ref("10.0.0.10")
IP2 = ip_ref("10.0.0.11")
MAC_A = mac_ref("AA-BB-CC-00-00-01")
MAC_B = mac_ref("aa:bb:cc:00:00:02")


def record(
    kind: EvidenceKind,
    native_id: str,
    assertions: list[Assertion],
    *,
    source: str,
    start: datetime,
    end: datetime | None,
    confidence: float = 0.95,
    observed_at: datetime | None = None,
    guest: bool = False,
) -> EvidenceRecord:
    return EvidenceRecord(
        source=source,
        native_id=native_id,
        kind=kind,
        observed_at=observed_at if observed_at is not None else start,
        valid_from=start,
        valid_to=end,
        confidence=confidence,
        assertions=tuple(assertions),
        guest=guest,
    )


def dhcp(
    ip: EntityRef,
    mac: EntityRef,
    start: datetime,
    end: datetime | None,
    *,
    native_id: str | None = None,
    confidence: float = 0.95,
) -> EvidenceRecord:
    return record(
        EvidenceKind.DHCP_LEASE,
        native_id or f"lease-{ip.id}-{mac.id}-{start.isoformat()}",
        [Assertion(ip, Relation.IP_MAC, mac)],
        source="dhcp",
        start=start,
        end=end,
        confidence=confidence,
    )


def radius(
    account: EntityRef,
    mac: EntityRef,
    start: datetime,
    end: datetime | None,
    *,
    native_id: str | None = None,
    observed_at: datetime | None = None,
    port: EntityRef | None = None,
    vlan: EntityRef | None = None,
    confidence: float = 0.95,
) -> EvidenceRecord:
    assertions = [Assertion(account, Relation.ACCOUNT_MAC, mac)]
    if port is not None:
        assertions.append(Assertion(mac, Relation.MAC_PORT, port))
    if vlan is not None:
        assertions.append(Assertion(mac, Relation.MAC_VLAN, vlan))
    return record(
        EvidenceKind.RADIUS_SESSION,
        native_id or f"radius-{account.id}-{mac.id}-{start.isoformat()}",
        assertions,
        source="radius",
        start=start,
        end=end,
        observed_at=observed_at,
        confidence=confidence,
    )


def directory(person: EntityRef, account: EntityRef, *, confidence: float = 0.98) -> EvidenceRecord:
    return record(
        EvidenceKind.DIRECTORY_ACCOUNT,
        f"dir-{person.id}-{account.id}",
        [Assertion(person, Relation.PERSON_ACCOUNT, account)],
        source="directory",
        start=at(-48),
        end=at(48),
        confidence=confidence,
        observed_at=at(-1),
    )


def vpn(
    account: EntityRef, ip: EntityRef, start: datetime, end: datetime | None, *, native_id: str = ""
) -> EvidenceRecord:
    return record(
        EvidenceKind.VPN_SESSION,
        native_id or f"vpn-{account.id}-{ip.id}-{start.isoformat()}",
        [Assertion(account, Relation.ACCOUNT_IP, ip)],
        source="vpn",
        start=start,
        end=end,
    )


def signin(
    account: EntityRef, ip: EntityRef, when: datetime, *, confidence: float = 0.9
) -> EvidenceRecord:
    return record(
        EvidenceKind.IDP_SIGNIN,
        f"signin-{account.id}-{ip.id}-{when.isoformat()}",
        [Assertion(account, Relation.ACCOUNT_IP, ip)],
        source="idp",
        start=when,
        end=when + timedelta(minutes=30),
        confidence=confidence,
    )


def wifi(
    mac: EntityRef,
    ap: EntityRef,
    start: datetime,
    end: datetime | None,
    *,
    vlan: EntityRef | None = None,
    guest: bool = False,
) -> EvidenceRecord:
    assertions = [Assertion(mac, Relation.MAC_AP, ap)]
    if vlan is not None:
        assertions.append(Assertion(mac, Relation.MAC_VLAN, vlan))
    return record(
        EvidenceKind.WIFI_ASSOCIATION,
        f"wifi-{mac.id}-{ap.id}-{start.isoformat()}",
        assertions,
        source="wifi",
        start=start,
        end=end,
        guest=guest,
    )


def agent(
    device: EntityRef,
    ip: EntityRef,
    start: datetime,
    end: datetime | None,
    *,
    mac: EntityRef | None = None,
    confidence: float = 0.9,
) -> EvidenceRecord:
    assertions = [Assertion(device, Relation.DEVICE_IP, ip)]
    if mac is not None:
        assertions.append(Assertion(device, Relation.DEVICE_MAC, mac))
    return record(
        EvidenceKind.ENDPOINT_AGENT,
        f"agent-{device.id}",
        assertions,
        source="wazuh",
        start=start,
        end=end,
        confidence=confidence,
    )


def assignment(person: EntityRef, device: EntityRef) -> EvidenceRecord:
    return record(
        EvidenceKind.ASSET_ASSIGNMENT,
        f"assign-{person.id}-{device.id}",
        [Assertion(person, Relation.PERSON_DEVICE, device)],
        source="netbox",
        start=at(-48),
        end=at(48),
        confidence=0.9,
        observed_at=at(-1),
    )


def static_ip(device: EntityRef, ip: EntityRef) -> EvidenceRecord:
    return record(
        EvidenceKind.ASSET_ASSIGNMENT,
        f"netbox-ip-{device.id}-{ip.id}",
        [Assertion(device, Relation.DEVICE_IP, ip)],
        source="netbox",
        start=at(-48),
        end=at(48),
        confidence=0.9,
        observed_at=at(-1),
    )
