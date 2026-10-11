"""The unknown-device scan: read the sources, compare, record (Step 8c).

Hermetic: every source is a fake that returns a value or raises, and the store is the in-memory one.
The scan only ever reads from NetBox, LibreNMS and Wazuh; the only thing it writes is Netsight's own
finding store. A source it cannot read makes the answer smaller, never wrong: NetBox unreadable means
no comparison and no change at all.
"""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from typing import Any

import pytest
from inventory_support import (
    NOW,
    FakeLibrenms,
    FakeNetbox,
    FakeWazuh,
    agent,
    asset,
    device,
)

from netsight_api.adapters.netbox_ipam import MacMatch
from netsight_api.identity.model import (
    Assertion,
    CorrelationPolicy,
    EvidenceKind,
    EvidenceRecord,
    Relation,
    mac_ref,
    port_ref,
    switch_ref,
    vlan_ref,
)
from netsight_api.identity.sources import MemoryEvidenceSource
from netsight_api.storage import StorageUnavailableError
from netsight_api.storage.unknown_devices import InMemoryUnknownDeviceRepository
from netsight_api.unknown_devices import scanner as sc
from netsight_api.unknown_devices.policy import POLICY_ENV, load_policy
from netsight_api.unknown_devices.scanner import UnknownDeviceScanner

FIELD = "wazuh_agent"
MAC = "aa:bb:cc:00:11:22"
POLICY = load_policy(
    {
        POLICY_ENV: json.dumps(
            {
                "version": 1,
                "default_severity": "medium",
                "quarantine_recommended_at": "high",
                "rules": [{"cidrs": ["10.20.0.0/16"], "severity": "high"}],
            }
        )
    }
)


def make(
    netbox: Any = "default",
    librenms: Any = "default",
    wazuh: Any = None,
    *,
    sources: list[Any] | None = None,
    store: Any = None,
    field: str | None = FIELD,
    policy: Any = POLICY,
) -> tuple[UnknownDeviceScanner, InMemoryUnknownDeviceRepository]:
    if netbox == "default":
        netbox = FakeNetbox(
            [asset("1", "core-sw-1", ip="10.0.0.2")],
            ip_assignments={"10.0.0.50": "pc-1"},
            agent_keys={"1": "001"},
        )
    if librenms == "default":
        librenms = FakeLibrenms(
            [
                device("librenms", "7", "core-sw-1", ip="10.0.0.2", mac="aa:bb:cc:00:00:01"),
                device("librenms", "9", "printer-x", ip="10.20.5.9", mac=MAC),
            ]
        )
    repo = store or InMemoryUnknownDeviceRepository(clock=lambda: NOW)
    scanner = UnknownDeviceScanner(
        netbox=netbox,
        librenms=librenms,
        wazuh=wazuh,
        agent_field=field,
        evidence_sources=sources or [],
        store=repo,
        policy=policy,
        correlation=CorrelationPolicy(),
        clock=lambda: NOW,
    )
    return scanner, repo


def states(result: sc.ScanResult) -> dict[str, str]:
    return {s.source: s.state for s in result.sources}


def findings(repo: InMemoryUnknownDeviceRepository) -> list[Any]:
    return repo.list_findings(limit=50)[0]


@pytest.mark.asyncio
async def test_a_device_netbox_does_not_know_becomes_a_finding_and_a_known_one_does_not() -> None:
    scanner, repo = make()
    result = await scanner.scan()
    assert (result.state, result.created, result.refreshed, result.suppressed) == ("ok", 1, 0, 0)
    (finding,) = findings(repo)
    assert finding.endpoint.hostname == "printer-x" and finding.endpoint.mac == MAC
    assert (finding.severity, finding.severity_basis) == ("high", "policy-rule")
    assert finding.proposed_action is not None and finding.proposed_action.executable is False
    assert states(result) == {"netbox": "ok", "librenms": "ok", "wazuh": "not-connected"}


@pytest.mark.asyncio
async def test_scanning_again_refreshes_instead_of_duplicating() -> None:
    scanner, repo = make()
    await scanner.scan()
    again = await scanner.scan()
    assert (again.created, again.refreshed) == (0, 1)
    assert len(findings(repo)) == 1 and findings(repo)[0].seen_count == 2


@pytest.mark.asyncio
async def test_a_false_positive_stays_suppressed_across_scans() -> None:
    scanner, repo = make()
    await scanner.scan()
    finding = findings(repo)[0]
    repo.transition_state(finding.id, to_state="false-positive", actor_id="u", reason="lab device")
    result = await scanner.scan()
    assert (result.created, result.refreshed, result.suppressed) == (0, 0, 1)


@pytest.mark.asyncio
async def test_netbox_not_configured_changes_nothing() -> None:
    scanner, repo = make(netbox=None)
    result = await scanner.scan()
    assert result.state == "not-connected" and findings(repo) == []
    assert (result.created, result.refreshed, result.suppressed, result.unverified) == (0, 0, 0, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize("broken", ["inventory_assets", "ip_assignments"])
async def test_netbox_unreadable_changes_nothing_and_never_makes_everything_unknown(
    broken: str,
) -> None:
    netbox = FakeNetbox([asset("1", "core-sw-1", ip="10.0.0.2")])
    if broken == "inventory_assets":
        netbox = FakeNetbox(RuntimeError("down"))
    else:
        netbox = FakeNetbox([asset("1", "core-sw-1")], ip_assignments=RuntimeError("down"))
    scanner, repo = make(netbox=netbox)
    result = await scanner.scan()
    assert result.state == "unknown" and findings(repo) == []
    assert states(result)["netbox"] == "unknown"


@pytest.mark.asyncio
async def test_no_discovery_source_means_nothing_to_compare() -> None:
    scanner, repo = make(librenms=None, wazuh=None)
    result = await scanner.scan()
    assert result.state == "ok" and result.created == 0 and findings(repo) == []
    assert states(result)["librenms"] == "not-connected"


@pytest.mark.asyncio
async def test_librenms_failing_just_leaves_it_out() -> None:
    scanner, repo = make(librenms=FakeLibrenms(RuntimeError("down")))
    result = await scanner.scan()
    assert result.state == "ok" and states(result)["librenms"] == "unknown" and findings(repo) == []


@pytest.mark.asyncio
async def test_a_wazuh_agent_is_known_by_its_key_address_or_name() -> None:
    wazuh = FakeWazuh(
        [
            agent("001", "differently-named", "10.9.9.1"),  # joined by the operator's key
            agent("002", "pc-1", "10.0.0.50"),  # assigned address in NetBox
            agent("003", "core-sw-1", "10.7.7.7"),  # name of a NetBox device
            agent("004", "stray", "10.0.0.77"),  # nothing matches
        ]
    )
    scanner, repo = make(librenms=None, wazuh=wazuh)
    result = await scanner.scan()
    assert result.created == 1
    assert findings(repo)[0].endpoint.hostname == "stray"
    assert states(result)["wazuh"] == "ok"


@pytest.mark.asyncio
async def test_a_wazuh_agent_is_not_judged_when_the_keys_that_would_join_it_are_unreadable() -> (
    None
):
    netbox = FakeNetbox([asset("1", "core-sw-1", ip="10.0.0.2")], agent_keys=RuntimeError("down"))
    scanner, repo = make(
        netbox=netbox, librenms=None, wazuh=FakeWazuh([agent("001", "x", "10.0.0.77")])
    )
    result = await scanner.scan()
    assert states(result)["wazuh"] == "unknown" and findings(repo) == []


@pytest.mark.asyncio
async def test_a_truncated_agent_list_is_not_used() -> None:
    scanner, repo = make(
        librenms=None, wazuh=FakeWazuh([agent("004", "stray", "10.0.0.77")], truncated=True)
    )
    result = await scanner.scan()
    assert states(result)["wazuh"] == "unknown" and findings(repo) == []


@pytest.mark.asyncio
async def test_a_mac_netbox_has_on_an_interface_clears_the_device() -> None:
    netbox = FakeNetbox(
        [asset("1", "core-sw-1", ip="10.0.0.2")],
        macs={MAC: [MacMatch("5", "printer-from-netbox", "eth0")]},
    )
    scanner, repo = make(netbox=netbox)
    result = await scanner.scan()
    assert result.created == 0 and findings(repo) == []


@pytest.mark.asyncio
async def test_a_failed_mac_lookup_is_unverified_not_a_finding() -> None:
    netbox = FakeNetbox([asset("1", "core-sw-1", ip="10.0.0.2")], macs=RuntimeError("down"))
    scanner, repo = make(netbox=netbox)
    result = await scanner.scan()
    assert result.created == 0 and result.unverified == 1 and findings(repo) == []


@pytest.mark.asyncio
async def test_lookups_are_bounded_and_the_rest_are_unverified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sc, "MAX_MAC_LOOKUPS", 1)
    netbox = FakeNetbox([asset("1", "unrelated-device")])
    scanner, _ = make(netbox=netbox)
    result = await scanner.scan()
    assert netbox.calls.count("interfaces_by_mac") == 1
    assert (result.created, result.unverified) == (1, 1)


@pytest.mark.asyncio
async def test_an_endpoint_another_field_already_cleared_costs_no_mac_lookup() -> None:
    netbox = FakeNetbox([asset("1", "core-sw-1", ip="10.0.0.2")])
    scanner, _ = make(netbox=netbox)
    await scanner.scan()
    assert netbox.calls.count("interfaces_by_mac") == 1  # only printer-x was asked about


@pytest.mark.asyncio
async def test_nothing_is_ever_written_to_netbox() -> None:
    netbox = FakeNetbox([asset("1", "core-sw-1", ip="10.0.0.2")])
    scanner, _ = make(netbox=netbox)
    await scanner.scan()
    allowed = {"inventory_assets", "ip_assignments", "device_agent_keys", "interfaces_by_mac"}
    assert set(netbox.calls) <= allowed


@pytest.mark.asyncio
async def test_switch_evidence_fills_the_chain_and_names_the_vlan_for_the_policy() -> None:
    sw = switch_ref("netbox", "sw-3", "access-sw-3")
    record = EvidenceRecord(
        source="snmp",
        native_id="fdb-1",
        kind=EvidenceKind.SWITCH_MAC_TABLE,
        observed_at=NOW - timedelta(minutes=2),
        valid_from=NOW - timedelta(minutes=10),
        valid_to=None,
        confidence=0.9,
        assertions=(
            Assertion(mac_ref(MAC), Relation.MAC_SWITCH, sw),
            Assertion(mac_ref(MAC), Relation.MAC_PORT, port_ref(sw.id, "Gi1/0/7")),
            Assertion(mac_ref(MAC), Relation.MAC_VLAN, vlan_ref(30)),
        ),
    )
    policy = load_policy(
        {POLICY_ENV: json.dumps({"version": 1, "rules": [{"vlans": [30], "severity": "critical"}]})}
    )
    scanner, repo = make(sources=[MemoryEvidenceSource("snmp", [record])], policy=policy)
    await scanner.scan()
    (finding,) = findings(repo)
    assert [s.basis for s in finding.chain] == ["observed"] * 5
    assert finding.chain[2].label == "access-sw-3" and finding.chain[4].value == "vlan-30"
    assert finding.severity == "critical"


@pytest.mark.asyncio
async def test_without_attachment_evidence_the_hops_say_the_source_is_unavailable() -> None:
    scanner, repo = make()
    await scanner.scan()
    chain = findings(repo)[0].chain
    assert [s.basis for s in chain] == ["observed", "observed", "unknown", "unknown", "unknown"]
    assert {s.reason for s in chain[2:]} == {"source-unavailable"}


@pytest.mark.asyncio
async def test_an_evidence_source_that_fails_is_ignored_and_its_relations_are_not_claimed() -> None:
    class Broken:
        name = "snmp"
        kinds = frozenset({EvidenceKind.SWITCH_MAC_TABLE})

        async def fetch(self, **_: Any) -> Any:
            raise RuntimeError("down")

    scanner, repo = make(sources=[Broken()])
    result = await scanner.scan()
    assert result.created == 1
    assert {s.reason for s in findings(repo)[0].chain[2:]} == {"source-unavailable"}


@pytest.mark.asyncio
async def test_a_source_that_hangs_is_unknown_after_its_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sc, "SOURCE_BUDGET_SECONDS", 0.05)

    class Hanging(FakeLibrenms):
        async def devices(self) -> Any:
            await asyncio.sleep(5)

    scanner, _ = make(librenms=Hanging([]))
    result = await scanner.scan()
    assert states(result)["librenms"] == "unknown"


@pytest.mark.asyncio
async def test_a_store_that_is_down_fails_the_scan_loudly_not_silently() -> None:
    class Down:
        def observe(self, detection: Any) -> Any:
            raise StorageUnavailableError("down")

    scanner, _ = make(store=Down())
    with pytest.raises(StorageUnavailableError):
        await scanner.scan()


@pytest.mark.asyncio
async def test_concurrent_scans_never_duplicate_a_finding() -> None:
    scanner, repo = make()
    await asyncio.gather(*(scanner.scan() for _ in range(5)))
    assert len(findings(repo)) == 1


@pytest.mark.asyncio
async def test_hostile_names_become_data_and_a_clean_finding() -> None:
    hostile = "<script>alert(1)</script> ' OR 1=1 --"
    librenms = FakeLibrenms([device("librenms", "9", hostile[:60], ip="10.20.5.9", mac=MAC)])
    scanner, repo = make(librenms=librenms)
    await scanner.scan()
    assert findings(repo)[0].endpoint.hostname == hostile[:60]


@pytest.mark.asyncio
async def test_the_cycle_runner_swallows_nothing_the_scheduler_needs_to_log() -> None:
    scanner, repo = make()
    await scanner.run_cycle()
    assert len(findings(repo)) == 1
