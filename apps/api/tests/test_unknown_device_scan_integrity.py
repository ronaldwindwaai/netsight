"""The scan keeps its integrity under pressure (Step 8 review fix: security M1, M2, M5; code M1, M3).

* the bounded MAC lookups go to endpoints we have not seen before, then the most recent, not to
  whichever MAC sorts first;
* an incomplete answer (NetBox rows dropped, lookups past the cap, one bad detection) is visible
  as ``unverified`` / ``incomplete_sources`` plus a log line, and never becomes a finding or aborts
  the scan;
* one scan at a time, and not more than one a minute, shared by the scheduler and the API.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest
from inventory_support import NOW, FakeLibrenms, FakeNetbox, FakeWazuh, agent, asset, device
from test_unknown_device_scanner import MAC, findings, make

from netsight_api.storage import InvalidOperationError, StorageUnavailableError
from netsight_api.storage.unknown_devices import InMemoryUnknownDeviceRepository
from netsight_api.unknown_devices import scanner as sc
from netsight_api.unknown_devices.scanner import ScanBusy, ScanGuard

OTHER = "aa:bb:cc:00:11:99"


def two_devices(netbox: Any = None) -> tuple[Any, Any]:
    librenms = FakeLibrenms(
        [
            device("librenms", "9", "printer-x", ip="10.20.5.9", mac=MAC),
            device("librenms", "10", "printer-y", ip="10.20.5.10", mac=OTHER),
        ]
    )
    return netbox or FakeNetbox([asset("1", "core-sw-1", ip="10.0.0.2")]), librenms


@pytest.mark.asyncio
async def test_the_bounded_lookups_go_to_the_endpoint_not_seen_before(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sc, "MAX_MAC_LOOKUPS", 1)
    # MAC sorts first and already has a finding; OTHER is new to us
    netbox, librenms = two_devices()
    scanner, repo = make(netbox=netbox, librenms=librenms)
    from unknown_support import detection

    repo.observe(detection(mac=MAC, ip="10.20.5.9"))
    result = await scanner.scan()
    assert netbox.lookups == [OTHER]
    assert result.unverified == 1  # the seen-before one past the cap


@pytest.mark.asyncio
async def test_unverified_endpoints_are_raised_in_the_result_and_the_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    netbox = FakeNetbox([asset("1", "core-sw-1", ip="10.0.0.2")], macs=RuntimeError("down"))
    scanner, _ = make(netbox=netbox)
    with caplog.at_level(logging.WARNING, logger="netsight_api"):
        result = await scanner.scan()
    assert result.unverified == 1
    assert any(
        "unverified" in r.getMessage() and getattr(r, "unverified", None) == 1
        for r in caplog.records
    )


@pytest.mark.asyncio
async def test_netbox_rows_dropped_as_malformed_make_the_comparison_unverified_not_a_finding() -> (
    None
):
    netbox = FakeNetbox(
        [asset("1", "core-sw-1", ip="10.0.0.2")],
        ip_assignments={"10.0.0.50": "pc-1"},
        skipped=2,
    )
    scanner, repo = make(netbox=netbox)
    result = await scanner.scan()
    assert result.state == "ok"
    assert result.incomplete_sources == ("netbox",)
    assert result.created == 0 and findings(repo) == []
    assert result.unverified == 1  # printer-x: "NetBox does not have it" can not be said


@pytest.mark.asyncio
async def test_a_positive_match_still_clears_when_netbox_rows_were_dropped() -> None:
    netbox = FakeNetbox([asset("1", "core-sw-1", ip="10.0.0.2")], skipped=1)
    librenms = FakeLibrenms(
        [device("librenms", "7", "core-sw-1", ip="10.0.0.2", mac="aa:bb:cc:00:00:01")]
    )
    scanner, repo = make(netbox=netbox, librenms=librenms)
    result = await scanner.scan()
    assert result.unverified == 0 and findings(repo) == []
    assert result.incomplete_sources == ("netbox",)


@pytest.mark.asyncio
async def test_a_complete_scan_reports_no_incomplete_source() -> None:
    scanner, _ = make()
    assert (await scanner.scan()).incomplete_sources == ()


@pytest.mark.asyncio
async def test_a_wazuh_inventory_with_dropped_rows_is_reported_incomplete() -> None:
    wazuh = FakeWazuh([agent("004", "stray", "10.0.0.77")], skipped=3)
    scanner, _ = make(librenms=None, wazuh=wazuh)
    result = await scanner.scan()
    assert "wazuh" in result.incomplete_sources


@pytest.mark.asyncio
async def test_one_detection_the_store_refuses_is_unverified_and_the_rest_are_recorded() -> None:
    netbox, librenms = two_devices()

    class Picky(InMemoryUnknownDeviceRepository):
        def observe(self, detection: Any) -> Any:
            if detection.endpoint.mac == MAC:
                raise InvalidOperationError("the database rejected the supplied values")
            return super().observe(detection)

    scanner, repo = make(netbox=netbox, librenms=librenms, store=Picky(clock=lambda: NOW))
    result = await scanner.scan()
    assert result.created == 1 and result.unverified == 1
    assert [f.endpoint.mac for f in findings(repo)] == [OTHER]


@pytest.mark.asyncio
async def test_a_store_that_is_unavailable_still_fails_the_scan_loudly() -> None:
    class Down:
        def known_subject_keys(self, keys: Any) -> set[str]:
            return set()

        def observe(self, detection: Any) -> Any:
            raise StorageUnavailableError("down")

    scanner, _ = make(store=Down())
    with pytest.raises(StorageUnavailableError):
        await scanner.scan()


@pytest.mark.asyncio
async def test_a_hostile_name_with_nul_and_bidi_characters_is_cleaned_before_it_reaches_the_store() -> (
    None
):
    librenms = FakeLibrenms(
        [device("librenms", "9", "prin\x00ter\u202e-x", ip="10.20.5.9", mac=MAC)]
    )
    scanner, repo = make(librenms=librenms)
    result = await scanner.scan()
    assert result.created == 1
    assert findings(repo)[0].endpoint.hostname == "printer-x"


# --- one scan at a time ------------------------------------------------------------------------------------------


class Ticker:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.mark.asyncio
async def test_a_second_scan_while_one_runs_is_refused_with_a_retry_after() -> None:
    release = asyncio.Event()
    started = asyncio.Event()
    clock = Ticker()
    guard = ScanGuard(min_interval=60.0, clock=clock)

    async def slow() -> sc.ScanResult:
        started.set()
        await release.wait()
        return sc.ScanResult("ok", NOW, ())

    first = asyncio.create_task(guard.run(slow))
    await started.wait()
    clock.now += 10
    with pytest.raises(ScanBusy) as busy:
        await guard.run(slow)
    assert 1 <= busy.value.retry_after <= 60
    release.set()
    assert (await first).state == "ok"


@pytest.mark.asyncio
async def test_a_scan_inside_the_minimum_interval_gets_the_last_result_without_scanning_again() -> (
    None
):
    clock = Ticker()
    guard = ScanGuard(min_interval=60.0, clock=clock)
    calls = 0

    async def scan() -> sc.ScanResult:
        nonlocal calls
        calls += 1
        return sc.ScanResult("ok", NOW, (), created=calls)

    first = await guard.run(scan)
    clock.now += 30
    again = await guard.run(scan)
    assert calls == 1 and again is first
    clock.now += 31
    assert (await guard.run(scan)).created == 2


@pytest.mark.asyncio
async def test_a_failed_scan_is_not_remembered_and_frees_the_guard() -> None:
    guard = ScanGuard(min_interval=60.0, clock=Ticker())

    async def broken() -> sc.ScanResult:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        await guard.run(broken)

    async def fine() -> sc.ScanResult:
        return sc.ScanResult("ok", NOW, ())

    assert (await guard.run(fine)).state == "ok"


@pytest.mark.asyncio
async def test_the_scheduler_and_the_api_share_one_guard_so_a_cycle_defers_to_a_running_scan() -> (
    None
):
    guard = ScanGuard(min_interval=0.0, clock=Ticker())
    scanner, repo = make()
    scanner._guard = guard
    release = asyncio.Event()
    started = asyncio.Event()

    async def hold() -> sc.ScanResult:
        started.set()
        await release.wait()
        return sc.ScanResult("ok", NOW, ())

    running = asyncio.create_task(guard.run(hold))
    await started.wait()
    await scanner.run_cycle()  # busy: skipped, not an error, nothing scanned
    assert findings(repo) == []
    release.set()
    await running
    await scanner.run_cycle()
    assert len(findings(repo)) == 1


@pytest.mark.asyncio
async def test_a_finished_scheduled_cycle_leaves_an_audit_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    scanner, _ = make()
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        await scanner.run_cycle()
    lines = [r.getMessage() for r in caplog.records if r.name == "netsight_api.audit"]
    assert any(
        '"action": "unknown-device.scan.scheduled"' in line and '"outcome": "success"' in line
        for line in lines
    )
    assert any('"created": 1' in line for line in lines)
