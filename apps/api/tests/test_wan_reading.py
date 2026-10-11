"""Assembling the Internet reading from LibreNMS and stored probe samples (Step 5a).

Every field is source-reported or null; an absent source is ``not-connected``, a failing one
``unknown``; stale data is labelled with the source's own freshness; nothing is fabricated.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from netsight_api.adapters.librenms import AdapterError, AdapterStatus, WanPortReading
from netsight_api.contracts import validate
from netsight_api.storage.errors import StorageError
from netsight_api.storage.wan import InMemoryWanSampleRepository
from netsight_api.wan import reading as wan_reading
from netsight_api.wan import sla
from netsight_api.wan.config import WanConfig, load_wan_links
from netsight_api.wan.reading import build_internet
from netsight_api.wan.sla import Sample

NOW = datetime(2026, 10, 11, 10, 0, 0, tzinfo=UTC)


def declare(*links: dict[str, Any]) -> WanConfig:
    return load_wan_links({"NETSIGHT_WAN_LINKS": json.dumps(list(links))})


def primary(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "fibre-1",
        "name": "Primary fibre",
        "role": "primary",
        "isp": "Example ISP",
        "gateway": "192.0.2.1",
        "librenms_device": "12",
        "librenms_port": "345",
        "probe_targets": ["probe-a.example"],
        "probe_location": "branch",
        "dns_target": "dns-check.example",
    }
    base.update(overrides)
    return base


def backup(**overrides: Any) -> dict[str, Any]:
    return primary(
        id="lte-1",
        name="Backup LTE",
        role="backup",
        isp=None,
        gateway=None,
        librenms_device="12",
        librenms_port="400",
        **overrides,
    )


def port_reading(**overrides: Any) -> WanPortReading:
    values: dict[str, Any] = {
        "oper_status": "up",
        "speed_bps": 1_000_000_000,
        "rx_bps": 100_000_000,
        "tx_bps": 20_000_000,
        "polled_at": NOW - timedelta(minutes=2),
        "public_ip": "8.8.8.8",
    }
    values.update(overrides)
    return WanPortReading(**values)


class FakePorts:
    def __init__(self, readings: dict[tuple[str, str], Any] | None = None) -> None:
        self.readings = readings or {("12", "345"): port_reading(), ("12", "400"): port_reading()}
        self.calls: list[tuple[str, str]] = []

    async def wan_port(self, device: str, port: str) -> WanPortReading | None:
        self.calls.append((device, port))
        outcome = self.readings.get((device, port))
        if isinstance(outcome, Exception):
            raise outcome
        if callable(outcome):
            return await outcome()  # type: ignore[no-any-return]
        return outcome  # type: ignore[no-any-return]


def record(
    store: InMemoryWanSampleRepository,
    when: datetime,
    outcomes: list[str],
    *,
    link: str = "wan-x",
    latency: float = 10.0,
    dns: str | None = "pass",
    interval: int = 60,
) -> None:
    rows = [
        Sample(
            "icmp",
            "probe-a.example",
            o,  # type: ignore[arg-type]
            latency if o == "pass" else None,
            "branch",
        )
        for o in outcomes
    ]
    if dns:
        rows.append(Sample("dns", "dns-check.example", dns, 15.0 if dns == "pass" else None))  # type: ignore[arg-type]
    store.record_cycle(sla.build_cycle(link, when, interval, rows), rows)


def fill(
    store: InMemoryWanSampleRepository,
    link: str,
    outcomes: list[str],
    *,
    minutes: int = 20,
    **kwargs: Any,
) -> None:
    for minute in range(minutes, 0, -1):
        record(store, NOW - timedelta(seconds=minute * 60 - 30), outcomes, link=link, **kwargs)


async def build(
    config: WanConfig,
    ports: Any = None,
    store: Any = None,
) -> Any:
    response = await build_internet(config, ports, store, NOW)
    validate("internet_response", json.loads(response.model_dump_json(by_alias=True)))
    return response


def run(coro: Any) -> Any:
    return asyncio.run(coro)


# --- configuration states --------------------------------------------------------------------------


def test_no_declared_links_is_not_connected_and_reads_no_source() -> None:
    ports = FakePorts()
    response = run(build(WanConfig("not-connected"), ports, InMemoryWanSampleRepository()))
    assert response.state == "not-connected" and response.links == []
    assert (response.failover.state, response.failover.basis) == ("unknown", "unknown")
    assert ports.calls == []


def test_an_unusable_declaration_is_unknown_and_reads_no_source() -> None:
    ports = FakePorts()
    response = run(build(WanConfig("unknown"), ports, InMemoryWanSampleRepository()))
    assert response.state == "unknown" and response.links == []
    assert ports.calls == []


# --- a fully connected link --------------------------------------------------------------------------


def test_a_fully_sourced_link_reports_source_values_and_labels_them() -> None:
    store = InMemoryWanSampleRepository()
    fill(store, "fibre-1", ["pass", "pass"])
    response = run(build(declare(primary()), FakePorts(), store))
    link = response.links[0]
    assert (link.id, link.name, link.role) == ("fibre-1", "Primary fibre", "primary")
    assert (link.configured.isp, link.configured.gateway) == ("Example ISP", "192.0.2.1")
    assert link.configured.probe_location == "branch"
    interface = link.interface
    assert interface.state == "ok" and interface.oper_status == "up"
    assert (interface.capacity_bps, interface.rx_bps, interface.tx_bps) == (
        1_000_000_000,
        100_000_000,
        20_000_000,
    )
    assert interface.utilisation_pct == 10.0 and interface.public_ip == "8.8.8.8"
    assert interface.freshness.state == "fresh" and interface.freshness.source == "librenms"
    assert interface.freshness.observed_at == NOW - timedelta(minutes=2)
    quality = link.quality
    assert quality.state == "ok" and quality.latency_ms == 10.0 and quality.jitter_ms == 0.0
    assert (
        quality.loss_pct == 0.0 and quality.dns_status == "pass" and quality.dns_latency_ms == 15.0
    )
    assert quality.sample_count == 15 * 2 and quality.window_seconds == 900
    assert quality.freshness.state == "fresh" and quality.freshness.source == "blackbox-probes"
    availability = link.availability
    assert availability.state == "ok" and availability.uptime_pct == 100.0
    assert availability.period_end == NOW and availability.period_start == NOW - timedelta(hours=24)
    assert availability.current_outage_started_at is None
    assert link.status == "up"
    assert (response.failover.state, response.failover.basis) == ("single-link", "inferred")


def test_utilisation_is_the_larger_direction_over_capacity_and_only_when_known() -> None:
    cases = [
        (port_reading(rx_bps=10, tx_bps=500_000_000), 50.0),
        (port_reading(speed_bps=None), None),
        (port_reading(speed_bps=0), None),
        (port_reading(rx_bps=None), None),
        (port_reading(tx_bps=None), None),
        (port_reading(rx_bps=0, tx_bps=0), 0.0),
    ]
    for reading, expected in cases:
        ports = FakePorts({("12", "345"): reading})
        response = run(build(declare(primary()), ports, None))
        assert response.links[0].interface.utilisation_pct == expected


def test_an_unreported_value_stays_null_never_zero() -> None:
    reading = port_reading(speed_bps=None, rx_bps=None, tx_bps=None, public_ip=None)
    response = run(build(declare(primary()), FakePorts({("12", "345"): reading}), None))
    interface = response.links[0].interface
    assert interface.state == "ok"
    assert (interface.capacity_bps, interface.rx_bps, interface.tx_bps) == (None, None, None)
    assert interface.public_ip is None


# --- the interface source ----------------------------------------------------------------------------


def test_no_librenms_client_is_not_connected_but_probes_still_report() -> None:
    store = InMemoryWanSampleRepository()
    fill(store, "fibre-1", ["pass"])
    response = run(build(declare(primary()), None, store))
    link = response.links[0]
    assert link.interface.state == "not-connected" and link.interface.rx_bps is None
    assert (
        link.interface.freshness.state == "unknown" and link.interface.freshness.observed_at is None
    )
    assert link.quality.state == "ok" and link.status == "up"  # from the probes alone


def test_a_link_with_no_declared_port_has_no_interface_source() -> None:
    ports = FakePorts()
    config = declare(primary(librenms_device=None, librenms_port=None))
    response = run(build(config, ports, None))
    assert response.links[0].interface.state == "not-connected"
    assert ports.calls == []


def test_a_failing_interface_source_is_unknown_and_leaks_nothing() -> None:
    error = AdapterError(AdapterStatus.UNAVAILABLE, "boom https://librenms.internal/secret-path")
    store = InMemoryWanSampleRepository()
    fill(store, "fibre-1", ["pass"])
    response = run(build(declare(primary()), FakePorts({("12", "345"): error}), store))
    link = response.links[0]
    assert link.interface.state == "unknown" and link.interface.oper_status is None
    assert "secret-path" not in response.model_dump_json()
    assert link.quality.state == "ok"  # the other source is unaffected
    assert link.status == "up"  # probes alone


def test_an_unexpected_error_from_the_source_is_unknown_too() -> None:
    ports = FakePorts({("12", "345"): RuntimeError("driver exploded")})
    response = run(build(declare(primary()), ports, None))
    assert response.links[0].interface.state == "unknown"
    assert "exploded" not in response.model_dump_json()


def test_a_port_the_source_does_not_list_is_unknown() -> None:
    response = run(build(declare(primary()), FakePorts({("12", "345"): None}), None))
    assert response.links[0].interface.state == "unknown"


def test_a_hung_interface_source_times_out_to_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    async def hang() -> None:
        await asyncio.sleep(30)

    monkeypatch.setattr(wan_reading, "PORT_TIMEOUT_SECONDS", 0.05)
    response = run(build(declare(primary()), FakePorts({("12", "345"): hang}), None))
    assert response.links[0].interface.state == "unknown"


def test_stale_counters_are_shown_labelled_stale_and_not_used_for_status() -> None:
    old = port_reading(polled_at=NOW - timedelta(hours=2), oper_status="down")
    response = run(build(declare(primary()), FakePorts({("12", "345"): old}), None))
    link = response.links[0]
    assert link.interface.state == "ok" and link.interface.freshness.state == "stale"
    assert link.interface.freshness.observed_at == NOW - timedelta(hours=2)
    assert link.interface.oper_status == "down"  # the last-known value, labelled
    assert link.status == "unknown"  # but a stale reading is no evidence about now


def test_counters_with_no_poll_time_have_unknown_freshness_and_are_no_evidence() -> None:
    reading = port_reading(polled_at=None)
    response = run(build(declare(primary()), FakePorts({("12", "345"): reading}), None))
    link = response.links[0]
    assert (
        link.interface.freshness.state == "unknown" and link.interface.freshness.observed_at is None
    )
    assert link.status == "unknown"


def test_a_poll_time_in_the_future_is_not_fresh() -> None:
    reading = port_reading(polled_at=NOW + timedelta(hours=1))
    response = run(build(declare(primary()), FakePorts({("12", "345"): reading}), None))
    assert response.links[0].interface.freshness.state == "unknown"


# --- the probe store -----------------------------------------------------------------------------------


def test_no_sample_store_is_not_connected_for_quality_and_availability() -> None:
    response = run(build(declare(primary()), FakePorts(), None))
    link = response.links[0]
    for block in (link.quality, link.availability):
        assert block.state == "not-connected"
        assert block.freshness.state == "unknown" and block.freshness.observed_at is None
    assert link.quality.latency_ms is None and link.availability.uptime_pct is None
    assert link.status == "up"  # the interface alone


def test_a_failing_store_is_unknown() -> None:
    class Broken(InMemoryWanSampleRepository):
        def cycles_between(self, *args: Any, **kwargs: Any) -> Any:
            raise StorageError("db exploded postgresql://u:p@h/db")

    response = run(build(declare(primary()), FakePorts(), Broken()))
    link = response.links[0]
    assert link.quality.state == "unknown" and link.availability.state == "unknown"
    assert "postgresql" not in response.model_dump_json()


def test_a_store_with_no_samples_is_empty_not_zero() -> None:
    response = run(build(declare(primary()), FakePorts(), InMemoryWanSampleRepository()))
    link = response.links[0]
    assert link.quality.state == "ok" and link.quality.sample_count == 0
    assert link.quality.latency_ms is None and link.quality.loss_pct is None
    assert link.quality.freshness.state == "unknown"
    assert link.availability.state == "ok" and link.availability.uptime_pct is None
    assert link.availability.coverage_pct == 0.0


def test_quality_and_loss_come_from_the_samples() -> None:
    store = InMemoryWanSampleRepository()
    for minute in range(10, 0, -1):
        record(store, NOW - timedelta(minutes=minute), ["pass", "fail"], link="fibre-1")
    link = run(build(declare(primary()), FakePorts(), store)).links[0]
    assert link.quality.loss_pct == 50.0
    assert link.status == "degraded"  # some targets answer, some do not


def test_all_probes_failing_makes_the_link_down_even_with_the_interface_up() -> None:
    store = InMemoryWanSampleRepository()
    fill(store, "fibre-1", ["fail", "fail"], dns="fail")
    link = run(build(declare(primary()), FakePorts(), store)).links[0]
    assert link.interface.oper_status == "up" and link.status == "down"
    assert link.quality.dns_status == "fail"
    assert link.availability.current_outage_started_at is not None
    assert link.availability.current_outage_seconds is not None


def test_a_quiet_collector_is_stale_and_claims_nothing_about_now() -> None:
    store = InMemoryWanSampleRepository()
    record(store, NOW - timedelta(hours=3), ["fail", "fail"], link="fibre-1")
    link = run(
        build(
            declare(
                primary(),
            ),
            None,
            store,
        )
    ).links[0]
    assert link.quality.freshness.state == "stale"
    assert link.availability.freshness.state == "stale"
    assert link.availability.current_outage_started_at is None  # nothing current is claimed
    assert link.status == "unknown"  # the last round is too old to say anything about now


def test_availability_is_over_known_time_with_gaps_unknown() -> None:
    store = InMemoryWanSampleRepository()
    record(store, NOW - timedelta(hours=23), ["pass"], link="fibre-1")
    record(store, NOW - timedelta(minutes=1), ["pass"], link="fibre-1")
    availability = run(build(declare(primary()), None, store)).links[0].availability
    assert availability.uptime_pct == 100.0
    assert availability.coverage_pct is not None and availability.coverage_pct < 1.0


# --- multi-WAN -------------------------------------------------------------------------------------------


def test_a_primary_down_with_a_working_backup_is_failed_over() -> None:
    ports = FakePorts(
        {
            ("12", "345"): port_reading(oper_status="down"),
            ("12", "400"): port_reading(oper_status="up"),
        }
    )
    response = run(build(declare(primary(), backup()), ports, None))
    assert [link.role for link in response.links] == ["primary", "backup"]
    assert [link.status for link in response.links] == ["down", "up"]
    assert (response.failover.state, response.failover.basis) == ("failed-over", "inferred")


def test_a_silent_backup_keeps_failover_unknown() -> None:
    ports = FakePorts({("12", "345"): port_reading(oper_status="down"), ("12", "400"): None})
    response = run(build(declare(primary(), backup()), ports, None))
    assert (response.failover.state, response.failover.basis) == ("unknown", "unknown")


def test_links_are_read_concurrently_and_each_independently() -> None:
    ports = FakePorts(
        {
            ("12", "345"): AdapterError(AdapterStatus.UNAVAILABLE, "x"),
            ("12", "400"): port_reading(),
        }
    )
    response = run(build(declare(primary(), backup()), ports, None))
    assert [link.interface.state for link in response.links] == ["unknown", "ok"]


# --- untrusted text ----------------------------------------------------------------------------------------


def test_configured_text_is_passed_through_as_data_unchanged() -> None:
    hostile = "<img src=x onerror=alert(1)>"
    response = run(build(declare(primary(name=hostile, isp=hostile)), None, None))
    link = response.links[0]
    assert link.name == hostile and link.configured.isp == hostile


# --- internet:read_detail redaction (security review M2) ------------------------------------------------


def test_redaction_withholds_exactly_the_detail_fields_and_changes_nothing_else() -> None:
    full = asyncio.run(
        build_internet(declare(primary()), FakePorts(), InMemoryWanSampleRepository(), NOW)
    )
    redacted = wan_reading.redact_detail(full)
    link, original = redacted.links[0], full.links[0]
    assert redacted.detail_redacted is True and full.detail_redacted is False
    assert (link.configured.isp, link.configured.gateway) == (None, None)
    assert (link.interface.public_ip, link.interface.rx_bps, link.interface.tx_bps) == (
        None,
        None,
        None,
    )
    assert link.interface.utilisation_pct is None
    assert original.configured.isp == "Example ISP" and original.interface.rx_bps == 100_000_000
    assert link.status == original.status and link.quality == original.quality
    assert link.availability == original.availability
    assert link.interface.capacity_bps == original.interface.capacity_bps
    assert link.interface.oper_status == original.interface.oper_status
    assert link.interface.freshness == original.interface.freshness
    assert link.configured.probe_location == original.configured.probe_location
    assert redacted.failover == full.failover
    validate("internet_response", json.loads(redacted.model_dump_json(by_alias=True)))


def test_redacting_twice_is_the_same_and_a_non_ok_response_is_only_flagged() -> None:
    empty = asyncio.run(build_internet(declare(), None, None, NOW))
    once = wan_reading.redact_detail(empty)
    assert once.detail_redacted is True and once.links == [] and once.state == empty.state
    assert wan_reading.redact_detail(once) == once
