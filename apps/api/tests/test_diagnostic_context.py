"""The live context sources of a diagnostic run (S7 Step 4): topology, changes and the store.

Hermetic: NetBox, LibreNMS and the incident store are fakes. The properties pinned: an
unconfigured source is ``not-connected``, a failing one is ``unknown`` (never an error that loses
the run), the topology uses canonical ids so cables join the right devices, and an alert is tied
to the target only when the alert source's own device link says so.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import pytest

from netsight_api.adapters.netbox import (
    CableCollection,
    CableLink,
    DeviceCollection,
    canonical_device_id,
)
from netsight_api.diagnostic_context import (
    LiveContextSources,
    get_context_sources,
    get_optional_diagnostic_session_store,
)
from netsight_api.schemas import Device, DeviceSourceAlias, Freshness
from netsight_api.storage import InMemoryIncidentRepository, StorageError

NOW = datetime(2026, 10, 10, 8, 0, tzinfo=UTC)
START = datetime(2026, 10, 9, 8, 0, tzinfo=UTC)


def device(native: str, name: str, role: str | None, **extra: Any) -> Device:
    return Device(
        id=canonical_device_id(native),
        name=name,
        hostname=extra.get("hostname"),
        type=role or "unknown",
        status="healthy",
        ip_addresses=extra.get("ip_addresses", []),
        source_aliases=[DeviceSourceAlias(source="netbox", native_id=native)],
        freshness=Freshness(state="fresh", observed_at=NOW, source="netbox"),
    )


class FakeNetbox:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail

    async def devices(self) -> DeviceCollection:
        if self.fail:
            raise RuntimeError("netbox down: secret-token")
        return DeviceCollection(
            items=(
                device("1", "SERVER01", "server", hostname="server01.example.test"),
                device("2", "fw-01", "Firewall"),
            ),
            observed_at=NOW,
        )

    async def cables(self) -> CableCollection:
        if self.fail:
            raise RuntimeError("netbox down: secret-token")
        return CableCollection(links=(CableLink("1", "2", None),), observed_at=NOW)


class FakeLibrenms:
    def __init__(self, alerts: list[dict[str, Any]], devices: list[Device], *, fail: bool = False):
        self._alerts = alerts
        self._devices = devices
        self._fail = fail

    async def alerts(self) -> list[dict[str, Any]]:
        if self._fail:
            raise RuntimeError("librenms down")
        return self._alerts

    async def devices(self) -> DeviceCollection:
        return DeviceCollection(items=tuple(self._devices), observed_at=NOW)


def alert(ident: str, device_id: str | None, title: str = "Link down") -> dict[str, Any]:
    return {
        "id": f"librenms:{ident}",
        "severity": "high",
        "state": "open",
        "title": title,
        "observed_at": NOW,
        "device_id": device_id,
    }


def sources(**kwargs: Any) -> LiveContextSources:
    return LiveContextSources(
        incident_store=kwargs.get("incident_store"),
        librenms=kwargs.get("librenms"),
        netbox=kwargs.get("netbox"),
    )


def run(coro: Any) -> Any:
    return asyncio.run(coro)


# --- topology ----------------------------------------------------------------------------------


def test_no_netbox_is_a_not_connected_topology() -> None:
    read = run(sources().topology())
    assert (read.state, read.devices, read.links, read.observed_at) == (
        "not-connected",
        (),
        (),
        None,
    )


def test_a_failing_netbox_is_an_unknown_topology_without_its_error() -> None:
    read = run(sources(netbox=FakeNetbox(fail=True)).topology())
    assert read.state == "unknown" and read.devices == () and "secret-token" not in repr(read)


def test_the_topology_joins_cables_to_devices_by_canonical_id() -> None:
    read = run(sources(netbox=FakeNetbox()).topology())
    assert read.state == "ok" and read.observed_at == NOW
    assert {d.name for d in read.devices} == {"SERVER01", "fw-01"}
    server = next(d for d in read.devices if d.name == "SERVER01")
    assert (server.role, server.hostname) == ("server", "server01.example.test")
    (link,) = read.links
    assert {link.a, link.b} == {d.device_id for d in read.devices}


# --- recent changes ----------------------------------------------------------------------------


def test_no_change_sources_are_not_connected() -> None:
    incidents, alerts = run(sources().changes(window_start=START, window_end=NOW, target="x"))
    assert (incidents.state, alerts.state) == ("not-connected", "not-connected")


def test_incidents_become_time_window_candidates() -> None:
    store = InMemoryIncidentRepository()
    created = store.create_incident(title="Firewall policy push", severity="high", actor_id="u-1")
    incidents, _ = run(
        sources(incident_store=store).changes(window_start=START, window_end=NOW, target="x")
    )
    assert incidents.state == "ok"
    (candidate,) = incidents.candidates
    assert (candidate.kind, candidate.ref_id, candidate.about_target) == (
        "incident",
        created.id,
        None,
    )


def test_a_failing_incident_store_is_unknown() -> None:
    class Broken:
        def list_incidents(self, **_kwargs: object) -> list[object]:
            raise StorageError("db down: secret-dsn")

    incidents, _ = run(
        sources(incident_store=Broken()).changes(window_start=START, window_end=NOW, target="x")  # type: ignore[arg-type]
    )
    assert incidents.state == "unknown" and incidents.candidates == ()


def test_an_alert_is_tied_to_the_target_only_by_its_own_device_link() -> None:
    mine = device("10", "SERVER01", "server")
    other = device("11", "other-host", "server")
    librenms = FakeLibrenms(
        [alert("1", mine.id), alert("2", other.id), alert("3", None)],
        [mine, other],
    )
    _, alerts = run(
        sources(librenms=librenms).changes(window_start=START, window_end=NOW, target=" server01 ")
    )
    assert alerts.state == "ok"
    assert {c.ref_id: c.about_target for c in alerts.candidates} == {
        "librenms:1": True,
        "librenms:2": False,
        "librenms:3": None,
    }


def test_an_alert_is_matched_by_address_or_hostname_too() -> None:
    mine = device("10", "srv", "server", hostname="app.example.test", ip_addresses=["10.0.5.20"])
    librenms = FakeLibrenms([alert("1", mine.id)], [mine])
    for needle in ("APP.example.test", "10.0.5.20"):
        _, alerts = run(
            sources(librenms=librenms).changes(window_start=START, window_end=NOW, target=needle)
        )
        assert alerts.candidates[0].about_target is True, needle


def test_a_failing_or_malformed_alert_source_is_unknown() -> None:
    _, failing = run(
        sources(librenms=FakeLibrenms([], [], fail=True)).changes(
            window_start=START, window_end=NOW, target="x"
        )
    )
    assert failing.state == "unknown"
    _, malformed = run(
        sources(librenms=FakeLibrenms([{"id": "librenms:1"}], [])).changes(
            window_start=START, window_end=NOW, target="x"
        )
    )
    assert malformed.state == "unknown"


# --- dependencies ------------------------------------------------------------------------------


def test_the_session_store_follows_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert get_optional_diagnostic_session_store() is None
    monkeypatch.setenv("DATABASE_URL", "mysql://nope")
    broken = get_optional_diagnostic_session_store()
    assert broken is not None
    with pytest.raises(StorageError):
        broken.get_session("diagnostic-x")


def test_with_nothing_configured_the_live_sources_are_all_not_connected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "DATABASE_URL",
        "NETBOX_BASE_URL",
        "NETBOX_TOKEN",
        "LIBRENMS_BASE_URL",
        "LIBRENMS_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    live = get_context_sources()
    assert run(live.topology()).state == "not-connected"
    incidents, alerts = run(live.changes(window_start=START, window_end=NOW, target="x"))
    assert (incidents.state, alerts.state) == ("not-connected", "not-connected")
