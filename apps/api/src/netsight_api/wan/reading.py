"""Assembles ``GET /api/v1/internet`` from LibreNMS port readings and stored probe samples.

Sources and what each may say (nothing else is ever stated):

* LibreNMS (``WanPortSource``): operational status, link speed, in/out rates and the public IPv4
  of the operator-declared port. Absent client or no declared port: ``not-connected``; a failing,
  hung or silent source: ``unknown``; counters older than ``INTERFACE_STALE_SECONDS`` (by the
  source's own poll time) or with no poll time are shown but labelled ``stale`` / ``unknown``.
* Callers without ``internet:read_detail`` get ``redact_detail`` applied by the route: the ISP
  name, gateway, public IP and throughput are withheld (null with ``detail_redacted``).
* The probe-sample store: latency, jitter, loss and DNS from the last ``QUALITY_WINDOW_SECONDS``
  of samples, and rolling 24-hour availability and the outage in progress from the stored cycles.
  No store: ``not-connected``; a failing store: ``unknown``; no samples yet: ``ok`` but empty.

Link status and failover are inferred (``status.py``) from *current* evidence only: a stale or
undated interface reading and a lapsed probe round contribute nothing. A source failure is logged
by error type and link id; nothing the source said (URLs, driver messages) reaches the response.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Final, Protocol

from netsight_api.adapters.librenms import WanPortReading
from netsight_api.schemas import Freshness
from netsight_api.schemas_internet import (
    InternetResponse,
    WanAvailability,
    WanConfigured,
    WanFailover,
    WanInterfaceReading,
    WanLink,
    WanQuality,
)
from netsight_api.storage.errors import StorageError
from netsight_api.storage.wan import WanSampleRepository
from netsight_api.wan import sla, status
from netsight_api.wan.config import WanConfig, WanLinkConfig

_LOGGER: Final = logging.getLogger("netsight_api")

INTERFACE_STALE_SECONDS: Final = 900
QUALITY_WINDOW_SECONDS: Final = 900
AVAILABILITY_WINDOW_SECONDS: Final = 86_400
PORT_TIMEOUT_SECONDS: Final = 10.0
_CLOCK_SKEW: Final = timedelta(seconds=60)
LIBRENMS_SOURCE: Final = "librenms"
PROBE_SOURCE: Final = "blackbox-probes"

_NO_FRESHNESS = Freshness(state="unknown", observed_at=None, source=None)


class WanPortSource(Protocol):
    async def wan_port(
        self, native_device_id: str, native_port_id: str
    ) -> WanPortReading | None: ...


# --- interface ----------------------------------------------------------------------------------


def _no_interface(state: str, source: str | None = None) -> WanInterfaceReading:
    return WanInterfaceReading(
        state=state,  # type: ignore[arg-type]
        oper_status=None,
        capacity_bps=None,
        rx_bps=None,
        tx_bps=None,
        utilisation_pct=None,
        public_ip=None,
        freshness=Freshness(state="unknown", observed_at=None, source=source),
    )


def _interface_freshness(polled_at: datetime | None, now: datetime) -> Freshness:
    if polled_at is None or polled_at > now + _CLOCK_SKEW:
        return Freshness(state="unknown", observed_at=None, source=LIBRENMS_SOURCE)
    age = (now - polled_at).total_seconds()
    if age <= INTERFACE_STALE_SECONDS:
        return Freshness(state="fresh", observed_at=polled_at, source=LIBRENMS_SOURCE)
    return Freshness(state="stale", observed_at=polled_at, source=LIBRENMS_SOURCE)


def _utilisation(reading: WanPortReading) -> float | None:
    capacity = reading.speed_bps
    if not capacity or reading.rx_bps is None or reading.tx_bps is None:
        return None
    return round(max(reading.rx_bps, reading.tx_bps) / capacity * 100, 3)


def _interface_from(reading: WanPortReading, now: datetime) -> WanInterfaceReading:
    return WanInterfaceReading(
        state="ok",
        oper_status=reading.oper_status,
        capacity_bps=reading.speed_bps,
        rx_bps=reading.rx_bps,
        tx_bps=reading.tx_bps,
        utilisation_pct=_utilisation(reading),
        public_ip=reading.public_ip,
        freshness=_interface_freshness(reading.polled_at, now),
    )


async def _read_interface(
    link: WanLinkConfig, ports: WanPortSource | None, now: datetime
) -> WanInterfaceReading:
    if ports is None or link.librenms_device is None or link.librenms_port is None:
        return _no_interface("not-connected")
    try:
        reading = await asyncio.wait_for(
            ports.wan_port(link.librenms_device, link.librenms_port),
            timeout=PORT_TIMEOUT_SECONDS,
        )
    except Exception as error:  # noqa: BLE001 - a source failure is `unknown`, never an error page
        _LOGGER.warning(
            "WAN interface read failed",
            extra={"link_id": link.id, "error_type": type(error).__name__},
        )
        return _no_interface("unknown", LIBRENMS_SOURCE)
    if reading is None:
        return _no_interface("unknown", LIBRENMS_SOURCE)
    return _interface_from(reading, now)


# --- probes -------------------------------------------------------------------------------------


def _probe_freshness(cycles: Sequence[sla.Cycle], now: datetime) -> Freshness:
    if not cycles:
        return Freshness(state="unknown", observed_at=None, source=PROBE_SOURCE)
    newest = cycles[-1]
    current = now < newest.sampled_at + timedelta(seconds=newest.coverage_seconds)
    return Freshness(
        state="fresh" if current else "stale", observed_at=newest.sampled_at, source=PROBE_SOURCE
    )


def _no_probes(state: str) -> tuple[WanQuality, WanAvailability]:
    freshness = Freshness(state="unknown", observed_at=None, source=PROBE_SOURCE)
    quality = WanQuality(
        state=state,  # type: ignore[arg-type]
        latency_ms=None,
        jitter_ms=None,
        loss_pct=None,
        dns_status=None,
        dns_latency_ms=None,
        sample_count=0,
        window_seconds=QUALITY_WINDOW_SECONDS,
        freshness=freshness,
    )
    availability = WanAvailability(
        state=state,  # type: ignore[arg-type]
        period_start=None,
        period_end=None,
        uptime_pct=None,
        coverage_pct=None,
        current_outage_started_at=None,
        current_outage_seconds=None,
        freshness=freshness,
    )
    return quality, availability


def _probe_blocks(
    cycles: Sequence[sla.Cycle],
    rows: Sequence[tuple[datetime, sla.Sample]],
    now: datetime,
) -> tuple[WanQuality, WanAvailability]:
    freshness = _probe_freshness(cycles, now)
    measured = sla.quality(rows)
    quality = WanQuality(
        state="ok",
        latency_ms=measured.latency_ms,
        jitter_ms=measured.jitter_ms,
        loss_pct=measured.loss_pct,
        dns_status=measured.dns_status,
        dns_latency_ms=measured.dns_latency_ms,
        sample_count=measured.sample_count,
        window_seconds=QUALITY_WINDOW_SECONDS,
        freshness=freshness,
    )
    start = now - timedelta(seconds=AVAILABILITY_WINDOW_SECONDS)
    summary = sla.summarise(cycles, start, now)
    outage = sla.current_outage(cycles, now)
    availability = WanAvailability(
        state="ok",
        period_start=start,
        period_end=now,
        uptime_pct=summary.uptime_pct,
        coverage_pct=summary.coverage_pct,
        current_outage_started_at=None if outage is None else outage.started_at,
        current_outage_seconds=None if outage is None else outage.duration_seconds,
        freshness=freshness,
    )
    return quality, availability


def _read_store(
    link: WanLinkConfig, store: WanSampleRepository, now: datetime
) -> tuple[list[sla.Cycle], list[tuple[datetime, sla.Sample]]]:
    end = now + timedelta(seconds=1)
    cycles = store.cycles_between(
        link.id, now - timedelta(seconds=AVAILABILITY_WINDOW_SECONDS), end
    )
    rows = store.samples_between(link.id, now - timedelta(seconds=QUALITY_WINDOW_SECONDS), end)
    return cycles, rows


async def _read_probes(
    link: WanLinkConfig, store: WanSampleRepository | None, now: datetime
) -> tuple[WanQuality, WanAvailability, str | None]:
    """Quality, availability and the latest *current* cycle state (``None`` if none is current)."""
    if store is None:
        return (*_no_probes("not-connected"), None)
    try:
        cycles, rows = await asyncio.to_thread(_read_store, link, store, now)
        quality, availability = _probe_blocks(cycles, rows, now)
    except (StorageError, ValueError, OSError) as error:
        _LOGGER.warning(
            "WAN probe store read failed",
            extra={"link_id": link.id, "error_type": type(error).__name__},
        )
        return (*_no_probes("unknown"), None)
    current = quality.freshness.state == "fresh"
    return quality, availability, cycles[-1].state if cycles and current else None


# --- assembly -----------------------------------------------------------------------------------


def _interface_evidence(interface: WanInterfaceReading) -> str | None:
    """The interface status only while it is a current reading."""
    if interface.state == "ok" and interface.freshness.state == "fresh":
        return interface.oper_status
    return None


async def _build_link(
    link: WanLinkConfig,
    ports: WanPortSource | None,
    store: WanSampleRepository | None,
    now: datetime,
) -> WanLink:
    interface, (quality, availability, probe_state) = await asyncio.gather(
        _read_interface(link, ports, now), _read_probes(link, store, now)
    )
    return WanLink(
        id=link.id,
        name=link.name,
        role=link.role,
        configured=WanConfigured(
            isp=link.isp, gateway=link.gateway, probe_location=link.probe_location
        ),
        status=status.link_status(_interface_evidence(interface), probe_state),
        interface=interface,
        quality=quality,
        availability=availability,
    )


async def build_internet(
    config: WanConfig,
    ports: WanPortSource | None,
    store: WanSampleRepository | None,
    now: datetime,
) -> InternetResponse:
    if config.state != "ok":
        return InternetResponse(
            state=config.state,
            generated_at=now,
            links=[],
            failover=WanFailover(state="unknown", basis="unknown"),
            detail_redacted=False,
        )
    links = list(
        await asyncio.gather(*(_build_link(link, ports, store, now) for link in config.links))
    )
    state, basis = status.failover([(link.role, link.status) for link in links])
    return InternetResponse(
        state="ok",
        generated_at=now,
        links=links,
        failover=WanFailover(state=state, basis=basis),
        detail_redacted=False,
    )


def redact_detail(response: InternetResponse) -> InternetResponse:
    """A copy of ``response`` without what only ``internet:read_detail`` may see.

    Withheld (null, ``detail_redacted`` true): the ISP name, the gateway, the public IP and the
    per-link throughput (rx, tx and the utilisation derived from them). Status, capacity, probe
    quality, availability and freshness stay: they are the status and SLA summary. The original is
    not modified, and redacting twice changes nothing more.
    """
    links = [
        link.model_copy(
            update={
                "configured": link.configured.model_copy(update={"isp": None, "gateway": None}),
                "interface": link.interface.model_copy(
                    update={
                        "public_ip": None,
                        "rx_bps": None,
                        "tx_bps": None,
                        "utilisation_pct": None,
                    }
                ),
            }
        )
        for link in response.links
    ]
    return response.model_copy(update={"links": links, "detail_redacted": True})
