"""Where a diagnostic run gets its context from (S7 Step 4): topology, changes and the store.

``ContextSources`` is the narrow, read-only interface the run needs; ``LiveContextSources`` is
built from the sources that are actually configured (NetBox for the explicit topology, the
incident store and LibreNMS for recent changes). An unconfigured source reads ``not-connected``,
a source that fails reads ``unknown`` without leaking its error, and nothing is ever invented.
Everything here is bounded: one incident page, one alert list, one device list, one cable list.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Callable
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, NoReturn, Protocol, cast

from fastapi import Depends
from fastapi.concurrency import run_in_threadpool

from netsight_api.adapters.netbox import canonical_device_id as netbox_canonical_device_id
from netsight_api.diagnostic_changes import ChangeCandidate, SourceRead
from netsight_api.diagnostic_path import TopologyDevice, TopologyLink, TopologyRead
from netsight_api.incident_deps import get_optional_incident_store
from netsight_api.schemas import Alert
from netsight_api.storage import IncidentRepository, StorageConfigurationError, StorageError
from netsight_api.storage.diagnostics import DiagnosticSessionRepository

if TYPE_CHECKING:
    from netsight_api.adapters.librenms import LibrenmsClient
    from netsight_api.adapters.netbox import NetboxClient

_LOGGER = logging.getLogger("netsight_api")

# One page of the newest incidents is plenty: the panel shows at most twenty changes.
INCIDENT_SCAN_LIMIT = 100


class ContextSources(Protocol):
    async def topology(self) -> TopologyRead: ...

    async def changes(
        self, *, window_start: datetime, window_end: datetime, target: str
    ) -> tuple[SourceRead, SourceRead]:
        """(incidents, alerts) candidates; callers apply the window and the caps."""
        ...


def _warn(message: str, exc: Exception) -> None:
    _LOGGER.warning(message, extra={"error_type": type(exc).__name__})


class LiveContextSources:
    def __init__(
        self,
        *,
        incident_store: IncidentRepository | None,
        librenms: LibrenmsClient | None,
        netbox: NetboxClient | None,
    ) -> None:
        self._incidents = incident_store
        self._librenms = librenms
        self._netbox = netbox

    # --- topology (NetBox cables are the only edge source) ---------------------------------

    async def topology(self) -> TopologyRead:
        netbox = self._netbox
        if netbox is None:
            return TopologyRead("not-connected", (), (), None)
        try:
            cables, devices = await asyncio.gather(netbox.cables(), netbox.devices())
        except Exception as exc:  # noqa: BLE001 — a failed source is an explicit unknown
            _warn("diagnostic topology read failed", exc)
            return TopologyRead("unknown", (), (), None)
        return TopologyRead(
            state="ok",
            devices=tuple(
                TopologyDevice(
                    device_id=device.id,
                    name=device.name,
                    role=device.type,
                    hostname=device.hostname,
                    addresses=tuple(device.ip_addresses),
                )
                for device in devices.items
            ),
            links=tuple(
                TopologyLink(
                    netbox_canonical_device_id(link.device_a_native_id),
                    netbox_canonical_device_id(link.device_b_native_id),
                )
                for link in cables.links
            ),
            observed_at=min(cables.observed_at, devices.observed_at),
        )

    # --- recent changes ----------------------------------------------------------------------

    async def changes(
        self, *, window_start: datetime, window_end: datetime, target: str
    ) -> tuple[SourceRead, SourceRead]:
        return await asyncio.gather(self._incident_changes(), self._alert_changes(target))

    async def _incident_changes(self) -> SourceRead:
        store = self._incidents
        if store is None:
            return SourceRead("not-connected")
        try:
            rows = await run_in_threadpool(lambda: store.list_incidents(limit=INCIDENT_SCAN_LIMIT))
        except Exception as exc:  # noqa: BLE001
            _warn("diagnostic incident read failed", exc)
            return SourceRead("unknown")
        return SourceRead(
            "ok",
            # No title: an incident change is a reference (id, severity, time) only.
            tuple(
                ChangeCandidate("incident", row.id, None, row.created_at, row.severity)
                for row in rows
            ),
        )

    async def _alert_changes(self, target: str) -> SourceRead:
        client = self._librenms
        if client is None:
            return SourceRead("not-connected")
        try:
            rows, devices = await asyncio.gather(client.alerts(), client.devices())
            alerts = [Alert.model_validate(row) for row in rows]
        except Exception as exc:  # noqa: BLE001
            _warn("diagnostic alert read failed", exc)
            return SourceRead("unknown")
        wanted = target.strip().casefold()
        mine = {
            device.id
            for device in devices.items
            if wanted
            and wanted
            in {
                device.name.casefold(),
                (device.hostname or "").casefold(),
                *(address.casefold() for address in device.ip_addresses),
            }
        }
        return SourceRead(
            "ok",
            tuple(
                ChangeCandidate(
                    "alert",
                    alert.id,
                    alert.title,
                    alert.observed_at,
                    about_target=(
                        # The source's own device link decides; an alert without one is time-only.
                        None if alert.device_id is None else alert.device_id in mine
                    ),
                )
                for alert in alerts
            ),
        )


# --- dependencies ---------------------------------------------------------------------------------


class _UnavailableStore:
    """Stands in when ``DATABASE_URL`` is set but unusable: every call fails as unavailable."""

    def __getattr__(self, name: str) -> Callable[..., NoReturn]:
        def unavailable(*_args: object, **_kwargs: object) -> NoReturn:
            raise StorageError("the diagnostic session store is not usable")

        return unavailable


def get_optional_diagnostic_session_store() -> DiagnosticSessionRepository | None:
    """PostgreSQL store for the app role (``DATABASE_URL``); ``None`` means not-connected."""
    if not os.environ.get("DATABASE_URL", "").strip():
        return None
    from netsight_api.storage.connection import PostgresSettings
    from netsight_api.storage.postgres_diagnostics import PostgresDiagnosticSessionRepository

    try:
        settings = PostgresSettings.from_env()
    except StorageConfigurationError:
        return cast(DiagnosticSessionRepository, _UnavailableStore())
    return PostgresDiagnosticSessionRepository(settings)


def get_context_sources() -> ContextSources:
    """The configured sources. ``main`` is imported lazily: it owns the adapter factories."""
    from netsight_api import main

    return LiveContextSources(
        incident_store=get_optional_incident_store(),
        librenms=main.get_optional_librenms_client(),
        netbox=main.get_optional_netbox_client(),
    )


OptionalSessionStore = Annotated[
    DiagnosticSessionRepository | None, Depends(get_optional_diagnostic_session_store)
]
Context = Annotated[ContextSources, Depends(get_context_sources)]
