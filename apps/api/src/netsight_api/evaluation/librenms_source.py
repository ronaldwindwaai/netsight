"""LibreNMS-backed observations, built on the existing read-only adapter.

Metrics (both per canonical device, scoped to the device and the organisation):

* ``device.status``: 1.0 up, 0.0 down, ``None`` when LibreNMS cannot say (status unknown) or the
  device is disabled/ignored on the LibreNMS side (it is not being monitored, so there is
  nothing to judge);
* ``device.alert_count``: the number of *open* (not acknowledged) LibreNMS alerts on the device;
  every known device is reported (0.0 when quiet) so that a count can fall back below its
  threshold, which an alert-only list could never express.

Everything goes through ``LibrenmsClient`` (vendor shapes stay in the adapter). Device names and
alert titles are untrusted text and are not copied into observations at all. More than
``MAX_OBSERVATIONS`` devices is reported as ``unknown`` rather than silently truncated.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from datetime import datetime
from typing import Final

from netsight_api.adapters.librenms import AdapterError, LibrenmsClient
from netsight_api.alerting.engine import Observation
from netsight_api.evaluation.source import ObservationBatch
from netsight_api.schemas import Device

MAX_OBSERVATIONS: Final = 5000
SUPPORTED_METRICS: Final = ("device.status", "device.alert_count")
ORGANISATION_SCOPE: Final = ("organisation", "default")


def _status_value(device: Device) -> float | None:
    if device.status == "healthy":
        return 1.0
    if device.status == "offline":
        return 0.0
    return None  # unknown / maintenance: no data, never a guess


class LibrenmsObservationSource:
    def __init__(self, client_provider: Callable[[], LibrenmsClient | None]) -> None:
        self._client_provider = client_provider

    def __repr__(self) -> str:
        return "LibrenmsObservationSource()"

    def supports(self, metric: str) -> bool:
        return metric in SUPPORTED_METRICS

    async def observe(self, metric: str, *, now: datetime) -> ObservationBatch:
        if not self.supports(metric):
            raise ValueError("unsupported metric")
        client = self._client_provider()
        if client is None:
            return ObservationBatch("not-connected")
        try:
            devices = (await client.devices()).items
            counts = await self._open_alert_counts(client) if metric == "device.alert_count" else {}
        except AdapterError:
            return ObservationBatch("unknown", detail="SOURCE_FAILED")
        if len(devices) > MAX_OBSERVATIONS:
            return ObservationBatch("unknown", detail="TOO_MANY_OBSERVATIONS")
        observations = tuple(
            Observation(
                at=now,
                entity=device.id,
                scopes=frozenset({("device", device.id), ORGANISATION_SCOPE}),
                value=_status_value(device)
                if metric == "device.status"
                else float(counts.get(device.id, 0)),
            )
            for device in devices
        )
        return ObservationBatch("ok", observations)

    @staticmethod
    async def _open_alert_counts(client: LibrenmsClient) -> Counter[str]:
        alerts = await client.alerts()
        return Counter(
            alert["device_id"]
            for alert in alerts
            if alert.get("state") == "open" and alert.get("device_id") is not None
        )
