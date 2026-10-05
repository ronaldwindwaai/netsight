"""Read-only NetBox adapter for canonical Netsight device data.

NetBox is the intended source of truth (ADR/architecture). This adapter owns
the vendor URL shape, authentication header, source-data validation and
source-ID mapping. Source failures are typed and never silently converted
into empty successful results. Discovered data must never overwrite or
impersonate source-of-truth records; this adapter only reports them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from time import perf_counter
from typing import Any, cast
from urllib.parse import quote
from uuid import NAMESPACE_URL, uuid5

import httpx
from pydantic import ValidationError

from netsight_api.schemas import (
    Device,
    DeviceSourceAlias,
    DeviceStatus,
    Freshness,
)

ADAPTER_VERSION = "netbox/1"
SOURCE_NAME = "netbox"


class AdapterStatus(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    STALE = "stale"
    UNAVAILABLE = "unavailable"
    FORBIDDEN = "forbidden"
    INVALID_SOURCE_DATA = "invalid-source-data"


class AdapterError(Exception):
    """A sanitised source failure safe to map at the platform boundary."""

    def __init__(self, status: AdapterStatus, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


class DeviceNotFoundError(Exception):
    """Raised when a device does not exist in the current source inventory."""


@dataclass(frozen=True)
class SourceHealth:
    source: str
    status: AdapterStatus
    reachable: bool
    latency_ms: float | None
    checked_at: datetime
    detail: str


@dataclass(frozen=True)
class DeviceCollection:
    items: tuple[Device, ...]
    observed_at: datetime


def canonical_device_id(native_id: str) -> str:
    value = uuid5(NAMESPACE_URL, f"urn:netsight:{SOURCE_NAME}:device:{native_id}")
    return f"device-{value}"


def _required_text(value: object, field_name: str) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, f"missing {field_name}")


def _optional_text(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _optional_display_text(value: object) -> str | None:
    """NetBox renders relations as ``{"display": "..."}`` dicts or plain strings."""
    if isinstance(value, dict):
        display = value.get("display")
        if isinstance(display, str) and display.strip():
            return display.strip()
        name = value.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
        return None
    return _optional_text(value)


def _native_id(row: dict[str, Any]) -> str:
    value = row.get("id")
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid device id")
    native_id = str(value).strip()
    if not native_id:
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid device id")
    return native_id


def _device_rows(body: dict[str, Any]) -> list[dict[str, Any]]:
    raw = body.get("results")
    if not isinstance(raw, list):
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "missing device list")
    rows: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid device row")
        rows.append(cast(dict[str, Any], item))
    return rows


def _netbox_status(row: dict[str, Any]) -> DeviceStatus:
    status = row.get("status")
    if isinstance(status, dict):
        value = status.get("value") or status.get("label")
        if isinstance(value, str):
            value = value.strip().lower()
            if value == "active":
                return "healthy"
            if value == "offline":
                return "offline"
            if value in ("planned", "staged"):
                return "unknown"
            if value == "failed":
                return "critical"
            if value in ("inventory", "decommissioning"):
                return "maintenance"
            return "unknown"
    if isinstance(status, str) and status.strip():
        value = status.strip().lower()
        if value == "active":
            return "healthy"
        if value == "offline":
            return "offline"
        if value == "failed":
            return "critical"
        if value in ("inventory", "decommissioning"):
            return "maintenance"
        return "unknown"
    return "unknown"


def _primary_ip(row: dict[str, Any]) -> str | None:
    for key in ("primary_ip4", "primary_ip6", "primary_ip"):
        candidate = row.get(key)
        if isinstance(candidate, dict):
            address = candidate.get("address")
            if isinstance(address, str) and address.strip():
                # NetBox returns CIDR form ("10.0.0.1/24"); strip prefix.
                return address.split("/", 1)[0].strip()
        if isinstance(candidate, str) and candidate.strip():
            return candidate.split("/", 1)[0].strip()
    return None


def _map_device(row: dict[str, Any], observed_at: datetime) -> Device:
    native_id = _native_id(row)
    display = _optional_display_text(row.get("name")) or _optional_display_text(row.get("display"))
    name = _required_text(display, "device name")
    hostname = _optional_text(row.get("name")) or name
    device_type = _optional_display_text(row.get("role")) or _optional_display_text(row.get("device_type")) or "unknown"
    site_name = _optional_display_text(row.get("site"))
    ip = _primary_ip(row)
    try:
        return Device(
            id=canonical_device_id(native_id),
            name=name,
            hostname=hostname,
            type=device_type,
            status=_netbox_status(row),
            ip_addresses=[ip] if ip is not None else [],
            mac_addresses=[],
            site_id=site_name,
            owner_identity_id=None,
            source_aliases=[DeviceSourceAlias(source=SOURCE_NAME, native_id=native_id)],
            freshness=Freshness(state="fresh", observed_at=observed_at, source=SOURCE_NAME),
        )
    except ValidationError as exc:
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid device row") from exc


@dataclass
class NetboxClient:
    base_url: str
    token: str = field(repr=False)
    timeout_seconds: float = 10.0
    _transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Token {self.token}",
            "Accept": "application/json",
        }

    async def _get(self, path: str, *, not_found_is_device: bool = False) -> dict[str, Any]:
        url = f"{self.base_url.rstrip('/')}{path}"
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds,
                transport=self._transport,
                follow_redirects=False,
            ) as client:
                response = await client.get(url, headers=self._headers())
        except httpx.TimeoutException as exc:
            raise AdapterError(AdapterStatus.UNAVAILABLE, "request timed out") from exc
        except httpx.HTTPError as exc:
            raise AdapterError(AdapterStatus.UNAVAILABLE, "request failed") from exc

        if response.status_code == 404 and not_found_is_device:
            raise DeviceNotFoundError
        if response.status_code in (401, 403):
            raise AdapterError(AdapterStatus.FORBIDDEN, "source denied the request")
        if response.status_code >= 500 or response.status_code in (408, 425, 429):
            raise AdapterError(AdapterStatus.UNAVAILABLE, "source is unavailable")
        if response.status_code >= 400:
            raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "unexpected source response")

        try:
            raw_body: object = response.json()
        except ValueError as exc:
            raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "non-json response") from exc
        if not isinstance(raw_body, dict):
            raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "unexpected payload shape")
        return cast(dict[str, Any], raw_body)

    async def health(self) -> SourceHealth:
        checked_at = datetime.now(UTC)
        started = perf_counter()
        try:
            await self._get("/api/status/")
        except AdapterError as exc:
            detail_by_status = {
                AdapterStatus.UNAVAILABLE: "unavailable",
                AdapterStatus.FORBIDDEN: "forbidden",
                AdapterStatus.INVALID_SOURCE_DATA: "invalid-source-data",
            }
            return SourceHealth(
                source=SOURCE_NAME,
                status=exc.status,
                reachable=False,
                latency_ms=None,
                checked_at=checked_at,
                detail=detail_by_status.get(exc.status, "unavailable"),
            )
        elapsed_ms = (perf_counter() - started) * 1000
        return SourceHealth(
            source=SOURCE_NAME,
            status=AdapterStatus.SUCCESS,
            reachable=True,
            latency_ms=round(elapsed_ms, 1),
            checked_at=checked_at,
            detail="ok",
        )

    async def devices(self) -> DeviceCollection:
        body = await self._get("/api/dcim/devices/")
        observed_at = datetime.now(UTC)
        devices = tuple(_map_device(row, observed_at) for row in _device_rows(body))
        return DeviceCollection(items=devices, observed_at=observed_at)

    async def get_device(self, native_id: str) -> Device:
        encoded_native_id = quote(native_id, safe="")
        body = await self._get(
            f"/api/dcim/devices/{encoded_native_id}/",
            not_found_is_device=True,
        )
        if "results" in body:
            rows = _device_rows(body)
        else:
            # NetBox detail endpoints return a single object, not a list.
            rows = [body]
        if len(rows) != 1:
            raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "unexpected device detail count")
        device = _map_device(rows[0], datetime.now(UTC))
        if device.source_aliases[0].native_id != native_id:
            raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "device detail identity mismatch")
        return device

    async def device(self, canonical_id: str) -> Device:
        collection = await self.devices()
        for device in collection.items:
            if device.id == canonical_id:
                return await self.get_device(device.source_aliases[0].native_id)
        raise DeviceNotFoundError
