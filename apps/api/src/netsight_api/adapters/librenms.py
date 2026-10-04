"""Read-only LibreNMS adapter for canonical Netsight device data.

This module owns the vendor URL shape, authentication header, source-data
validation and source-ID mapping. Source failures are typed and never
silently converted into empty successful results.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from time import perf_counter
from typing import Any, cast
from urllib.parse import quote
from uuid import NAMESPACE_URL, uuid5
from zoneinfo import ZoneInfo

import httpx
from pydantic import ValidationError

from netsight_api.schemas import Device, DeviceSourceAlias, DeviceStatus, Freshness

ADAPTER_VERSION = "librenms/1"
SOURCE_NAME = "librenms"

_ALERT_SEVERITY_MAP = {
    "critical": "critical",
    "warning": "high",
    "notice": "medium",
}

_RFC3339_DATE_TIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}"
    r"(?P<fraction>\.\d+)?"
    r"(?:[Zz]|(?P<offset_sign>[+-])(?P<offset_hour>\d{2}):(?P<offset_minute>\d{2}))$",
    re.ASCII,
)
_LIBRENMS_NATIVE_DATE_TIME = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$",
    re.ASCII,
)


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
    """Return a stable, opaque platform ID while retaining the source alias."""

    value = uuid5(NAMESPACE_URL, f"urn:netsight:{SOURCE_NAME}:device:{native_id}")
    return f"device-{value}"


def _source_boolean(value: object) -> bool:
    return value is True or value == 1 or value == "1"


def _required_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdapterError(
            AdapterStatus.INVALID_SOURCE_DATA,
            f"invalid {field_name}",
        )
    return value.strip()


def _optional_text(value: object) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid text field")
    return value.strip() or None


def _invalid_alert_timestamp() -> AdapterError:
    return AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid alert timestamp")


def _format_utc(timestamp: datetime, *, fraction: str = "") -> str:
    utc_timestamp = timestamp.astimezone(UTC)
    return f"{utc_timestamp:%Y-%m-%dT%H:%M:%S}{fraction}Z"


def _normalize_rfc3339_timestamp(timestamp: str, match: re.Match[str]) -> str:
    offset_hour = match.group("offset_hour")
    offset_minute = match.group("offset_minute")
    if offset_hour is not None and (
        int(offset_hour) > 23
        or offset_minute is None
        or int(offset_minute) > 59
    ):
        raise _invalid_alert_timestamp()
    normalized = f"{timestamp[:-1]}+00:00" if timestamp[-1] in "Zz" else timestamp
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        raise _invalid_alert_timestamp() from None
    if parsed.utcoffset() is None:
        raise _invalid_alert_timestamp()
    return _format_utc(parsed, fraction=match.group("fraction") or "")


def _normalize_native_timestamp(timestamp: str, source_timezone: ZoneInfo | None) -> str:
    if not isinstance(source_timezone, ZoneInfo):
        raise _invalid_alert_timestamp()
    try:
        naive_timestamp = datetime.fromisoformat(timestamp)
    except ValueError:
        raise _invalid_alert_timestamp() from None

    candidates: list[datetime] = []
    for fold in (0, 1):
        candidate = naive_timestamp.replace(tzinfo=source_timezone, fold=fold)
        round_trip = candidate.astimezone(UTC).astimezone(source_timezone)
        if (
            round_trip.replace(tzinfo=None) == naive_timestamp
            and round_trip.fold == fold
        ):
            candidates.append(candidate)
    if len(candidates) != 1:
        raise _invalid_alert_timestamp()
    return _format_utc(candidates[0])


def _alert_timestamp(value: object, source_timezone: ZoneInfo | None) -> str:
    if not isinstance(value, str):
        raise _invalid_alert_timestamp()
    timestamp = value.strip()
    if not timestamp:
        raise _invalid_alert_timestamp()
    rfc3339_match = _RFC3339_DATE_TIME.fullmatch(timestamp)
    if rfc3339_match is not None:
        return _normalize_rfc3339_timestamp(timestamp, rfc3339_match)
    if _LIBRENMS_NATIVE_DATE_TIME.fullmatch(timestamp) is not None:
        return _normalize_native_timestamp(timestamp, source_timezone)
    raise _invalid_alert_timestamp()


def _native_id(row: dict[str, Any]) -> str:
    value = row.get("device_id")
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid device id")
    native_id = str(value).strip()
    if not native_id:
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid device id")
    return native_id


def _device_status(row: dict[str, Any]) -> DeviceStatus:
    if _source_boolean(row.get("disabled")) or _source_boolean(row.get("ignore")):
        return "maintenance"
    status = row.get("status")
    if _source_boolean(status):
        return "healthy"
    if status in (False, 0, "0"):
        return "offline"
    return "unknown"


def _map_device(row: dict[str, Any], observed_at: datetime) -> Device:
    native_id = _native_id(row)
    hostname = _required_text(row.get("hostname"), "hostname")
    display_name = row.get("display") or row.get("sysName") or hostname
    name = _required_text(display_name, "device name")
    device_type = _optional_text(row.get("type")) or "unknown"
    ip_address = _optional_text(row.get("ip"))
    mac_address = _optional_text(row.get("mac"))
    try:
        return Device(
            id=canonical_device_id(native_id),
            name=name,
            hostname=hostname,
            type=device_type,
            status=_device_status(row),
            ip_addresses=[ip_address] if ip_address is not None else [],
            mac_addresses=[mac_address] if mac_address is not None else [],
            site_id=None,
            owner_identity_id=None,
            source_aliases=[DeviceSourceAlias(source=SOURCE_NAME, native_id=native_id)],
            freshness=Freshness(
                state="fresh",
                observed_at=observed_at,
                source=SOURCE_NAME,
            ),
        )
    except ValidationError as exc:
        raise AdapterError(
            AdapterStatus.INVALID_SOURCE_DATA,
            "device does not satisfy canonical contract",
        ) from exc


def _device_rows(body: dict[str, Any]) -> list[dict[str, Any]]:
    if body.get("status") != "ok":
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid source status")
    raw_rows = body.get("devices")
    if not isinstance(raw_rows, list):
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "missing devices list")
    rows: list[dict[str, Any]] = []
    for raw_row in raw_rows:
        if not isinstance(raw_row, dict):
            raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid device row")
        rows.append(cast(dict[str, Any], raw_row))
    source_count = body.get("count")
    if source_count is not None:
        try:
            count = int(source_count)
        except (TypeError, ValueError) as exc:
            raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid device count") from exc
        if count != len(rows):
            raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "device count mismatch")
    return rows


@dataclass
class LibrenmsClient:
    base_url: str
    token: str = field(repr=False)
    timeout_seconds: float = 10.0
    source_timezone: ZoneInfo | None = field(default=None, kw_only=True)
    _transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
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
            await self._get("/api/v0/system")
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
        body = await self._get("/api/v0/devices")
        observed_at = datetime.now(UTC)
        devices = tuple(_map_device(row, observed_at) for row in _device_rows(body))
        return DeviceCollection(items=devices, observed_at=observed_at)

    async def get_device(self, native_id: str) -> Device:
        encoded_native_id = quote(native_id, safe="")
        body = await self._get(
            f"/api/v0/devices/{encoded_native_id}",
            not_found_is_device=True,
        )
        rows = _device_rows(body)
        if not rows:
            raise DeviceNotFoundError
        if len(rows) != 1:
            raise AdapterError(
                AdapterStatus.INVALID_SOURCE_DATA,
                "unexpected device detail count",
            )
        device = _map_device(rows[0], datetime.now(UTC))
        if device.source_aliases[0].native_id != native_id:
            raise AdapterError(
                AdapterStatus.INVALID_SOURCE_DATA,
                "device detail identity mismatch",
            )
        return device

    async def device(self, canonical_id: str) -> Device:
        collection = await self.devices()
        for device in collection.items:
            if device.id == canonical_id:
                return await self.get_device(device.source_aliases[0].native_id)
        raise DeviceNotFoundError

    async def alerts(self) -> list[dict[str, Any]]:
        body = await self._get("/api/v0/alerts")
        raw = body.get("alerts")
        if not isinstance(raw, list):
            raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "missing alerts list")
        canonical: list[dict[str, Any]] = []
        for raw_row in raw:
            if not isinstance(raw_row, dict):
                raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid alert row")
            row = cast(dict[str, Any], raw_row)
            if "id" not in row:
                raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid alert row")
            severity_raw = str(row.get("severity", "")).lower()
            source_device_id = row.get("device_id")
            canonical.append(
                {
                    "id": f"librenms:{row['id']}",
                    "severity": _ALERT_SEVERITY_MAP.get(severity_raw, "info"),
                    "state": (
                        "open"
                        if row.get("state") in (0, "0", "active")
                        else "acknowledged"
                    ),
                    "title": row.get("name") or row.get("rule", "alert"),
                    "observed_at": _alert_timestamp(
                        row.get("timestamp"),
                        self.source_timezone,
                    ),
                    "device_id": (
                        canonical_device_id(str(source_device_id))
                        if source_device_id is not None
                        else None
                    ),
                }
            )
        return canonical
