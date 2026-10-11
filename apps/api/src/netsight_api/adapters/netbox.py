"""Read-only NetBox adapter for canonical Netsight device data.

NetBox is the intended source of truth (ADR/architecture). This adapter owns
the vendor URL shape, authentication header, source-data validation and
source-ID mapping. Source failures are typed and never silently converted
into empty successful results. Discovered data must never overwrite or
impersonate source-of-truth records; this adapter only reports them.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from time import perf_counter
from typing import Any, cast
from urllib.parse import quote, urlsplit
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
_MAX_CABLE_PAGES = 10
# Identity evidence reads: 500 rows a page, at most 10 pages. More than that is a failure (a partial
# list would hide a second owner or a duplicate address), never a silent truncation.
_ASSIGNMENT_PAGE_SIZE = 500
_MAX_ASSIGNMENT_PAGES = 10
_MAX_TEXT = 128
# Upper bound on one decoded response body: a hostile or broken NetBox cannot make a read hold more.
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
# A custom-field name as NetBox allows it, and the agent key a device may carry in it.
CUSTOM_FIELD_NAME = re.compile(r"[a-z][a-z0-9_]{0,49}")
AGENT_KEY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


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


@dataclass(frozen=True)
class CableLink:
    """One explicit physical link between two NetBox devices.

    Only cables whose terminations resolve to devices on both ends are ever
    reported; anything else is dropped rather than guessed.
    """

    device_a_native_id: str
    device_b_native_id: str
    observed_at: datetime | None


@dataclass(frozen=True)
class CableCollection:
    links: tuple[CableLink, ...]
    observed_at: datetime


@dataclass(frozen=True)
class IpAssignment:
    """A static address NetBox assigned to a device interface (declared intent, not observation)."""

    address: str
    device_native_id: str
    device_name: str | None
    last_updated: datetime | None


@dataclass(frozen=True)
class IpAssignmentCollection:
    items: tuple[IpAssignment, ...]
    observed_at: datetime
    skipped: int = 0


@dataclass(frozen=True)
class ContactAssignment:
    """A NetBox contact assigned to a device with a role. Every text field is untrusted."""

    contact_native_id: str
    contact_name: str | None
    device_native_id: str
    device_name: str | None
    role: str | None
    last_updated: datetime | None


@dataclass(frozen=True)
class ContactAssignmentCollection:
    items: tuple[ContactAssignment, ...]
    observed_at: datetime
    skipped: int = 0


@dataclass(frozen=True)
class DeviceAgentKey:
    """The Wazuh agent id an operator recorded on a NetBox device (the cross-source join key)."""

    device_native_id: str
    agent_key: str


@dataclass(frozen=True)
class DeviceAgentKeyCollection:
    items: tuple[DeviceAgentKey, ...]
    observed_at: datetime
    skipped: int = 0


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


def _cable_rows(body: dict[str, Any]) -> list[dict[str, Any]]:
    raw = body.get("results")
    if not isinstance(raw, list):
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "missing cable list")
    rows: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid cable row")
        rows.append(cast(dict[str, Any], item))
    return rows


def _cable_is_active(row: dict[str, Any]) -> bool:
    """Only explicitly active cables count as evidence of a link."""
    status = row.get("status")
    if isinstance(status, dict):
        value = status.get("value") or status.get("label")
    elif isinstance(status, str):
        value = status
    else:
        return False
    return isinstance(value, str) and value.strip().lower() == "active"


def _termination_device_native_id(row: dict[str, Any], key: str) -> str | None:
    """Resolve a cable termination to its device native ID, or None.

    Never guesses: a termination without a nested device ID yields None and
    the cable is skipped by the caller.
    """
    termination = row.get(key)
    if not isinstance(termination, dict):
        return None
    obj = termination.get("object")
    if not isinstance(obj, dict):
        return None
    device = obj.get("device")
    if not isinstance(device, dict):
        return None
    value = device.get("id")
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None
    native_id = str(value).strip()
    return native_id or None


def _cable_timestamp(row: dict[str, Any]) -> datetime | None:
    for key in ("last_updated", "created"):
        raw = row.get(key)
        if isinstance(raw, str) and raw.strip():
            try:
                parsed = datetime.fromisoformat(raw.strip())
            except ValueError:
                continue
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed.astimezone(UTC)
    return None


def _bounded_text(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()[:_MAX_TEXT]
    return None


def _native_text(value: object) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None
    text = str(value).strip()
    return text or None


def _status_value(row: dict[str, Any]) -> str | None:
    status = row.get("status")
    value = status.get("value") if isinstance(status, dict) else status
    return value.strip().lower() if isinstance(value, str) else None


def _ip_assignment(row: dict[str, Any]) -> IpAssignment | None:
    """A static interface assignment, or None when the row is not one (DHCP, VM, unassigned)."""
    if _status_value(row) != "active" or row.get("assigned_object_type") != "dcim.interface":
        return None
    assigned = row.get("assigned_object")
    device = assigned.get("device") if isinstance(assigned, dict) else None
    device_id = _native_text(device.get("id")) if isinstance(device, dict) else None
    if device_id is None or not isinstance(device, dict):
        return None
    raw = row.get("address")
    if not isinstance(raw, str):
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid ip address row")
    try:
        address = str(ipaddress.ip_interface(raw.strip()).ip)
    except ValueError as exc:
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid ip address row") from exc
    return IpAssignment(
        address=address,
        device_native_id=device_id,
        device_name=_bounded_text(device.get("name")),
        last_updated=_cable_timestamp(row),
    )


def _contact_assignment(row: dict[str, Any]) -> ContactAssignment | None:
    """A contact assigned to a device, or None when the row is about another kind of object."""
    if row.get("object_type") != "dcim.device":
        return None
    contact = row.get("contact")
    contact_id = _native_text(contact.get("id")) if isinstance(contact, dict) else None
    obj = row.get("object")
    device_id = _native_text(row.get("object_id")) or (
        _native_text(obj.get("id")) if isinstance(obj, dict) else None
    )
    if contact_id is None or device_id is None or not isinstance(contact, dict):
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid contact assignment row")
    role = row.get("role")
    return ContactAssignment(
        contact_native_id=contact_id,
        contact_name=_bounded_text(contact.get("name")) or _bounded_text(contact.get("display")),
        device_native_id=device_id,
        device_name=_bounded_text(obj.get("name")) if isinstance(obj, dict) else None,
        role=_bounded_text(role.get("name")) if isinstance(role, dict) else _bounded_text(role),
        last_updated=_cable_timestamp(row),
    )


def _device_agent_key(row: dict[str, Any], field_name: str) -> DeviceAgentKey | None:
    """The device's agent key, None when it carries none; raises when the value is unusable."""
    fields = row.get("custom_fields")
    value = fields.get(field_name) if isinstance(fields, dict) else None
    if value is None or value == "":
        return None
    device_id = _native_text(row.get("id"))
    key = _native_text(value)
    if device_id is None or key is None or AGENT_KEY_PATTERN.fullmatch(key) is None:
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid agent key")
    return DeviceAgentKey(device_native_id=device_id, agent_key=key)


def _tolerant[T](
    rows: list[dict[str, Any]], parse: Callable[[dict[str, Any]], T | None]
) -> tuple[list[T], int]:
    """Parse every row; a malformed one is skipped and counted. Mostly-malformed output is a failure."""
    items: list[T] = []
    skipped = 0
    for row in rows:
        try:
            item = parse(row)
        except AdapterError:
            skipped += 1
            continue
        if item is not None:
            items.append(item)
    if skipped > len(items):
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "most rows are malformed")
    return items, skipped


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
    device_type = (
        _optional_display_text(row.get("role"))
        or _optional_display_text(row.get("device_type"))
        or "unknown"
    )
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
    max_response_bytes: int = _MAX_RESPONSE_BYTES
    _transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Token {self.token}",
            "Accept": "application/json",
            # The size cap counts decoded bytes, so refuse compressed bodies outright.
            "Accept-Encoding": "identity",
        }

    async def _read_body(self, response: httpx.Response) -> bytes:
        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > self.max_response_bytes:
            raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "response is too large")
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > self.max_response_bytes:
                raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "response is too large")
        return bytes(body)

    async def _get(self, path: str, *, not_found_is_device: bool = False) -> dict[str, Any]:
        url = f"{self.base_url.rstrip('/')}{path}"
        try:
            async with (
                httpx.AsyncClient(
                    timeout=self.timeout_seconds,
                    transport=self._transport,
                    follow_redirects=False,
                ) as client,
                client.stream("GET", url, headers=self._headers()) as response,
            ):
                status_code = response.status_code
                content = await self._read_body(response) if status_code < 300 else b""
        except httpx.TimeoutException as exc:
            raise AdapterError(AdapterStatus.UNAVAILABLE, "request timed out") from exc
        except httpx.HTTPError as exc:
            raise AdapterError(AdapterStatus.UNAVAILABLE, "request failed") from exc

        if status_code == 404 and not_found_is_device:
            raise DeviceNotFoundError
        if status_code in (401, 403):
            raise AdapterError(AdapterStatus.FORBIDDEN, "source denied the request")
        if status_code >= 500 or status_code in (408, 425, 429):
            raise AdapterError(AdapterStatus.UNAVAILABLE, "source is unavailable")
        if status_code >= 300:
            raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "unexpected source response")

        try:
            raw_body: object = json.loads(content)
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

    def _next_path(self, body: dict[str, Any]) -> str | None:
        """Return the path of the next pagination page, validated to same origin."""
        raw_next = body.get("next")
        if raw_next is None:
            return None
        if not isinstance(raw_next, str) or not raw_next.strip():
            raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid pagination url")
        base = urlsplit(self.base_url)
        candidate = urlsplit(raw_next.strip())
        if (candidate.scheme, candidate.netloc) != (base.scheme, base.netloc):
            raise AdapterError(AdapterStatus.UNAVAILABLE, "unexpected pagination origin")
        return f"{candidate.path}?{candidate.query}" if candidate.query else candidate.path

    async def cables(self) -> CableCollection:
        """Explicit physical links from NetBox cables (topology edge source).

        Bounded pagination: a runaway cable list is treated as a source
        failure rather than silently truncated into a partial graph.
        """
        links: list[CableLink] = []
        path: str | None = "/api/dcim/cables/?limit=1000"
        pages = 0
        while path is not None:
            if pages >= _MAX_CABLE_PAGES:
                raise AdapterError(AdapterStatus.UNAVAILABLE, "cable pagination exceeded")
            body = await self._get(path)
            for row in _cable_rows(body):
                if not _cable_is_active(row):
                    continue
                native_a = _termination_device_native_id(row, "termination_a")
                native_b = _termination_device_native_id(row, "termination_b")
                if native_a is None or native_b is None or native_a == native_b:
                    continue
                links.append(
                    CableLink(
                        device_a_native_id=native_a,
                        device_b_native_id=native_b,
                        observed_at=_cable_timestamp(row),
                    )
                )
            path = self._next_path(body)
            pages += 1
        return CableCollection(links=tuple(links), observed_at=datetime.now(UTC))

    async def _paged_rows(self, first_path: str) -> list[dict[str, Any]]:
        """Every row of a list endpoint, bounded: too many pages is a failure, not a truncation."""
        rows: list[dict[str, Any]] = []
        path: str | None = first_path
        pages = 0
        while path is not None:
            if pages >= _MAX_ASSIGNMENT_PAGES:
                raise AdapterError(AdapterStatus.UNAVAILABLE, "assignment pagination exceeded")
            body = await self._get(path)
            raw = body.get("results")
            if not isinstance(raw, list) or any(not isinstance(item, dict) for item in raw):
                raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid assignment list")
            rows.extend(cast(list[dict[str, Any]], raw))
            path = self._next_path(body)
            pages += 1
        return rows

    async def ip_assignments(self) -> IpAssignmentCollection:
        """Static, active addresses NetBox assigned to device interfaces (read-only).

        A malformed row is skipped and counted, not fatal; mostly-malformed output fails the read.
        """
        rows = await self._paged_rows(
            f"/api/ipam/ip-addresses/?limit={_ASSIGNMENT_PAGE_SIZE}"
            "&assigned_to_interface=true&status=active"
        )
        items, skipped = _tolerant(rows, _ip_assignment)
        return IpAssignmentCollection(tuple(items), datetime.now(UTC), skipped)

    async def contact_assignments(self) -> ContactAssignmentCollection:
        """Contacts assigned to devices, with their role (read-only; other objects are ignored)."""
        rows = await self._paged_rows(
            f"/api/tenancy/contact-assignments/?limit={_ASSIGNMENT_PAGE_SIZE}"
        )
        items, skipped = _tolerant(rows, _contact_assignment)
        return ContactAssignmentCollection(tuple(items), datetime.now(UTC), skipped)

    async def device_agent_keys(self, field_name: str) -> DeviceAgentKeyCollection:
        """The agent id an operator recorded in the device custom field ``field_name`` (read-only).

        Only devices that carry a usable value are returned; the filter is repeated client side so a
        NetBox that ignores it cannot widen what is trusted.
        """
        if CUSTOM_FIELD_NAME.fullmatch(field_name) is None:
            raise AdapterError(AdapterStatus.UNAVAILABLE, "the agent-key field name is invalid")
        rows = await self._paged_rows(
            f"/api/dcim/devices/?limit={_ASSIGNMENT_PAGE_SIZE}&cf_{field_name}__empty=false"
        )
        items, skipped = _tolerant(rows, lambda row: _device_agent_key(row, field_name))
        return DeviceAgentKeyCollection(tuple(items), datetime.now(UTC), skipped)

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
