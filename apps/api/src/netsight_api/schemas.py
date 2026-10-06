"""Typed platform-boundary models for the read-only device API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

DeviceStatus = Literal[
    "healthy",
    "warning",
    "degraded",
    "critical",
    "offline",
    "unknown",
    "maintenance",
]
FreshnessState = Literal["fresh", "stale", "unknown"]
AlertSeverity = Literal["info", "low", "medium", "high", "critical"]
AlertState = Literal["open", "acknowledged", "investigating", "resolved", "suppressed"]


class ApiModel(BaseModel):
    """Strict base model for data crossing the HTTP API boundary."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Freshness(ApiModel):
    state: FreshnessState
    observed_at: datetime | None
    source: str | None = Field(default=None, min_length=1, max_length=64)


class DeviceSourceAlias(ApiModel):
    source: str = Field(min_length=1, max_length=64)
    native_id: str = Field(min_length=1, max_length=255)


class Device(ApiModel):
    id: str = Field(
        min_length=43,
        max_length=43,
        pattern=r"^device-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    name: str = Field(min_length=1, max_length=255)
    hostname: str | None = Field(default=None, max_length=255)
    type: str = Field(default="unknown", min_length=1, max_length=128)
    status: DeviceStatus
    ip_addresses: list[str] = Field(default_factory=list, max_length=256)
    mac_addresses: list[str] = Field(default_factory=list, max_length=256)
    site_id: str | None = Field(default=None, max_length=255)
    owner_identity_id: str | None = Field(default=None, max_length=255)
    source_aliases: list[DeviceSourceAlias] = Field(min_length=1, max_length=32)
    freshness: Freshness


class DeviceListResponse(ApiModel):
    items: list[Device]
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    total: int = Field(ge=0)
    freshness: Freshness


InterfaceAdminStatus = Literal["up", "down", "testing", "unknown"]
InterfaceOperStatus = Literal[
    "up",
    "down",
    "testing",
    "dormant",
    "notPresent",
    "lowerLayerDown",
    "unknown",
]


class InterfaceSourceAlias(ApiModel):
    source: str = Field(min_length=1, max_length=64)
    native_id: str = Field(min_length=1, max_length=255)


class NetworkInterface(ApiModel):
    """Canonical interface record.

    ``admin_status`` and ``oper_status`` keep the source's own vocabulary
    because operators act on them directly. ``status`` is the derived
    Netsight health state and is never inferred when the source is silent:
    an unreported link state becomes ``unknown``, not ``healthy``.
    """

    id: str = Field(
        min_length=46,
        max_length=46,
        pattern=(
            r"^interface-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        ),
    )
    device_id: str = Field(
        min_length=43,
        max_length=43,
        pattern=r"^device-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    index: int | None = Field(default=None, ge=0)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=255)
    alias: str | None = Field(default=None, max_length=255)
    hardware_type: str | None = Field(default=None, max_length=128)
    mac_address: str | None = Field(default=None, max_length=64)
    admin_status: InterfaceAdminStatus
    oper_status: InterfaceOperStatus
    status: DeviceStatus
    speed_bps: int | None = Field(default=None, ge=0)
    source_aliases: list[InterfaceSourceAlias] = Field(min_length=1, max_length=32)
    freshness: Freshness


class InterfaceListResponse(ApiModel):
    items: list[NetworkInterface] = Field(max_length=2048)
    total: int = Field(ge=0)
    freshness: Freshness


class DeviceDetailResponse(ApiModel):
    item: Device


class Alert(ApiModel):
    id: str
    severity: AlertSeverity
    state: AlertState
    title: str
    observed_at: datetime
    device_id: str | None = None
    incident_id: str | None = None


class AlertListResponse(ApiModel):
    items: list[Alert]
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    total: int = Field(ge=0)
    freshness: Freshness


class SourceHealthResponse(ApiModel):
    source: Literal["librenms", "netbox"]
    status: Literal["success", "unavailable", "forbidden", "invalid-source-data"]
    reachable: bool
    latency_ms: float | None = Field(default=None, ge=0)
    checked_at: datetime
    detail: Literal["ok", "unavailable", "forbidden", "invalid-source-data"]


class ErrorDetail(ApiModel):
    code: str = Field(min_length=1, max_length=64, pattern=r"^[A-Z0-9_]+$")
    message: str = Field(min_length=1, max_length=255)
    correlation_id: str = Field(min_length=1, max_length=64)


class ErrorEnvelope(ApiModel):
    error: ErrorDetail


class HealthResponse(ApiModel):
    status: Literal["ok"]


class DeviceStatusCount(ApiModel):
    status: DeviceStatus
    count: int = Field(ge=0)


class DeviceHealthSummary(ApiModel):
    total: int = Field(ge=0)
    by_status: list[DeviceStatusCount] = Field(max_length=8)
    freshness: Freshness


class SourceState(ApiModel):
    configured: bool
    status: Literal["success", "unavailable", "forbidden", "invalid-source-data", "not-configured"]


class ReconciliationFinding(ApiModel):
    kind: Literal["missing-discovered", "unknown-discovered", "status-mismatch"]
    netbox_device_id: str | None = None
    discovered_device_id: str | None = None
    detail: str


class ReconciliationFindingsResponse(ApiModel):
    items: list[ReconciliationFinding]


class OverviewResponse(ApiModel):
    devices: DeviceHealthSummary
    sources: dict[Literal["librenms"], SourceState]


class ProviderState(ApiModel):
    """Public sign-in provider configuration state.

    Reports only whether a provider is connected. Client secrets and
    allow-list values are never exposed.
    """

    configured: bool


class AuthProvidersResponse(ApiModel):
    providers: dict[Literal["microsoft", "google"], ProviderState]
