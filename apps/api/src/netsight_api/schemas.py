"""Typed platform-boundary models for the read-only device API."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)

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


_DEVICE_ID_PATTERN = r"^device-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"


class TopologyNodeFinding(ApiModel):
    """Reconciliation finding attached to a topology node (edge context).

    Reconciliation output never overwrites source-of-truth records; it is
    only surfaced alongside the graph so operators see intent-vs-discovery
    drift exactly where the device sits in the topology.
    """

    kind: Literal["missing-discovered", "status-mismatch"]
    detail: str = Field(min_length=1, max_length=255)


class TopologyNode(ApiModel):
    device_id: str = Field(pattern=_DEVICE_ID_PATTERN, min_length=43, max_length=43)
    # Source-reported name; None when the source did not report one (never
    # inferred). Required (nullable) so the OpenAPI contract, canonical JSON
    # schema and browser parser all agree on presence.
    name: str | None = Field(..., max_length=255)
    # Whether reconciliation ran for this graph: False means "not checked"
    # (discovery source unavailable), which is not the same as "in sync".
    reconciled: bool
    # None = checked and in sync (when reconciled) or not checked.
    finding: TopologyNodeFinding | None

    @model_validator(mode="after")
    def _finding_requires_reconciliation(self) -> TopologyNode:
        """A finding is only evidence when reconciliation actually ran."""
        if self.finding is not None and not self.reconciled:
            raise ValueError("finding requires reconciled=true")
        return self


class TopologyEdge(ApiModel):
    source_device_id: str = Field(pattern=_DEVICE_ID_PATTERN, min_length=43, max_length=43)
    target_device_id: str = Field(pattern=_DEVICE_ID_PATTERN, min_length=43, max_length=43)
    source: Literal["lldp", "cdp", "routing", "switching", "netbox", "manual"]
    observed_at: datetime | None = None


class TopologyResponse(ApiModel):
    state: Literal["not-connected", "ok", "unknown"]
    nodes: list[TopologyNode] = Field(max_length=10_000)
    edges: list[TopologyEdge] = Field(max_length=10_000)
    freshness: Freshness


class OverviewResponse(ApiModel):
    devices: DeviceHealthSummary
    sources: dict[Literal["librenms", "netbox"], SourceState]


class ProviderState(ApiModel):
    """Public sign-in provider configuration state.

    Reports only whether a provider is connected. Client secrets and
    allow-list values are never exposed.
    """

    configured: bool


class AuthProvidersResponse(ApiModel):
    providers: dict[Literal["microsoft", "google"], ProviderState]


# --- Traffic (S4) -----------------------------------------------------------

TrafficState = Literal["not-connected", "ok", "unknown"]
TrafficDimension = Literal["talkers", "destinations"]
TrafficPreset = Literal["1h", "6h", "24h", "7d"]


class TrafficTimeRange(ApiModel):
    """Requested window (server-bounded, never source data)."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    from_: datetime = Field(..., alias="from")
    to: datetime
    preset: TrafficPreset | None


class TrafficItem(ApiModel):
    """One ranked row of a traffic aggregate.

    `label` is source-reported and untrusted; `subject_id` is a canonical ID
    only when the source resolves one (never inferred).
    """

    rank: int = Field(ge=1, le=1000)
    subject_kind: Literal["device", "ip", "user", "application", "domain", "asn", "interface"]
    subject_id: str | None = Field(..., min_length=1, max_length=128)
    label: str = Field(min_length=1, max_length=255)
    bytes: int = Field(ge=0)
    packets: int | None = Field(..., ge=0)
    share: float | None = Field(..., ge=0, le=1)


class TrafficTopResponse(ApiModel):
    state: TrafficState
    dimension: TrafficDimension
    time_range: TrafficTimeRange
    items: list[TrafficItem] = Field(max_length=1000)
    freshness: Freshness

    @model_validator(mode="after")
    def _non_ok_carries_no_rows(self) -> TrafficTopResponse:
        """A degraded state must never assert traffic data.

        This mirrors the canonical JSON schema `if state != ok then no items`
        rule and the browser parser, so the invariant is enforced at the
        platform boundary rather than only by construction convention.
        """
        if self.state != "ok" and self.items:
            raise ValueError("non-ok traffic state must not carry items")
        return self


class TrafficFlow(ApiModel):
    """One high-volume flow row; all enrichment fields are source-reported."""

    observed_at: datetime
    source_ip: str = Field(min_length=1, max_length=45)
    source_device_id: str | None = Field(..., pattern=_DEVICE_ID_PATTERN, max_length=43)
    destination_ip: str = Field(min_length=1, max_length=45)
    destination_host: str | None = Field(..., min_length=1, max_length=255)
    protocol: Literal["tcp", "udp", "icmp", "other"]
    destination_port: int | None = Field(..., ge=0, le=65535)
    bytes: int = Field(ge=0)
    packets: int | None = Field(..., ge=0)
    direction: Literal["inbound", "outbound", "internal", "unknown"]
    application: str | None = Field(..., min_length=1, max_length=255)
    user: str | None = Field(..., min_length=1, max_length=255)


class TrafficFlowsResponse(ApiModel):
    state: TrafficState
    time_range: TrafficTimeRange
    flows: list[TrafficFlow] = Field(max_length=500)
    freshness: Freshness

    @model_validator(mode="after")
    def _non_ok_carries_no_rows(self) -> TrafficFlowsResponse:
        """A degraded state must never assert flow data (see top response)."""
        if self.state != "ok" and self.flows:
            raise ValueError("non-ok traffic state must not carry flows")
        return self


# --- Security (S5) ----------------------------------------------------------

SecurityState = Literal["not-connected", "ok", "unknown"]


class SecurityEvent(ApiModel):
    """One security event; every text field is untrusted source telemetry."""

    id: str = Field(min_length=1, max_length=128)
    observed_at: datetime
    source: Literal["wazuh", "suricata"]
    severity: AlertSeverity
    category: str | None = Field(..., min_length=1, max_length=128)
    signature: str = Field(min_length=1, max_length=512)
    source_ip: str | None = Field(..., min_length=1, max_length=45)
    destination_ip: str | None = Field(..., min_length=1, max_length=45)
    device_id: str | None = Field(..., pattern=_DEVICE_ID_PATTERN, max_length=43)


class SecurityEventsResponse(ApiModel):
    state: SecurityState
    time_range: TrafficTimeRange
    events: list[SecurityEvent] = Field(max_length=500)
    freshness: Freshness

    @model_validator(mode="after")
    def _non_ok_carries_no_rows(self) -> SecurityEventsResponse:
        """A degraded state must never assert security events."""
        if self.state != "ok" and self.events:
            raise ValueError("non-ok security state must not carry events")
        return self


# --- Incidents, alert rules, maintenance windows (S6) -----------------------
#
# These mirror contracts/json-schema/incident.schema.json and
# alert-rule.schema.json and the OpenAPI components of the same names; the
# four-way agreement tests drive all of them from one vector file. Unlike the
# read-only telemetry models above they are strict (no type coercion), frozen
# and never strip input, so pydantic accepts exactly what the schema accepts.


class ContractModel(ApiModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        str_strip_whitespace=False,
        populate_by_name=True,
        serialize_by_alias=True,
    )


_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
INCIDENT_ID_PATTERN = rf"^incident-{_UUID}$"
TIMELINE_EVENT_ID_PATTERN = rf"^incident-event-{_UUID}$"
ALERT_RULE_ID_PATTERN = rf"^alert-rule-{_UUID}$"
MAINTENANCE_WINDOW_ID_PATTERN = rf"^maintenance-{_UUID}$"
NON_BLANK = r"\S"
MAX_MAINTENANCE_DURATION = timedelta(days=30)

IncidentSeverity = Literal["low", "medium", "high", "critical"]
IncidentState = Literal["open", "acknowledged", "investigating", "mitigated", "resolved", "closed"]
RootCauseStatus = Literal["determined", "not-determined"]
TimelineEventKind = Literal[
    "alert-linked",
    "alert-unlinked",
    "assignee-changed",
    "comment",
    "diagnostic",
    "action-proposed",
    "action-approved",
    "action-executed",
    "evidence-added",
    "state-changed",
    "resolution",
]
AlertScopeKind = Literal[
    "organisation", "site", "device", "device_group", "vlan", "user", "service"
]
AlertOperator = Literal["gt", "gte", "lt", "lte", "eq", "ne", "matches"]
BaselineMode = Literal["none", "above-baseline", "below-baseline", "outside-baseline"]
Weekday = Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
AlertRuleStatus = Literal["draft", "active", "disabled"]
AlertAction = Literal["create_alert", "email", "push"]
IncidentPolicy = Literal["none", "create", "group"]
MaintenanceEvaluation = Literal["retain", "disable"]
MaintenanceStatus = Literal["scheduled", "cancelled"]

IdentityRef = Annotated[str, Field(min_length=1, max_length=255)]
FollowUpAction = Annotated[str, Field(min_length=1, max_length=500, pattern=NON_BLANK)]
EvidenceRef = Annotated[str, Field(min_length=1, max_length=128)]
ShortName = Annotated[str, Field(min_length=1, max_length=128)]
_TIME_OF_DAY = r"^([01][0-9]|2[0-3]):[0-5][0-9]$"
_THRESHOLD_BOUND = 1_000_000_000_000_000


def _require_unique(values: list[str], what: str) -> None:
    if len(set(values)) != len(values):
        raise ValueError(f"{what} must be unique")


class IncidentResolutionInput(ContractModel):
    """Operator-supplied resolution fields (the store adds who and when)."""

    summary: str = Field(min_length=1, max_length=2000, pattern=NON_BLANK)
    root_cause_status: RootCauseStatus
    root_cause: str | None = Field(..., min_length=1, max_length=2000, pattern=NON_BLANK)
    impact: str = Field(min_length=1, max_length=2000, pattern=NON_BLANK)
    restored_at: AwareDatetime
    follow_up_actions: list[FollowUpAction] = Field(max_length=32)

    @model_validator(mode="after")
    def _root_cause_matches_status(self) -> IncidentResolutionInput:
        """'determined' needs an accepted root cause; 'not-determined' carries none."""
        if (self.root_cause_status == "determined") != (self.root_cause is not None):
            raise ValueError("root_cause is required exactly when root_cause_status is determined")
        return self


class IncidentResolution(IncidentResolutionInput):
    resolved_at: AwareDatetime
    resolved_by: IdentityRef

    @model_validator(mode="after")
    def _restored_not_after_resolved(self) -> IncidentResolution:
        if self.restored_at > self.resolved_at:
            raise ValueError("restored_at must not be after resolved_at")
        return self


class Incident(ContractModel):
    id: str = Field(min_length=45, max_length=45, pattern=INCIDENT_ID_PATTERN)
    title: str = Field(min_length=1, max_length=255, pattern=NON_BLANK)
    severity: IncidentSeverity
    state: IncidentState
    created_at: AwareDatetime
    updated_at: AwareDatetime
    assignee_id: str | None = Field(..., min_length=1, max_length=255)
    evidence_ids: list[EvidenceRef] = Field(max_length=256)
    resolution: IncidentResolution | None = Field(...)

    @model_validator(mode="after")
    def _invariants(self) -> Incident:
        _require_unique(self.evidence_ids, "evidence_ids")
        if (self.state in ("resolved", "closed")) != (self.resolution is not None):
            raise ValueError("resolution is required exactly when state is resolved or closed")
        return self


_SUBJECT_REQUIRED_KINDS = frozenset(
    {
        "alert-linked",
        "alert-unlinked",
        "diagnostic",
        "action-proposed",
        "action-approved",
        "action-executed",
        "evidence-added",
    }
)


class IncidentTimelineEvent(ContractModel):
    """One append-only timeline entry (no update or delete path exists)."""

    id: str = Field(min_length=51, max_length=51, pattern=TIMELINE_EVENT_ID_PATTERN)
    incident_id: str = Field(min_length=45, max_length=45, pattern=INCIDENT_ID_PATTERN)
    seq: int = Field(ge=1, le=1_000_000)
    occurred_at: AwareDatetime
    actor_id: IdentityRef
    kind: TimelineEventKind
    state_from: IncidentState | None = Field(...)
    state_to: IncidentState | None = Field(...)
    reason: str | None = Field(..., min_length=1, max_length=1000, pattern=NON_BLANK)
    message: str | None = Field(..., min_length=1, max_length=4000, pattern=NON_BLANK)
    subject_id: str | None = Field(..., min_length=1, max_length=128)

    @model_validator(mode="after")
    def _payload_matches_kind(self) -> IncidentTimelineEvent:
        is_state_change = self.kind == "state-changed"
        has_states = self.state_from is not None and self.state_to is not None
        if is_state_change != has_states:
            raise ValueError("state_from and state_to are required exactly for state-changed")
        if not is_state_change and (self.state_from is not None or self.state_to is not None):
            raise ValueError("state_from and state_to are only valid for state-changed")
        if is_state_change and self.state_to == "open" and self.reason is None:
            raise ValueError("reopening an incident requires a reason")
        if self.kind in ("comment", "resolution") and self.message is None:
            raise ValueError(f"{self.kind} requires a message")
        if self.kind in _SUBJECT_REQUIRED_KINDS and self.subject_id is None:
            raise ValueError(f"{self.kind} requires a subject_id")
        return self


# --- Incident routes (S6-2): response envelopes and request bodies --------------------
#
# Mirrors contracts/json-schema/incident-api.schema.json. Responses are strict contract
# models built by the server; request bodies are lax API models (FastAPI validates JSON
# bodies in python mode, where strict datetime parsing would reject ISO strings) that
# are re-validated against the strict contract models before they reach the store.

StoreState = Literal["not-connected", "ok", "unknown"]
MAX_INCIDENT_PAGE_SIZE = 100
MAX_INCIDENT_LIST_OFFSET = 10_000
MAX_TIMELINE_PAGE_SIZE = 500
MAX_TIMELINE_SEQ = 1_000_000
# Transitions reachable through the generic transition operation: resolve and reopen carry
# mandatory fields and human-only permissions, so they are separate operations.
TransitionTarget = Literal["acknowledged", "investigating", "mitigated", "closed"]


class IncidentListResponse(ContractModel):
    state: StoreState
    incidents: list[Incident] = Field(max_length=MAX_INCIDENT_PAGE_SIZE)
    limit: int = Field(ge=1, le=MAX_INCIDENT_PAGE_SIZE)
    offset: int = Field(ge=0, le=MAX_INCIDENT_LIST_OFFSET)
    next_offset: int | None = Field(..., ge=1, le=MAX_INCIDENT_LIST_OFFSET)

    @model_validator(mode="after")
    def _non_ok_carries_no_rows(self) -> IncidentListResponse:
        """A degraded state must never assert incidents or offer a continuation."""
        if self.state != "ok" and (self.incidents or self.next_offset is not None):
            raise ValueError("non-ok incident state must not carry incidents or a cursor")
        return self


class IncidentDetailResponse(ContractModel):
    state: StoreState
    incident: Incident | None = Field(...)

    @model_validator(mode="after")
    def _incident_exactly_when_ok(self) -> IncidentDetailResponse:
        if (self.state == "ok") != (self.incident is not None):
            raise ValueError("incident is present exactly when state is ok")
        return self


class IncidentTimelineResponse(ContractModel):
    state: StoreState
    incident_id: str = Field(min_length=45, max_length=45, pattern=INCIDENT_ID_PATTERN)
    events: list[IncidentTimelineEvent] = Field(max_length=MAX_TIMELINE_PAGE_SIZE)
    after_seq: int = Field(ge=0, le=MAX_TIMELINE_SEQ)
    next_after_seq: int | None = Field(..., ge=1, le=MAX_TIMELINE_SEQ)

    @model_validator(mode="after")
    def _non_ok_carries_no_rows(self) -> IncidentTimelineResponse:
        if self.state != "ok" and (self.events or self.next_after_seq is not None):
            raise ValueError("non-ok incident state must not carry events or a cursor")
        return self


class IncidentTransitionRequest(ApiModel):
    to_state: TransitionTarget
    reason: str | None = Field(None, min_length=1, max_length=1000, pattern=NON_BLANK)


class IncidentAssignRequest(ApiModel):
    assignee_id: str | None = Field(..., min_length=1, max_length=255)


class IncidentCommentRequest(ApiModel):
    message: str = Field(min_length=1, max_length=4000, pattern=NON_BLANK)


class IncidentEvidenceRequest(ApiModel):
    evidence_id: EvidenceRef


class IncidentResolveRequest(ApiModel):
    summary: str = Field(min_length=1, max_length=2000, pattern=NON_BLANK)
    root_cause_status: RootCauseStatus
    root_cause: str | None = Field(..., min_length=1, max_length=2000, pattern=NON_BLANK)
    impact: str = Field(min_length=1, max_length=2000, pattern=NON_BLANK)
    restored_at: AwareDatetime
    follow_up_actions: list[FollowUpAction] = Field(max_length=32)

    @model_validator(mode="after")
    def _root_cause_matches_status(self) -> IncidentResolveRequest:
        if (self.root_cause_status == "determined") != (self.root_cause is not None):
            raise ValueError("root_cause is required exactly when root_cause_status is determined")
        return self

    def to_resolution(self) -> IncidentResolutionInput:
        """Re-validate against the strict contract model the store accepts."""
        return IncidentResolutionInput.model_validate_json(self.model_dump_json())


class IncidentReopenRequest(ApiModel):
    reason: str = Field(min_length=1, max_length=1000, pattern=NON_BLANK)


class AlertScope(ContractModel):
    kind: AlertScopeKind
    ref: str = Field(min_length=1, max_length=255)


class AlertCondition(ContractModel):
    metric: str = Field(
        min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$"
    )
    operator: AlertOperator
    threshold: float | None = Field(
        ..., ge=-_THRESHOLD_BOUND, le=_THRESHOLD_BOUND, allow_inf_nan=False
    )
    pattern: str | None = Field(..., min_length=1, max_length=256)

    @model_validator(mode="after")
    def _operand_matches_operator(self) -> AlertCondition:
        if self.operator == "matches":
            if self.pattern is None or self.threshold is not None:
                raise ValueError("matches takes a pattern and no threshold")
        elif self.threshold is None or self.pattern is not None:
            raise ValueError(f"{self.operator} takes a threshold and no pattern")
        return self


class AlertScheduleEntry(ContractModel):
    weekdays: list[Weekday] = Field(min_length=1, max_length=7)
    from_: str = Field(alias="from", pattern=_TIME_OF_DAY)
    to: str = Field(pattern=_TIME_OF_DAY)

    @model_validator(mode="after")
    def _unique_weekdays(self) -> AlertScheduleEntry:
        _require_unique(list(self.weekdays), "weekdays")
        return self


class AlertSchedule(ContractModel):
    timezone: str = Field(
        max_length=64,
        pattern=r"^(UTC|[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z][A-Za-z0-9_+-]*){1,2})$",
    )
    active: list[AlertScheduleEntry] = Field(min_length=1, max_length=14)


class AlertExceptions(ContractModel):
    destinations: list[ShortName] = Field(max_length=64)
    device_groups: list[ShortName] = Field(max_length=64)

    @model_validator(mode="after")
    def _unique(self) -> AlertExceptions:
        _require_unique(self.destinations, "destinations")
        _require_unique(self.device_groups, "device_groups")
        return self


class AlertRuleDefinition(ContractModel):
    """Operator-editable rule fields (everything except lifecycle and audit)."""

    name: str = Field(min_length=1, max_length=255, pattern=NON_BLANK)
    scope: AlertScope
    condition: AlertCondition
    baseline_mode: BaselineMode
    window_seconds: int = Field(ge=60, le=86_400)
    for_seconds: int = Field(ge=0, le=86_400)
    cooldown_seconds: int = Field(ge=0, le=604_800)
    schedule: AlertSchedule | None = Field(...)
    exceptions: AlertExceptions
    severity: AlertSeverity
    labels: dict[
        Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,62}$")],
        Annotated[str, Field(max_length=128)],
    ] = Field(max_length=32)
    actions: list[AlertAction] = Field(min_length=1, max_length=3)
    incident_policy: IncidentPolicy

    @model_validator(mode="after")
    def _unique_actions(self) -> AlertRuleDefinition:
        _require_unique(list(self.actions), "actions")
        return self


class AlertRule(AlertRuleDefinition):
    id: str = Field(min_length=47, max_length=47, pattern=ALERT_RULE_ID_PATTERN)
    status: AlertRuleStatus
    created_by: IdentityRef
    created_at: AwareDatetime
    updated_at: AwareDatetime
    approved_by: str | None = Field(..., min_length=1, max_length=255)
    approved_at: AwareDatetime | None = Field(...)
    version: int = Field(ge=1, le=1_000_000)

    @model_validator(mode="after")
    def _approval_invariants(self) -> AlertRule:
        """No rule is active without a recorded approval; drafts are never approved."""
        if (self.approved_by is None) != (self.approved_at is None):
            raise ValueError("approved_by and approved_at must be set together")
        if self.status == "active" and self.approved_by is None:
            raise ValueError("an active rule requires approval")
        if self.status == "draft" and self.approved_by is not None:
            raise ValueError("a draft rule cannot carry an approval")
        return self


class MaintenanceWindowDefinition(ContractModel):
    name: str = Field(min_length=1, max_length=255, pattern=NON_BLANK)
    scope: AlertScope
    starts_at: AwareDatetime
    ends_at: AwareDatetime
    evaluation: MaintenanceEvaluation
    reason: str = Field(min_length=1, max_length=1000, pattern=NON_BLANK)

    @model_validator(mode="after")
    def _bounded_positive_duration(self) -> MaintenanceWindowDefinition:
        duration = self.ends_at - self.starts_at
        if duration <= timedelta(0):
            raise ValueError("ends_at must be after starts_at")
        if duration > MAX_MAINTENANCE_DURATION:
            raise ValueError("a maintenance window may last at most 30 days")
        return self


class MaintenanceWindow(MaintenanceWindowDefinition):
    id: str = Field(min_length=48, max_length=48, pattern=MAINTENANCE_WINDOW_ID_PATTERN)
    status: MaintenanceStatus
    created_by: IdentityRef
    created_at: AwareDatetime
    cancelled_by: str | None = Field(..., min_length=1, max_length=255)
    cancelled_at: AwareDatetime | None = Field(...)

    @model_validator(mode="after")
    def _cancellation_invariants(self) -> MaintenanceWindow:
        has_cancellation = self.cancelled_by is not None and self.cancelled_at is not None
        has_partial = (self.cancelled_by is None) != (self.cancelled_at is None)
        if has_partial or (self.status == "cancelled") != has_cancellation:
            raise ValueError("cancelled_by and cancelled_at are required exactly when cancelled")
        return self
