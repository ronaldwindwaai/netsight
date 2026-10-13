"""Typed boundary models for unknown-device findings (Step 8c).

Mirrors ``contracts/json-schema/unknown-devices.schema.json``, the OpenAPI components and the browser
parsers (shared vectors: ``contracts/test-vectors/unknown-devices.vectors.json``).

Honesty rules, enforced here and not only by construction:

* a finding is something telemetry saw that NetBox does not know: its comparison has no ``match`` and
  is not "nothing could be checked";
* the chain IP, MAC, switch or AP, port, VLAN holds only links that were actually observed (or
  inferred, never above 0.7); every other hop is ``unknown`` with the reason, never filled in;
* severity comes from the operator's policy: ``unknown`` exactly when no policy decided it;
* a quarantine is a recommendation only: ``executable`` is always false, because executing it is the
  action engine's job (Step 14) and needs step-up, a reason and human approval;
* the lifecycle is a fixed table (``ALLOWED_TRANSITIONS``); resolved and false-positive are final, and
  every resolution or dismissal carries its reason.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, StrictBool, model_validator

from netsight_api.schemas import ApiModel
from netsight_api.schemas_inventory import BlockState
from netsight_api.schemas_sources import SourceName, SourceStatus, check_unique_sources

UUID_PATTERN = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
FINDING_ID_PATTERN = rf"^unknown-device-{UUID_PATTERN}$"
EVENT_ID_PATTERN = rf"^unknown-device-event-{UUID_PATTERN}$"
MAC_PATTERN = r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$"
MAX_COUNT = 1_000_000
MAX_PAGE_SIZE = 50
MAX_TIMELINE_PAGE = 200
MAX_COMMENT = 4000
MAX_REASON = 1000
MAX_ASSIGNEE = 255
INFERRED_CEILING = 0.7
SYSTEM_ACTOR = "system:unknown-device-scan"

FindingState = Literal["new", "acknowledged", "investigating", "resolved", "false-positive"]
Severity = Literal["low", "medium", "high", "critical", "unknown"]
SeverityBasis = Literal["policy-rule", "policy-default", "no-policy"]
SlotName = Literal["ip", "mac", "attachment", "port", "vlan"]
LinkBasis = Literal["observed", "inferred", "unknown"]
SlotReason = Literal[
    "declared-assignment",
    "indirect-evidence",
    "low-confidence",
    "name-match",
    "no-evidence",
    "expired",
    "conflicting-evidence",
    "source-unavailable",
    "guest-network",
]
CheckField = Literal["ip", "mac", "hostname"]
CheckResult = Literal["match", "no-match", "not-checked"]
# Why the endpoint is a finding: nothing matched, or the name matched but the MAC did not (a name is
# corroboration only: anyone can claim one, so it never clears an endpoint).
ComparisonReason = Literal["no-match", "name-matches-mac-does-not"]
EventKind = Literal[
    "detected",
    "evidence-updated",
    "action-proposed",
    "state-changed",
    "assignee-changed",
    "comment",
    "suppressed-sighting",
]
OutcomeState = Literal["resolved", "false-positive"]

SLOT_ORDER: tuple[SlotName, ...] = ("ip", "mac", "attachment", "port", "vlan")
CHECK_ORDER: tuple[CheckField, ...] = ("ip", "mac", "hostname")
OPEN_STATES: tuple[FindingState, ...] = ("new", "acknowledged", "investigating")
FINAL_STATES: tuple[FindingState, ...] = ("resolved", "false-positive")
# Each state advances to a fixed set; resolved and false-positive are final (a new sighting after a
# resolution is a new finding; a dismissal keeps suppressing the endpoint).
ALLOWED_TRANSITIONS: dict[FindingState, frozenset[FindingState]] = {
    "new": frozenset({"acknowledged", "resolved", "false-positive"}),
    "acknowledged": frozenset({"investigating", "resolved", "false-positive"}),
    "investigating": frozenset({"resolved", "false-positive"}),
    "resolved": frozenset(),
    "false-positive": frozenset(),
}

FindingId = Annotated[str, Field(min_length=51, max_length=51, pattern=FINDING_ID_PATTERN)]
Count = Annotated[int, Field(ge=0, le=MAX_COUNT)]
_MAC = re.compile(MAC_PATTERN)


def _nonblank(value: str) -> str:
    if not value.strip():
        raise ValueError("text must not be blank")
    return value


class UnknownDeviceEvidenceRef(ApiModel):
    id: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=32, pattern=r"^[a-z0-9][a-z0-9_.-]{0,31}$")
    kind: str = Field(min_length=1, max_length=40, pattern=r"^[a-z0-9][a-z0-9-]{0,39}$")
    observed_at: AwareDatetime
    confidence: float | None = Field(..., ge=0, le=1, allow_inf_nan=False)


class UnknownDeviceLinkSlot(ApiModel):
    slot: SlotName
    basis: LinkBasis
    value: str | None = Field(..., min_length=1, max_length=128)
    label: str | None = Field(..., min_length=1, max_length=128)
    attachment_kind: Literal["switch", "ap"] | None
    confidence: float | None = Field(..., ge=0, le=1, allow_inf_nan=False)
    reason: SlotReason | None
    evidence: list[UnknownDeviceEvidenceRef] = Field(max_length=16)

    @model_validator(mode="after")
    def _basis_decides_what_may_be_said(self) -> UnknownDeviceLinkSlot:
        named = (self.value, self.label, self.attachment_kind, self.confidence)
        if self.basis == "unknown":
            if any(v is not None for v in named) or self.evidence or self.reason is None:
                raise ValueError("an unknown hop names nothing and says why")
            return self
        if self.value is None or not self.evidence:
            raise ValueError("a hop that is seen names its value and its evidence")
        if self.basis == "observed" and self.reason is not None:
            raise ValueError("an observed hop has no reason")
        if self.basis == "inferred" and (
            self.reason is None or self.confidence is None or self.confidence > INFERRED_CEILING
        ):
            raise ValueError("an inferred hop has a reason and a confidence of at most 0.7")
        if (self.slot == "attachment") != (self.attachment_kind is not None):
            raise ValueError("only an attachment names whether it is a switch or an access point")
        return self


class UnknownDeviceEndpoint(ApiModel):
    ip: str | None = Field(..., min_length=2, max_length=45)
    mac: str | None = Field(..., min_length=17, max_length=17, pattern=MAC_PATTERN)
    hostname: str | None = Field(..., min_length=1, max_length=255)

    @model_validator(mode="after")
    def _something_was_seen(self) -> UnknownDeviceEndpoint:
        if self.ip is None and self.mac is None and self.hostname is None:
            raise ValueError("an endpoint has an address, a MAC or a name")
        if self.ip is not None:
            try:
                canonical = str(ipaddress.ip_address(self.ip))
            except ValueError as error:
                raise ValueError("ip is an IP address") from error
            if canonical != self.ip:
                raise ValueError("ip is in canonical form")
        return self


class UnknownDeviceCheck(ApiModel):
    field: CheckField
    result: CheckResult
    detail: str | None = Field(..., min_length=1, max_length=255)


class UnknownDeviceComparison(ApiModel):
    checks: list[UnknownDeviceCheck] = Field(min_length=3, max_length=3)
    checked_at: AwareDatetime
    reason: ComparisonReason

    @model_validator(mode="after")
    def _nothing_cleared_it_and_something_was_asked(self) -> UnknownDeviceComparison:
        if tuple(c.field for c in self.checks) != CHECK_ORDER:
            raise ValueError("one check per field, in order")
        results = {c.field: c.result for c in self.checks}
        if self.reason == "name-matches-mac-does-not":
            # the one allowed match: the name, which is corroboration; the MAC was asked and said no
            if (results["ip"] == "match" or results["mac"] != "no-match") or (
                results["hostname"] != "match"
            ):
                raise ValueError("a name match is a finding only when the MAC was asked and differs")
            return self
        if "match" in results.values():
            raise ValueError("a finding exists only when nothing cleared the endpoint")
        if set(results.values()) == {"not-checked"}:
            raise ValueError("a comparison where nothing could be checked proves nothing")
        return self


class UnknownDeviceProposedAction(ApiModel):
    action_type: Literal["endpoint.isolate"]
    state: Literal["proposed"]
    risk: Literal["C"]
    executable: Literal[False]
    awaiting: Literal["action-engine"]
    rationale: str = Field(min_length=1, max_length=255)


class UnknownDeviceFinding(ApiModel):
    id: FindingId
    state: FindingState
    severity: Severity
    severity_basis: SeverityBasis
    # Counts changes of the evidence (endpoint, chain, comparison results, severity, proposal), not
    # sightings: a write that decides on the evidence it was shown quotes this and loses with 409
    # STALE_EVIDENCE if the evidence changed since.
    evidence_version: int = Field(ge=1, le=MAX_COUNT, strict=True)
    assignee_id: str | None = Field(..., min_length=1, max_length=MAX_ASSIGNEE)
    first_seen_at: AwareDatetime
    last_seen_at: AwareDatetime
    seen_count: int = Field(ge=1, le=MAX_COUNT)
    recurrence_of: FindingId | None
    endpoint: UnknownDeviceEndpoint
    chain: list[UnknownDeviceLinkSlot] = Field(min_length=5, max_length=5)
    comparison: UnknownDeviceComparison
    proposed_action: UnknownDeviceProposedAction | None

    @model_validator(mode="after")
    def _severity_follows_the_policy(self) -> UnknownDeviceFinding:
        if (self.severity == "unknown") != (self.severity_basis == "no-policy"):
            raise ValueError("severity is unknown exactly when no policy decided it")
        if self.last_seen_at < self.first_seen_at:
            raise ValueError("last seen is not before first seen")
        if self.recurrence_of == self.id:
            raise ValueError("a finding is not its own recurrence")
        return self

    @model_validator(mode="after")
    def _chain_matches_the_endpoint(self) -> UnknownDeviceFinding:
        if tuple(s.slot for s in self.chain) != SLOT_ORDER:
            raise ValueError("the chain is ip, mac, attachment, port, vlan")
        ip_slot, mac_slot = self.chain[0], self.chain[1]
        if ip_slot.value != self.endpoint.ip or mac_slot.value != self.endpoint.mac:
            raise ValueError("the chain starts from the endpoint that was seen")
        return self


class UnknownDeviceStateCount(ApiModel):
    state: FindingState
    count: Count


class UnknownDeviceSeverityCount(ApiModel):
    severity: Severity
    count: Count


class UnknownDeviceCounts(ApiModel):
    open: Count
    by_state: list[UnknownDeviceStateCount] = Field(max_length=5)
    by_severity: list[UnknownDeviceSeverityCount] = Field(max_length=5)

    @model_validator(mode="after")
    def _counts_agree(self) -> UnknownDeviceCounts:
        states = [row.state for row in self.by_state]
        severities = [row.severity for row in self.by_severity]
        if len(set(states)) != len(states) or len(set(severities)) != len(severities):
            raise ValueError("each state and severity is counted once")
        total = sum(row.count for row in self.by_state)
        if total != sum(row.count for row in self.by_severity):
            raise ValueError("state counts and severity counts cover the same findings")
        if self.open != sum(row.count for row in self.by_state if row.state in OPEN_STATES):
            raise ValueError("open counts new, acknowledged and investigating")
        return self


class UnknownDeviceEvent(ApiModel):
    id: str = Field(min_length=57, max_length=57, pattern=EVENT_ID_PATTERN)
    finding_id: FindingId
    seq: int = Field(ge=1, le=MAX_COUNT)
    occurred_at: AwareDatetime
    actor_id: str = Field(min_length=1, max_length=255)
    kind: EventKind
    state_from: FindingState | None
    state_to: FindingState | None
    reason: str | None = Field(..., min_length=1, max_length=MAX_REASON)
    message: str | None = Field(..., min_length=1, max_length=MAX_COMMENT)
    subject_id: str | None = Field(..., min_length=1, max_length=128)

    @model_validator(mode="after")
    def _kind_decides_the_fields(self) -> UnknownDeviceEvent:
        changed = self.kind == "state-changed"
        if changed != (self.state_from is not None and self.state_to is not None):
            raise ValueError("only a state change carries both states")
        if not changed and (self.state_from is not None or self.state_to is not None):
            raise ValueError("only a state change carries states")
        if changed:
            assert self.state_from is not None and self.state_to is not None
            if self.state_to not in ALLOWED_TRANSITIONS[self.state_from]:
                raise ValueError("this transition is not part of the lifecycle")
            if self.state_to in FINAL_STATES and self.reason is None:
                raise ValueError("a resolution or dismissal carries its reason")
        if self.kind == "comment" and self.message is None:
            raise ValueError("a comment carries its text")
        return self


class _Page(ApiModel):
    state: BlockState
    generated_at: AwareDatetime


class UnknownDeviceListResponse(_Page):
    page: int = Field(ge=1, le=100_000)
    page_size: int = Field(ge=1, le=MAX_PAGE_SIZE)
    total: Count
    items: list[UnknownDeviceFinding] = Field(max_length=MAX_PAGE_SIZE)

    @model_validator(mode="after")
    def _rows_need_the_store(self) -> UnknownDeviceListResponse:
        if self.state != "ok":
            if self.items or self.total != 0:
                raise ValueError("without the store there are no rows")
            return self
        ids = [item.id for item in self.items]
        if len(ids) > self.page_size or len(ids) > self.total or len(set(ids)) != len(ids):
            raise ValueError("a page holds at most page_size distinct rows and at most the total")
        return self


class UnknownDeviceDetailResponse(_Page):
    item: UnknownDeviceFinding | None

    @model_validator(mode="after")
    def _item_only_when_ok(self) -> UnknownDeviceDetailResponse:
        if (self.state == "ok") != (self.item is not None):
            raise ValueError("only an ok answer carries the finding")
        return self


class UnknownDeviceSummaryResponse(_Page):
    counts: UnknownDeviceCounts | None

    @model_validator(mode="after")
    def _counts_only_when_ok(self) -> UnknownDeviceSummaryResponse:
        if (self.state == "ok") != (self.counts is not None):
            raise ValueError("only an ok answer carries counts")
        return self


class UnknownDeviceTimelineResponse(_Page):
    finding_id: FindingId
    events: list[UnknownDeviceEvent] = Field(max_length=MAX_TIMELINE_PAGE)
    after_seq: int = Field(ge=0, le=MAX_COUNT)
    next_after_seq: int | None = Field(..., ge=1, le=MAX_COUNT)

    @model_validator(mode="after")
    def _events_follow_the_cursor(self) -> UnknownDeviceTimelineResponse:
        if self.state != "ok":
            if self.events or self.next_after_seq is not None:
                raise ValueError("without the store there are no events")
            return self
        seqs = [event.seq for event in self.events]
        if any(event.finding_id != self.finding_id for event in self.events):
            raise ValueError("a timeline holds one finding's events")
        if seqs != sorted(set(seqs)) or (seqs and seqs[0] <= self.after_seq):
            raise ValueError("events are in order and after the cursor")
        if self.next_after_seq is not None and (not seqs or self.next_after_seq != seqs[-1]):
            raise ValueError("the next cursor is the last event read")
        return self


class UnknownDeviceScanResponse(_Page):
    sources: list[SourceStatus] = Field(max_length=3)
    created: Count
    refreshed: Count
    suppressed: Count
    unverified: Count
    truncated: StrictBool
    # Sources that answered, but with rows dropped as malformed: their absence from the result
    # proves nothing, so the comparison they feed was left unverified.
    incomplete_sources: list[SourceName] = Field(max_length=3)

    @model_validator(mode="after")
    def _a_scan_needs_netbox(self) -> UnknownDeviceScanResponse:
        check_unique_sources(self.sources, must_include="netbox")
        netbox = next(s for s in self.sources if s.source == "netbox")
        if (self.state == "ok") != (netbox.state == "ok"):
            raise ValueError("a scan is ok exactly when NetBox could be read")
        if len(set(self.incomplete_sources)) != len(self.incomplete_sources):
            raise ValueError("an incomplete source is listed once")
        if self.state != "ok" and (
            self.created
            or self.refreshed
            or self.suppressed
            or self.unverified
            or self.incomplete_sources
        ):
            raise ValueError("a scan that could not compare changed nothing")
        return self


EvidenceVersion = Annotated[int, Field(ge=1, le=MAX_COUNT, strict=True)]


class UnknownDeviceTransitionRequest(ApiModel):
    """Acknowledge or investigate: names the evidence version the person was looking at."""

    expected_evidence_version: EvidenceVersion


class UnknownDeviceAssignRequest(ApiModel):
    assignee_id: str | None = Field(..., min_length=1, max_length=MAX_ASSIGNEE)
    expected_evidence_version: EvidenceVersion


class UnknownDeviceCommentRequest(ApiModel):
    message: str = Field(min_length=1, max_length=MAX_COMMENT)

    @model_validator(mode="after")
    def _not_blank(self) -> UnknownDeviceCommentRequest:
        _nonblank(self.message)
        return self


class UnknownDeviceResolveRequest(ApiModel):
    outcome: OutcomeState
    reason: str = Field(min_length=1, max_length=MAX_REASON)
    expected_evidence_version: EvidenceVersion

    @model_validator(mode="after")
    def _not_blank(self) -> UnknownDeviceResolveRequest:
        _nonblank(self.reason)
        return self


def check_slots(slots: Sequence[UnknownDeviceLinkSlot]) -> None:
    """Raise unless the slots are the five hops in order (used by the storage layer on write)."""
    if tuple(s.slot for s in slots) != SLOT_ORDER:
        raise ValueError("the chain is ip, mac, attachment, port, vlan")
