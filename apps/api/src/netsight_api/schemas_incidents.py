"""Incident API envelopes and request bodies (S6-2) and management's summary projection.

Split out of ``schemas.py`` (which holds the entity models these wrap) to keep both files
cohesive; behaviour is unchanged. Import these names from here, not from ``schemas``.
"""

from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, Field, model_validator

from netsight_api.schemas import (
    INCIDENT_ID_PATTERN,
    NON_BLANK,
    ApiModel,
    ContractModel,
    EvidenceRef,
    FollowUpAction,
    Incident,
    IncidentResolutionInput,
    IncidentSeverity,
    IncidentState,
    IncidentTimelineEvent,
    RootCauseStatus,
    StoreState,
)

# --- Incident routes (S6-2): response envelopes and request bodies --------------------
#
# Mirrors contracts/json-schema/incident-api.schema.json. Responses are strict contract
# models built by the server; request bodies are lax API models (FastAPI validates JSON
# bodies in python mode, where strict datetime parsing would reject ISO strings) that
# are re-validated against the strict contract models before they reach the store.

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


class IncidentSummary(ContractModel):
    """Management's reduced view of an incident (``incidents:read-summary``).

    Deliberately omits evidence ids, the whole resolution record (free text and the
    resolver's identity) and the assignee identity: only whether somebody is assigned and
    when the incident was resolved. ``title`` is the headline operators and alert rules set.
    """

    id: str = Field(min_length=45, max_length=45, pattern=INCIDENT_ID_PATTERN)
    title: str = Field(min_length=1, max_length=255, pattern=NON_BLANK)
    severity: IncidentSeverity
    state: IncidentState
    created_at: AwareDatetime
    updated_at: AwareDatetime
    assigned: bool
    resolved_at: AwareDatetime | None = Field(...)

    @model_validator(mode="after")
    def _resolved_at_matches_state(self) -> IncidentSummary:
        if (self.state in ("resolved", "closed")) != (self.resolved_at is not None):
            raise ValueError("resolved_at is required exactly when state is resolved or closed")
        return self

    @classmethod
    def from_incident(cls, incident: Incident) -> IncidentSummary:
        resolution = incident.resolution
        return cls(
            id=incident.id,
            title=incident.title,
            severity=incident.severity,
            state=incident.state,
            created_at=incident.created_at,
            updated_at=incident.updated_at,
            assigned=incident.assignee_id is not None,
            resolved_at=None if resolution is None else resolution.resolved_at,
        )


class IncidentSummaryListResponse(ContractModel):
    state: StoreState
    incidents: list[IncidentSummary] = Field(max_length=MAX_INCIDENT_PAGE_SIZE)
    limit: int = Field(ge=1, le=MAX_INCIDENT_PAGE_SIZE)
    offset: int = Field(ge=0, le=MAX_INCIDENT_LIST_OFFSET)
    next_offset: int | None = Field(..., ge=1, le=MAX_INCIDENT_LIST_OFFSET)

    @model_validator(mode="after")
    def _non_ok_carries_no_rows(self) -> IncidentSummaryListResponse:
        if self.state != "ok" and (self.incidents or self.next_offset is not None):
            raise ValueError("non-ok incident state must not carry incidents or a cursor")
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
