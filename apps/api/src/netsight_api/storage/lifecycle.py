"""Pure domain rules shared by every repository implementation.

Keeping the state machine and lifecycle rules here (no I/O) means the in-memory
fake and the PostgreSQL store cannot disagree about what is legal; they only
differ in how the resulting objects are persisted.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from pydantic import BaseModel, TypeAdapter

from netsight_api.schemas import (
    AlertRule,
    AlertRuleDefinition,
    IdentityRef,
    Incident,
    IncidentResolution,
    IncidentResolutionInput,
    IncidentSeverity,
    IncidentState,
    IncidentTimelineEvent,
    MaintenanceWindow,
    MaintenanceWindowDefinition,
    TimelineEventKind,
)
from netsight_api.storage.errors import (
    IllegalTransitionError,
    InvalidOperationError,
    LimitExceededError,
    NotFoundError,
    ScopeViolationError,
    StorageConflictError,
)
from netsight_api.storage.repository import MAX_PAGE_SIZE, MAX_TIMELINE_PAGE_SIZE, NoteKind

Clock = Callable[[], datetime]
UuidFactory = Callable[[], uuid.UUID]

MAX_REASON_LENGTH = 1000
# Actor ids in this namespace are non-human principals (the alert evaluator is
# ``service:alert-evaluator``); human ids come from the identity provider or the seed tooling.
SERVICE_ACTOR_PREFIX = "service:"
MAX_EVIDENCE_IDS = 256

# Capacity caps on monitoring configuration (S6-3 security review H1/M5). Rules and windows are
# never deleted, so an unbounded creator could grow them without limit and, with windows, bury
# the legitimate ones. Enforced inside the store call (under a lock), read at call time.
MAX_RULES = 2000
MAX_LIVE_WINDOWS = 500  # scheduled (not cancelled) and not yet ended, in total
MAX_LIVE_WINDOWS_PER_SCOPE = 20  # the same, per (scope kind, scope reference)

# Each state advances to exactly one successor. Resolved/closed may be reopened
# (to "open") with an audited reason; nothing else moves backwards.
_FORWARD: dict[IncidentState, IncidentState] = {
    "open": "acknowledged",
    "acknowledged": "investigating",
    "investigating": "mitigated",
    "mitigated": "resolved",
    "resolved": "closed",
}
_REOPENABLE: frozenset[IncidentState] = frozenset({"resolved", "closed"})
_NOTE_KINDS: frozenset[str] = frozenset(
    {
        "alert-linked",
        "alert-unlinked",
        "comment",
        "diagnostic",
        "action-proposed",
        "action-approved",
        "action-executed",
    }
)
_IDENTITY = TypeAdapter(IdentityRef)


def utc_now() -> datetime:
    return datetime.now(UTC)


# --- ids and paging -------------------------------------------------------------


def format_id(prefix: str, value: uuid.UUID) -> str:
    return f"{prefix}-{value}"


def parse_id(prefix: str, value: str) -> uuid.UUID | None:
    """Return the UUID inside ``<prefix>-<uuid>``, or None for any other string."""
    head = f"{prefix}-"
    if not isinstance(value, str) or not value.startswith(head):
        return None
    try:
        parsed = uuid.UUID(value[len(head) :])
    except ValueError:
        return None
    return parsed if str(parsed) == value[len(head) :] else None


def check_page(limit: int, offset: int, *, maximum: int = MAX_PAGE_SIZE) -> None:
    if not 1 <= limit <= maximum:
        raise ValueError(f"limit must be between 1 and {maximum}")
    if offset < 0:
        raise ValueError("offset must not be negative")


def check_timeline_page(after_seq: int, limit: int) -> None:
    if after_seq < 0:
        raise ValueError("after_seq must not be negative")
    check_page(limit, 0, maximum=MAX_TIMELINE_PAGE_SIZE)


def check_identity(identity: str) -> str:
    _IDENTITY.validate_python(identity)
    return identity


def is_service_actor(actor_id: str) -> bool:
    """True for a non-human principal: the reserved ``service:`` namespace."""
    return actor_id.lower().startswith(SERVICE_ACTOR_PREFIX)


def require_human_actor(actor_id: str, what: str) -> None:
    """Judgements and configuration edits are human-only: a service principal is refused here, in
    the shared domain rules, so no store (memory or PostgreSQL) can be talked into them."""
    if is_service_actor(actor_id):
        raise ScopeViolationError(f"a service principal may not {what}")


def revalidate[M: BaseModel](model: M) -> M:
    """Re-run every contract invariant on a model derived via ``model_copy``."""
    return type(model).model_validate(model.model_dump())


# --- incidents -------------------------------------------------------------------


@dataclass(frozen=True)
class EventDraft:
    kind: TimelineEventKind
    state_from: IncidentState | None = None
    state_to: IncidentState | None = None
    reason: str | None = None
    message: str | None = None
    subject_id: str | None = None


@dataclass(frozen=True)
class TransitionPlan:
    incident: Incident
    events: tuple[EventDraft, ...]


def new_incident(
    *,
    incident_uuid: uuid.UUID,
    title: str,
    severity: IncidentSeverity,
    actor_id: str,
    evidence_ids: Sequence[str],
    now: datetime,
) -> Incident:
    check_identity(actor_id)
    return Incident(
        id=format_id("incident", incident_uuid),
        title=title,
        severity=severity,
        state="open",
        created_at=now,
        updated_at=now,
        assignee_id=None,
        evidence_ids=list(evidence_ids),
        resolution=None,
    )


def require_mutable(incident: Incident) -> None:
    """Closed incidents accept nothing but a reopen."""
    if incident.state == "closed":
        raise IllegalTransitionError("a closed incident can only be reopened")


def _clean_reason(reason: str | None, *, required: bool) -> str | None:
    if reason is None:
        if required:
            raise InvalidOperationError("reopening an incident requires a reason")
        return None
    cleaned = reason.strip()
    if not cleaned or len(cleaned) > MAX_REASON_LENGTH:
        raise InvalidOperationError(f"reason must be 1 to {MAX_REASON_LENGTH} non-blank characters")
    return cleaned


def plan_transition(
    incident: Incident,
    *,
    to_state: IncidentState,
    actor_id: str,
    reason: str | None,
    resolution: IncidentResolutionInput | None,
    now: datetime,
) -> TransitionPlan:
    """Validate one state change and return the new record plus timeline entries."""
    check_identity(actor_id)
    require_human_actor(actor_id, "acknowledge, advance, resolve or reopen an incident")
    is_reopen = to_state == "open" and incident.state in _REOPENABLE
    if _FORWARD.get(incident.state) != to_state and not is_reopen:
        raise IllegalTransitionError(f"cannot move an incident from {incident.state} to {to_state}")

    cleaned_reason = _clean_reason(reason, required=is_reopen)
    if to_state == "resolved":
        if resolution is None:
            raise InvalidOperationError("resolving an incident requires a resolution")
    elif resolution is not None:
        raise InvalidOperationError("a resolution is only accepted when resolving")

    events = [
        EventDraft(
            kind="state-changed",
            state_from=incident.state,
            state_to=to_state,
            reason=cleaned_reason,
        )
    ]
    record = incident.resolution
    if is_reopen:
        record = None
    elif resolution is not None:
        record = IncidentResolution(
            **resolution.model_dump(), resolved_at=now, resolved_by=actor_id
        )
        events.append(EventDraft(kind="resolution", message=record.summary))
    updated = revalidate(
        incident.model_copy(update={"state": to_state, "resolution": record, "updated_at": now})
    )
    return TransitionPlan(updated, tuple(events))


def plan_assignee(
    incident: Incident, *, assignee_id: str | None, actor_id: str, now: datetime
) -> TransitionPlan:
    check_identity(actor_id)
    require_human_actor(actor_id, "assign an incident")
    require_mutable(incident)
    updated = revalidate(
        incident.model_copy(update={"assignee_id": assignee_id, "updated_at": now})
    )
    return TransitionPlan(updated, (EventDraft(kind="assignee-changed", subject_id=assignee_id),))


def plan_evidence(
    incident: Incident, *, evidence_id: str, actor_id: str, now: datetime
) -> TransitionPlan:
    """Idempotent: re-adding existing evidence changes nothing and records nothing."""
    check_identity(actor_id)
    require_human_actor(actor_id, "attach evidence to an incident")
    require_mutable(incident)
    if evidence_id in incident.evidence_ids:
        return TransitionPlan(incident, ())
    if len(incident.evidence_ids) >= MAX_EVIDENCE_IDS:
        raise InvalidOperationError(f"an incident holds at most {MAX_EVIDENCE_IDS} evidence ids")
    updated = revalidate(
        incident.model_copy(
            update={"evidence_ids": [*incident.evidence_ids, evidence_id], "updated_at": now}
        )
    )
    return TransitionPlan(updated, (EventDraft(kind="evidence-added", subject_id=evidence_id),))


def plan_note(
    incident: Incident,
    *,
    kind: NoteKind,
    actor_id: str,
    message: str | None,
    subject_id: str | None,
) -> EventDraft:
    check_identity(actor_id)
    if kind not in _NOTE_KINDS:
        raise InvalidOperationError(f"{kind} events are written by dedicated operations only")
    require_mutable(incident)
    return EventDraft(kind=kind, message=message, subject_id=subject_id)


def materialise_event(
    draft: EventDraft,
    *,
    event_uuid: uuid.UUID,
    incident_id: str,
    seq: int,
    actor_id: str,
    now: datetime,
) -> IncidentTimelineEvent:
    """Build (and thereby validate against the contract) one timeline entry."""
    return IncidentTimelineEvent(
        id=format_id("incident-event", event_uuid),
        incident_id=incident_id,
        seq=seq,
        occurred_at=now,
        actor_id=actor_id,
        kind=draft.kind,
        state_from=draft.state_from,
        state_to=draft.state_to,
        reason=draft.reason,
        message=draft.message,
        subject_id=draft.subject_id,
    )


# --- alert rules and maintenance windows -------------------------------------------


def new_rule(
    definition: AlertRuleDefinition, *, rule_uuid: uuid.UUID, actor_id: str, now: datetime
) -> AlertRule:
    """Rules are always created as unapproved drafts, never active."""
    check_identity(actor_id)
    require_human_actor(actor_id, "create an alert rule")
    return AlertRule(
        **definition.model_dump(),
        id=format_id("alert-rule", rule_uuid),
        status="draft",
        created_by=actor_id,
        created_at=now,
        updated_at=now,
        approved_by=None,
        approved_at=None,
        version=1,
    )


def require_version(rule: AlertRule, expected_version: int) -> None:
    """Optimistic concurrency: the caller must have seen the version it acts on."""
    if rule.version != expected_version:
        raise StorageConflictError("the alert rule was changed by someone else")


def edited_rule(
    rule: AlertRule, definition: AlertRuleDefinition, *, actor_id: str, now: datetime
) -> AlertRule:
    """Editing resets to an unapproved draft so a changed rule is never silently live.

    ``actor_id`` is validated but not stored (the rule record has no editor column):
    the route layer writes the audit event and cannot call this without naming one.
    """
    check_identity(actor_id)
    require_human_actor(actor_id, "edit an alert rule")
    if rule.status == "active":
        raise IllegalTransitionError("disable an active rule before editing it")
    return AlertRule(
        **definition.model_dump(),
        id=rule.id,
        status="draft",
        created_by=rule.created_by,
        created_at=rule.created_at,
        updated_at=now,
        approved_by=None,
        approved_at=None,
        version=rule.version + 1,
    )


def approved_rule(
    rule: AlertRule, *, approver_id: str, expected_version: int, now: datetime
) -> AlertRule:
    """Activate exactly the version the approver reviewed (never a later edit)."""
    check_identity(approver_id)
    require_human_actor(approver_id, "approve an alert rule")
    require_version(rule, expected_version)
    if rule.status == "active":
        raise IllegalTransitionError("the rule is already active")
    return revalidate(
        rule.model_copy(
            update={
                "status": "active",
                "approved_by": approver_id,
                "approved_at": now,
                "updated_at": now,
                "version": rule.version + 1,
            }
        )
    )


def disabled_rule(rule: AlertRule, *, actor_id: str, now: datetime) -> AlertRule:
    """Disable an active rule; ``actor_id`` is validated for the caller's audit event."""
    check_identity(actor_id)
    require_human_actor(actor_id, "disable an alert rule")
    if rule.status != "active":
        raise IllegalTransitionError("only an active rule can be disabled")
    return revalidate(
        rule.model_copy(
            update={"status": "disabled", "updated_at": now, "version": rule.version + 1}
        )
    )


def new_window(
    definition: MaintenanceWindowDefinition,
    *,
    window_uuid: uuid.UUID,
    actor_id: str,
    now: datetime,
) -> MaintenanceWindow:
    check_identity(actor_id)
    require_human_actor(actor_id, "create a maintenance window")  # a window silences alerts
    return MaintenanceWindow(
        **definition.model_dump(),
        id=format_id("maintenance", window_uuid),
        status="scheduled",
        created_by=actor_id,
        created_at=now,
        cancelled_by=None,
        cancelled_at=None,
    )


def check_rule_capacity(rule_count: int) -> None:
    if rule_count >= MAX_RULES:
        raise LimitExceededError("the alert-rule limit is reached")


def check_window_capacity(*, live_total: int, live_in_scope: int) -> None:
    """``live_*`` count scheduled windows that have not ended, before the new one is added."""
    if live_total >= MAX_LIVE_WINDOWS or live_in_scope >= MAX_LIVE_WINDOWS_PER_SCOPE:
        raise LimitExceededError("the maintenance-window limit is reached")


def window_is_live(window: MaintenanceWindow, now: datetime) -> bool:
    return window.status == "scheduled" and window.ends_at > now


def require_window_scope(window: MaintenanceWindow, *, organisation_allowed: bool) -> None:
    """Organisation-wide windows may only be cancelled with the organisation permission.

    Judged on the locked row, before the state rule, like the incident assignee scope.
    """
    if window.scope.kind == "organisation" and not organisation_allowed:
        raise ScopeViolationError("the window has organisation scope")


def require_window_creation_scope(
    definition: MaintenanceWindowDefinition, *, organisation_allowed: bool
) -> None:
    """Defence in depth for window creation, judged on the immutable definition.

    The route already refuses with a specific audit reason; this closes the gap for any
    future call path (scheduler, CLI, refactor) that reaches the repository directly.
    Unlike the cancel path (``require_window_scope``), this reads only the caller-supplied
    definition, which cannot change under us, so no row lock is needed: the in-memory store
    calls it under its lock, PostgreSQL checks it before opening the transaction, and both
    agree because the check is deterministic.
    An organisation-scope window silences everything and ``disable`` evaluation stops rules
    from running entirely, so both need ``organisation_allowed`` whatever the scope kind.
    """
    if organisation_allowed:
        return
    if definition.scope.kind == "organisation":
        raise ScopeViolationError("the window has organisation scope")
    if definition.evaluation == "disable":
        raise ScopeViolationError("the window disables evaluation")


def cancelled_window(
    window: MaintenanceWindow, *, actor_id: str, now: datetime
) -> MaintenanceWindow:
    check_identity(actor_id)
    require_human_actor(actor_id, "cancel a maintenance window")
    if window.status == "cancelled":
        raise IllegalTransitionError("the maintenance window is already cancelled")
    return revalidate(
        window.model_copy(
            update={"status": "cancelled", "cancelled_by": actor_id, "cancelled_at": now}
        )
    )


def check_active_at(active_at: datetime | None) -> None:
    if active_at is not None and active_at.tzinfo is None:
        raise ValueError("active_at must be timezone-aware")


def window_matches(
    window: MaintenanceWindow, *, active_at: datetime | None, include_cancelled: bool
) -> bool:
    if window.status == "cancelled" and not include_cancelled:
        return False
    if active_at is None:
        return True
    return window.status == "scheduled" and window.starts_at <= active_at < window.ends_at


def require_assignee(incident: Incident, required_assignee: str | None) -> None:
    """Assigned-incidents-only scope, judged on the locked row and before any state rule.

    ``None`` means the caller has full access. Judged first so a caller outside the scope
    learns nothing about the incident (not even that a transition would be illegal).
    """
    if required_assignee is not None and incident.assignee_id != required_assignee:
        raise ScopeViolationError("the incident is not assigned to the caller")


def require_found[M: BaseModel](value: M | None, what: str) -> M:
    if value is None:
        raise NotFoundError(f"{what} not found")
    return value
