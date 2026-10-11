"""Unknown-device finding store (Step 8c): the Protocol, the shared rules and the in-memory store.

Findings are Netsight application state (DATABASE-OWNERSHIP): what telemetry saw that NetBox does
not know, with the evidence chain captured at detection, and the lifecycle people move it through
(new, acknowledged, investigating, resolved, false-positive). NetBox is never written to.

* ``observe`` is the scanner's write: it creates a finding, refreshes an open one, or is suppressed
  by an earlier false-positive. A quiet endpoint seen again costs a counter and a time; a change in
  what is known about it (a hop observed, the severity moved) is an ``evidence-updated`` event.
  After a resolution a new sighting is a *new* finding that points at the old one.
* The lifecycle is the fixed table in ``schemas_unknown_devices.ALLOWED_TRANSITIONS``. The state
  machine is the optimistic-concurrency check: a transition is applied under a row lock only from a
  state it is legal from, so the loser of a race gets ``IllegalTransitionError`` (HTTP 409).
* The timeline is append-only. Free text (reasons, comments) is stored and returned verbatim as data.
* Reads are bounded: a page is capped and so is a timeline page.

The shared pure rules live here so the in-memory fake and the PostgreSQL store cannot disagree.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Literal, Protocol

from netsight_api.schemas_unknown_devices import (
    ALLOWED_TRANSITIONS,
    FINAL_STATES,
    MAX_COMMENT,
    MAX_PAGE_SIZE,
    MAX_REASON,
    MAX_TIMELINE_PAGE,
    OPEN_STATES,
    SYSTEM_ACTOR,
    FindingState,
    Severity,
    UnknownDeviceCounts,
    UnknownDeviceEvent,
    UnknownDeviceFinding,
    UnknownDeviceSeverityCount,
    UnknownDeviceStateCount,
)
from netsight_api.storage import lifecycle
from netsight_api.storage.errors import IllegalTransitionError, InvalidOperationError, NotFoundError
from netsight_api.unknown_devices.model import Detection, finding_fingerprint

FINDING_PREFIX: Final = "unknown-device"
EVENT_PREFIX: Final = "unknown-device-event"
MAX_ASSIGNEE: Final = 255
_STATE_ORDER: Final[tuple[FindingState, ...]] = (
    "new",
    "acknowledged",
    "investigating",
    "resolved",
    "false-positive",
)
_SEVERITY_ORDER: Final[tuple[Severity, ...]] = ("low", "medium", "high", "critical", "unknown")


@dataclass(frozen=True)
class Observation:
    """What an observation did: made a finding, refreshed an open one, or was suppressed."""

    outcome: Literal["created", "refreshed", "suppressed"]
    finding_id: str


class UnknownDeviceRepository(Protocol):
    def observe(self, detection: Detection) -> Observation: ...

    def get_finding(self, finding_id: str) -> UnknownDeviceFinding | None: ...

    def list_findings(
        self,
        *,
        states: Sequence[FindingState] | None = None,
        severity: Severity | None = None,
        assigned: bool | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> tuple[list[UnknownDeviceFinding], int]:
        """Newest sighting first; the total is the number of matches, not of this page."""
        ...

    def counts(self) -> UnknownDeviceCounts: ...

    def list_timeline(
        self, finding_id: str, *, after_seq: int = 0, limit: int = 200
    ) -> list[UnknownDeviceEvent]: ...

    def transition_state(
        self,
        finding_id: str,
        *,
        to_state: FindingState,
        actor_id: str,
        reason: str | None = None,
    ) -> UnknownDeviceFinding: ...

    def set_assignee(
        self, finding_id: str, *, assignee_id: str | None, actor_id: str
    ) -> UnknownDeviceFinding: ...

    def add_comment(
        self, finding_id: str, *, actor_id: str, message: str
    ) -> UnknownDeviceEvent: ...


# --- shared rules ------------------------------------------------------------------------------------


def check_list_args(limit: int, offset: int) -> None:
    lifecycle.check_page(limit, offset, maximum=MAX_PAGE_SIZE)


def check_timeline_args(after_seq: int, limit: int) -> None:
    if after_seq < 0:
        raise ValueError("after_seq must not be negative")
    lifecycle.check_page(limit, 0, maximum=MAX_TIMELINE_PAGE)


def check_actor(actor_id: str) -> str:
    if (
        not isinstance(actor_id, str)
        or not 1 <= len(actor_id) <= MAX_ASSIGNEE
        or not actor_id.strip()
    ):
        raise InvalidOperationError(f"an actor is 1 to {MAX_ASSIGNEE} characters")
    return actor_id


def clean_assignee(assignee_id: str | None) -> str | None:
    if assignee_id is None:
        return None
    if (
        not isinstance(assignee_id, str)
        or not assignee_id.strip()
        or len(assignee_id) > MAX_ASSIGNEE
    ):
        raise InvalidOperationError(f"an assignee is 1 to {MAX_ASSIGNEE} non-blank characters")
    return assignee_id


def clean_comment(message: str) -> str:
    if not isinstance(message, str) or not message.strip() or len(message) > MAX_COMMENT:
        raise InvalidOperationError(f"a comment is 1 to {MAX_COMMENT} non-blank characters")
    return message


def plan_transition(
    current: FindingState, to_state: FindingState, reason: str | None
) -> str | None:
    """Validate one state change; returns the cleaned reason (``None`` when none was needed)."""
    if to_state not in ALLOWED_TRANSITIONS[current]:
        raise IllegalTransitionError(f"cannot move a finding from {current} to {to_state}")
    needs_reason = to_state in FINAL_STATES
    if reason is None:
        if needs_reason:
            raise InvalidOperationError("resolving or dismissing a finding requires a reason")
        return None
    if not isinstance(reason, str) or not reason.strip() or len(reason) > MAX_REASON:
        raise InvalidOperationError(f"a reason is 1 to {MAX_REASON} non-blank characters")
    return reason


def is_open(state: FindingState) -> bool:
    return state in OPEN_STATES


def build_counts(
    states: Sequence[FindingState], severities: Sequence[Severity]
) -> UnknownDeviceCounts:
    return UnknownDeviceCounts(
        open=sum(1 for s in states if is_open(s)),
        by_state=[
            UnknownDeviceStateCount(state=s, count=states.count(s))
            for s in _STATE_ORDER
            if s in states
        ],
        by_severity=[
            UnknownDeviceSeverityCount(severity=s, count=severities.count(s))
            for s in _SEVERITY_ORDER
            if s in severities
        ],
    )


# --- in-memory store ---------------------------------------------------------------------------------


class InMemoryUnknownDeviceRepository:
    """Unit-test implementation applying the same rules as the PostgreSQL store."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] = lifecycle.utc_now,
        new_uuid: Callable[[], uuid.UUID] = uuid.uuid4,
    ) -> None:
        self._clock = clock
        self._new_uuid = new_uuid
        self._lock = threading.RLock()
        self._findings: dict[str, UnknownDeviceFinding] = {}
        self._subject: dict[str, str] = {}  # finding id -> subject key
        self._order: list[str] = []  # creation order
        self._events: dict[str, list[UnknownDeviceEvent]] = {}

    # -- internals --

    def _event(
        self, finding_id: str, kind: str, actor_id: str, now: datetime, **fields: object
    ) -> UnknownDeviceEvent:
        events = self._events[finding_id]
        event = UnknownDeviceEvent.model_validate(
            {
                "id": lifecycle.format_id(EVENT_PREFIX, self._new_uuid()),
                "finding_id": finding_id,
                "seq": len(events) + 1,
                "occurred_at": now,
                "actor_id": actor_id,
                "kind": kind,
                "state_from": None,
                "state_to": None,
                "reason": None,
                "message": None,
                "subject_id": None,
                **fields,
            }
        )
        events.append(event)
        return event

    def _locked(self, finding_id: str) -> UnknownDeviceFinding:
        found = (
            self._findings.get(finding_id)
            if lifecycle.parse_id(FINDING_PREFIX, finding_id)
            else None
        )
        if found is None:
            raise NotFoundError("finding not found")
        return found

    def _subject_findings(self, subject_key: str) -> list[UnknownDeviceFinding]:
        return [self._findings[i] for i in self._order if self._subject[i] == subject_key]

    # -- scanner write --

    def observe(self, detection: Detection) -> Observation:
        with self._lock:
            now = self._clock()
            history = self._subject_findings(detection.subject_key)
            open_ones = [f for f in history if is_open(f.state)]
            if open_ones:
                return self._refresh(open_ones[-1], detection, now)
            latest = history[-1] if history else None
            if latest is not None and latest.state == "false-positive":
                return Observation("suppressed", latest.id)
            recurrence = latest.id if latest is not None and latest.state == "resolved" else None
            finding_id = lifecycle.format_id(FINDING_PREFIX, self._new_uuid())
            finding = detection.as_finding(finding_id, now, recurrence_of=recurrence)
            self._findings[finding_id] = finding
            self._subject[finding_id] = detection.subject_key
            self._order.append(finding_id)
            self._events[finding_id] = []
            self._event(finding_id, "detected", SYSTEM_ACTOR, now)
            if finding.proposed_action is not None:
                self._event(finding_id, "action-proposed", SYSTEM_ACTOR, now)
            return Observation("created", finding_id)

    def _refresh(
        self, current: UnknownDeviceFinding, detection: Detection, now: datetime
    ) -> Observation:
        changed = finding_fingerprint(current) != detection.fingerprint()
        values: dict[str, object] = {
            "last_seen_at": now,
            "seen_count": current.seen_count + 1,
            "comparison": detection.comparison,
        }
        if changed:
            values.update(
                severity=detection.severity,
                severity_basis=detection.severity_basis,
                endpoint=detection.endpoint,
                chain=list(detection.chain),
                proposed_action=detection.proposed_action,
            )
        refreshed = UnknownDeviceFinding.model_validate({**current.model_dump(), **values})
        self._findings[current.id] = refreshed
        if changed:
            self._event(current.id, "evidence-updated", SYSTEM_ACTOR, now)
            if current.proposed_action is None and detection.proposed_action is not None:
                self._event(current.id, "action-proposed", SYSTEM_ACTOR, now)
        return Observation("refreshed", current.id)

    # -- reads --

    def get_finding(self, finding_id: str) -> UnknownDeviceFinding | None:
        with self._lock:
            found = self._findings.get(finding_id)
            return found.model_copy(deep=True) if found is not None else None

    def list_findings(
        self,
        *,
        states: Sequence[FindingState] | None = None,
        severity: Severity | None = None,
        assigned: bool | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> tuple[list[UnknownDeviceFinding], int]:
        check_list_args(limit, offset)
        with self._lock:
            rows = [
                f
                for f in self._findings.values()
                if (states is None or f.state in states)
                and (severity is None or f.severity == severity)
                and (assigned is None or (f.assignee_id is not None) == assigned)
            ]
        rows.sort(key=lambda f: (f.last_seen_at, f.id), reverse=True)
        return [f.model_copy(deep=True) for f in rows[offset : offset + limit]], len(rows)

    def counts(self) -> UnknownDeviceCounts:
        with self._lock:
            findings = list(self._findings.values())
        return build_counts([f.state for f in findings], [f.severity for f in findings])

    def list_timeline(
        self, finding_id: str, *, after_seq: int = 0, limit: int = 200
    ) -> list[UnknownDeviceEvent]:
        check_timeline_args(after_seq, limit)
        with self._lock:
            self._locked(finding_id)
            events = [e for e in self._events[finding_id] if e.seq > after_seq]
            return [e.model_copy(deep=True) for e in events[:limit]]

    # -- people's writes --

    def transition_state(
        self,
        finding_id: str,
        *,
        to_state: FindingState,
        actor_id: str,
        reason: str | None = None,
    ) -> UnknownDeviceFinding:
        check_actor(actor_id)
        with self._lock:
            current = self._locked(finding_id)
            cleaned = plan_transition(current.state, to_state, reason)
            updated = current.model_copy(update={"state": to_state})
            self._findings[finding_id] = updated
            self._event(
                finding_id,
                "state-changed",
                actor_id,
                self._clock(),
                state_from=current.state,
                state_to=to_state,
                reason=cleaned,
            )
            return updated.model_copy(deep=True)

    def set_assignee(
        self, finding_id: str, *, assignee_id: str | None, actor_id: str
    ) -> UnknownDeviceFinding:
        check_actor(actor_id)
        assignee = clean_assignee(assignee_id)
        with self._lock:
            current = self._locked(finding_id)
            if current.state in FINAL_STATES:
                raise IllegalTransitionError("a finished finding cannot be reassigned")
            if current.assignee_id == assignee:
                return current.model_copy(deep=True)
            updated = current.model_copy(update={"assignee_id": assignee})
            self._findings[finding_id] = updated
            self._event(
                finding_id,
                "assignee-changed",
                actor_id,
                self._clock(),
                subject_id=assignee if assignee is not None else None,
            )
            return updated.model_copy(deep=True)

    def add_comment(self, finding_id: str, *, actor_id: str, message: str) -> UnknownDeviceEvent:
        check_actor(actor_id)
        text = clean_comment(message)
        with self._lock:
            self._locked(finding_id)
            event = self._event(finding_id, "comment", actor_id, self._clock(), message=text)
            return event.model_copy(deep=True)
