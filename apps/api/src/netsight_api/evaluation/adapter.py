"""The alert evaluator's runtime view of the incident store: three operations, nothing else.

The evaluator opens an incident (together with its link and first timeline note, in one
transaction), appends a timeline note and reads an incident back. It is deliberately *not* handed
the incident repository: an adapter with no method to acknowledge, assign, resolve, reopen or edit
does not reach those operations through its interface, and the storage layer independently refuses
the service principal for them (``lifecycle.require_human_actor``: incident transitions, assignment,
evidence, and rule/window creation, edit, approval, disable and cancel), so a mistake in either
place is caught by the other. Timeline notes are limited at runtime to ``alert-linked`` and
``comment``.

Follow-up (not done): a separate database role for the evaluator whose grants cover only these
operations, so the database enforces it too.
"""

from __future__ import annotations

from typing import Final, Literal

from netsight_api.schemas import Incident, IncidentSeverity, IncidentTimelineEvent
from netsight_api.storage import (
    AlertIncidentStore,
    IncidentRepository,
    InvalidOperationError,
    LinkClaim,
    OpenedIncident,
)

_NOTE_KINDS: Final = frozenset({"alert-linked", "comment"})


class EvaluatorIncidentAdapter:
    def __init__(self, incidents: IncidentRepository, opener: AlertIncidentStore) -> None:
        self.__incidents = incidents
        self.__opener = opener

    def __repr__(self) -> str:
        return "EvaluatorIncidentAdapter()"

    def open_linked(
        self,
        *,
        title: str,
        severity: IncidentSeverity,
        actor_id: str,
        primary: LinkClaim,
        secondary: LinkClaim | None = None,
        note: str,
        note_subject: str,
    ) -> OpenedIncident | None:
        return self.__opener.open_linked(
            title=title,
            severity=severity,
            actor_id=actor_id,
            primary=primary,
            secondary=secondary,
            note=note,
            note_subject=note_subject,
        )

    def append_event(
        self,
        incident_id: str,
        *,
        kind: Literal["alert-linked", "comment"],
        actor_id: str,
        message: str | None = None,
        subject_id: str | None = None,
    ) -> IncidentTimelineEvent:
        if kind not in _NOTE_KINDS:  # the annotation is not enforced at runtime
            raise InvalidOperationError("the evaluator may only write alert-linked or comment notes")
        return self.__incidents.append_event(
            incident_id, kind=kind, actor_id=actor_id, message=message, subject_id=subject_id
        )

    def get_incident(self, incident_id: str) -> Incident | None:
        return self.__incidents.get_incident(incident_id)
