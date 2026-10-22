"""Open an incident for an alert in one transaction: incident, link claim and timeline note.

The alert evaluator must never leave an incident nobody links to (the next cycle would not find
it and would open another). ``AlertIncidentStore.open_linked`` therefore creates the incident,
appends its ``alert-linked`` note and claims the alert/group link as one atomic step: when the
primary claim loses (another writer linked the key first) or anything fails, nothing was written.

Both implementations (this in-memory one and ``postgres_alert_incidents``) pass the same
conformance suite (``tests/test_storage_evaluation_conformance.py``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from netsight_api.schemas import Incident, IncidentSeverity
from netsight_api.storage.links import (
    InMemoryAlertIncidentLinkRepository,
    LinkKind,
    check_link_args,
)
from netsight_api.storage.memory import InMemoryIncidentRepository


@dataclass(frozen=True)
class LinkClaim:
    """One compare-and-set on ``alert_incident_links``: ``key`` must currently point at
    ``replacing`` (None: at nothing)."""

    kind: LinkKind
    key: str
    replacing: str | None = None


@dataclass(frozen=True)
class OpenedIncident:
    """The committed incident; ``secondary_claimed`` is False when the secondary claim lost."""

    incident: Incident
    secondary_claimed: bool = True


class AlertIncidentStore(Protocol):
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
        """Create an incident, append an ``alert-linked`` note (``note``, ``note_subject``) and
        claim ``primary`` for it, atomically.

        Returns None, having written nothing, when the ``primary`` claim loses. A lost
        ``secondary`` claim does not undo anything and is reported on the result. Any error
        (validation, store failure) also leaves nothing behind. ``ValueError`` for malformed
        arguments, before anything is written."""
        ...


def check_claim(claim: LinkClaim) -> None:
    """``ValueError`` for a malformed kind, key or expected incident id (nothing is written)."""
    check_link_args(claim.kind, claim.key, claim.replacing, claim.replacing)


class InMemoryAlertIncidentStore:
    """Unit-test implementation over the in-memory incident and link stores."""

    def __init__(
        self, incidents: InMemoryIncidentRepository, links: InMemoryAlertIncidentLinkRepository
    ) -> None:
        self._incidents = incidents
        self._links = links

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
        for claim in (primary, secondary):
            if claim is not None:
                check_claim(claim)
        with self._incidents._atomic(), self._links._atomic() as undo_links:
            incident = self._incidents.create_incident(
                title=title, severity=severity, actor_id=actor_id
            )
            opened: OpenedIncident | None = None
            try:
                opened = self._write(incident, actor_id, primary, secondary, note, note_subject)
            finally:
                if opened is None:  # a lost claim or any error: as if it never happened
                    self._incidents._discard(incident.id)
                    undo_links(incident.id)
            return opened

    def _write(
        self,
        incident: Incident,
        actor_id: str,
        primary: LinkClaim,
        secondary: LinkClaim | None,
        note: str,
        note_subject: str,
    ) -> OpenedIncident | None:
        self._incidents.append_event(
            incident.id,
            kind="alert-linked",
            actor_id=actor_id,
            message=note,
            subject_id=note_subject,
        )
        if not self._claim(primary, incident.id):
            return None
        won = secondary is None or self._claim(secondary, incident.id)
        return OpenedIncident(incident, secondary_claimed=won)

    def _claim(self, claim: LinkClaim, incident_id: str) -> bool:
        return self._links.claim(
            claim.kind, claim.key, incident_id=incident_id, replacing=claim.replacing
        )
