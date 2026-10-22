"""PostgreSQL implementation of ``AlertIncidentStore`` (see ``alert_incidents``).

One transaction: the incident row, its ``alert-linked`` timeline event and the link claim(s) are
committed together or not at all. A lost primary claim (``INSERT ... ON CONFLICT DO NOTHING`` that
inserted nothing, or an ``UPDATE`` whose ``WHERE`` no longer matched) rolls the transaction back,
so a racing evaluator leaves no orphan incident. Concurrent callers for one key serialise on the
link's unique index: the second waits for the first to commit, then loses its claim cleanly.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from netsight_api.schemas import IncidentSeverity
from netsight_api.storage import lifecycle
from netsight_api.storage.alert_incidents import LinkClaim, OpenedIncident, check_claim
from netsight_api.storage.connection import Connection, PostgresSettings
from netsight_api.storage.lifecycle import Clock, UuidFactory
from netsight_api.storage.postgres import insert_event_row, insert_incident_row
from netsight_api.storage.postgres_links import claim_link


class PostgresAlertIncidentStore:
    def __init__(
        self,
        settings: PostgresSettings,
        *,
        clock: Clock = lifecycle.utc_now,
        new_uuid: UuidFactory = uuid.uuid4,
    ) -> None:
        self._settings = settings
        self._clock = clock
        self._new_uuid = new_uuid

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
        incident_uuid, event_uuid, now = self._new_uuid(), self._new_uuid(), self._clock()
        incident = lifecycle.new_incident(
            incident_uuid=incident_uuid,
            title=title,
            severity=severity,
            actor_id=actor_id,
            evidence_ids=(),
            now=now,
        )
        event = lifecycle.materialise_event(  # validated before anything is written
            lifecycle.EventDraft(kind="alert-linked", message=note, subject_id=note_subject),
            event_uuid=event_uuid,
            incident_id=incident.id,
            seq=1,
            actor_id=actor_id,
            now=now,
        )
        with self._settings.session() as conn:
            insert_incident_row(conn, incident_uuid, incident)
            insert_event_row(conn, event_uuid, incident_uuid, event)
            claimed = self._claims(conn, now, incident_uuid, primary, secondary)
            if claimed is None:
                conn.rollback()  # the primary claim lost: the incident never existed
                return None
        return OpenedIncident(incident, secondary_claimed=claimed)

    @staticmethod
    def _claims(
        conn: Connection,
        now: datetime,
        incident_uuid: uuid.UUID,
        primary: LinkClaim,
        secondary: LinkClaim | None,
    ) -> bool | None:
        """None when the primary claim lost; else whether the secondary (if any) won."""
        if not _claim(conn, now, incident_uuid, primary):
            return None
        return secondary is None or _claim(conn, now, incident_uuid, secondary)


def _claim(conn: Connection, now: datetime, incident_uuid: uuid.UUID, claim: LinkClaim) -> bool:
    current = None if claim.replacing is None else lifecycle.parse_id("incident", claim.replacing)
    return claim_link(conn, now, claim.kind, claim.key, incident_uuid, current)
