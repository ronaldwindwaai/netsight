"""PostgreSQL implementation of the alert -> incident link store (see ``links``).

One short transaction per call, static SQL, bound parameters. ``claim`` is a single
compare-and-set statement (insert-if-absent or update-where-current), so concurrent claimers
serialise on the row and exactly one succeeds.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from netsight_api.storage import lifecycle
from netsight_api.storage.connection import Connection, PostgresSettings
from netsight_api.storage.errors import NotFoundError
from netsight_api.storage.lifecycle import Clock
from netsight_api.storage.links import LinkKind, check_link_args

_SELECT_LINK = "SELECT incident_id FROM alert_incident_links WHERE kind = %s AND dedup_key = %s"
_SELECT_INCIDENT = "SELECT 1 AS present FROM incidents WHERE id = %s"
_INSERT_LINK = (
    "INSERT INTO alert_incident_links (kind, dedup_key, incident_id, linked_at) "
    "VALUES (%s, %s, %s, %s) ON CONFLICT (kind, dedup_key) DO NOTHING"
)
_REPLACE_LINK = (
    "UPDATE alert_incident_links SET incident_id = %s, linked_at = %s, recovered_at = NULL "
    "WHERE kind = %s AND dedup_key = %s AND incident_id = %s"
)
_MARK_RECOVERED = (
    "UPDATE alert_incident_links SET recovered_at = %s "
    "WHERE kind = %s AND dedup_key = %s AND recovered_at IS NULL"
)
_SELECT_RECOVERED = (
    "SELECT recovered_at IS NOT NULL AS recovered FROM alert_incident_links "
    "WHERE kind = %s AND dedup_key = %s"
)


def claim_link(
    conn: Connection,
    now: datetime,
    kind: str,
    key: str,
    target: uuid.UUID,
    current: uuid.UUID | None,
) -> bool:
    """The compare-and-set in the caller's transaction (also used by ``open_linked``)."""
    if current is None:
        return conn.execute(_INSERT_LINK, (kind, key, target, now)).rowcount == 1
    return conn.execute(_REPLACE_LINK, (target, now, kind, key, current)).rowcount == 1


class PostgresAlertIncidentLinkRepository:
    def __init__(self, settings: PostgresSettings, *, clock: Clock = lifecycle.utc_now) -> None:
        self._settings = settings
        self._clock = clock

    def get(self, kind: LinkKind, key: str) -> str | None:
        check_link_args(kind, key)
        with self._settings.session() as conn:
            row = conn.execute(_SELECT_LINK, (kind, key)).fetchone()
        return None if row is None else lifecycle.format_id("incident", row["incident_id"])

    def claim(self, kind: LinkKind, key: str, *, incident_id: str, replacing: str | None) -> bool:
        check_link_args(kind, key, incident_id, replacing)
        target = lifecycle.parse_id("incident", incident_id)
        current = None if replacing is None else lifecycle.parse_id("incident", replacing)
        assert target is not None  # check_link_args validated the format
        with self._settings.session() as conn:
            if conn.execute(_SELECT_INCIDENT, (target,)).fetchone() is None:
                raise NotFoundError("incident not found")
            return claim_link(conn, self._clock(), kind, key, target, current)

    def mark_recovered(self, kind: LinkKind, key: str) -> bool:
        check_link_args(kind, key)
        with self._settings.session() as conn:
            return conn.execute(_MARK_RECOVERED, (self._clock(), kind, key)).rowcount == 1

    def is_recovered(self, kind: LinkKind, key: str) -> bool:
        check_link_args(kind, key)
        with self._settings.session() as conn:
            row = conn.execute(_SELECT_RECOVERED, (kind, key)).fetchone()
        return row is not None and bool(row["recovered"])
