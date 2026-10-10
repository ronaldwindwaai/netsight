"""PostgreSQL implementation of the diagnostic session store (see ``diagnostics``).

One short transaction per call, static SQL, bound parameters. The session is stored as the
validated contract document (``jsonb``) next to the few columns the list needs, written by the
same INSERT from the same object so they cannot disagree. There is no UPDATE or DELETE statement
here and the table's triggers and the application role's grants forbid both.
"""

from __future__ import annotations

import logging
from datetime import datetime

from psycopg.types.json import Jsonb
from pydantic import ValidationError

from netsight_api.schemas_diagnostic_session import DiagnosticSession, DiagnosticSessionSummary
from netsight_api.storage import lifecycle
from netsight_api.storage.connection import PostgresSettings
from netsight_api.storage.diagnostics import (
    ID_PREFIX,
    check_actor,
    check_session_page,
    check_storable,
)
from netsight_api.storage.errors import StorageError

_LOGGER = logging.getLogger("netsight_api")

_INSERT = (
    "INSERT INTO diagnostic_sessions (id, target, started_at, completed_at, "
    "probable_fault_domain, confidence, created_by, created_at, document) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, now(), %s)"
)
_SELECT_ONE = "SELECT document::text AS document FROM diagnostic_sessions WHERE id = %s"
_SELECT_PAGE = (
    "SELECT id, target, started_at, completed_at, probable_fault_domain, confidence "
    "FROM diagnostic_sessions ORDER BY completed_at DESC, id DESC LIMIT %s OFFSET %s"
)
_COUNT_SINCE = "SELECT count(*) AS n FROM diagnostic_sessions WHERE completed_at >= %s"


class PostgresDiagnosticSessionRepository:
    def __init__(self, settings: PostgresSettings) -> None:
        self._settings = settings

    def save_session(self, session: DiagnosticSession, *, actor_id: str) -> None:
        check_actor(actor_id)
        check_storable(session)
        run = session.run
        key = lifecycle.parse_id(ID_PREFIX, run.id)
        assert key is not None  # the contract pattern guarantees a well-formed id
        document = Jsonb(session.model_dump(mode="json", by_alias=True))
        with self._settings.session() as conn:
            conn.execute(
                _INSERT,
                (
                    key,
                    run.target,
                    run.started_at,
                    run.completed_at,
                    run.probable_fault_domain,
                    run.confidence,
                    actor_id,
                    document,
                ),
            )

    def get_session(self, session_id: str) -> DiagnosticSession | None:
        key = lifecycle.parse_id(ID_PREFIX, session_id)
        if key is None:
            return None
        with self._settings.session() as conn:
            row = conn.execute(_SELECT_ONE, (key,)).fetchone()
        if row is None:
            return None
        try:
            return DiagnosticSession.model_validate_json(row["document"])
        except ValidationError as error:
            _LOGGER.warning("stored diagnostic session failed validation")
            raise StorageError("a stored session could not be read") from error

    def list_sessions(self, *, limit: int = 50, offset: int = 0) -> list[DiagnosticSessionSummary]:
        check_session_page(limit, offset)
        with self._settings.session() as conn:
            rows = conn.execute(_SELECT_PAGE, (limit, offset)).fetchall()
        try:
            return [
                DiagnosticSessionSummary(
                    id=lifecycle.format_id(ID_PREFIX, row["id"]),
                    target=row["target"],
                    started_at=row["started_at"],
                    completed_at=row["completed_at"],
                    probable_fault_domain=row["probable_fault_domain"],
                    confidence=row["confidence"],
                )
                for row in rows
            ]
        except ValidationError as error:
            _LOGGER.warning("stored diagnostic session summary failed validation")
            raise StorageError("a stored session could not be read") from error

    def count_sessions_since(self, since: datetime) -> int:
        with self._settings.session() as conn:
            row = conn.execute(_COUNT_SINCE, (since,)).fetchone()
        return 0 if row is None else int(row["n"])
