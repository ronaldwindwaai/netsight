"""Diagnostic session store (S7 Step 4a): the Protocol and the in-memory implementation.

Sessions are PostgreSQL-owned application state (DATABASE-OWNERSHIP). A session is written once,
when its run finishes, and is immutable from then on: the Protocol has no update or delete, saving
an existing id is a conflict (never an overwrite), and the PostgreSQL implementation also has the
database reject UPDATE / DELETE / TRUNCATE. Reads are bounded: a page is capped and the offset is
capped, so no caller can ask for the whole table.

The actor who started the run is stored for audit but is not part of the session contract.
"""

from __future__ import annotations

import threading
from datetime import datetime
from typing import Protocol

from netsight_api.schemas_diagnostic_session import (
    MAX_SESSION_LIST_OFFSET,
    MAX_SESSION_PAGE_SIZE,
    DiagnosticSession,
    DiagnosticSessionSummary,
)
from netsight_api.storage import lifecycle
from netsight_api.storage.errors import StorageConflictError

ID_PREFIX = "diagnostic"
MAX_ACTOR_LENGTH = 255


class DiagnosticSessionRepository(Protocol):
    def save_session(self, session: DiagnosticSession, *, actor_id: str) -> None:
        """Store a finished session. ``StorageConflictError`` if the id exists (never overwrites)."""
        ...

    def get_session(self, session_id: str) -> DiagnosticSession | None:
        """The stored session, or None for an unknown or malformed id."""
        ...

    def list_sessions(self, *, limit: int = 50, offset: int = 0) -> list[DiagnosticSessionSummary]:
        """Newest completed first (id breaks ties); ``limit`` and ``offset`` are bounded."""
        ...

    def count_sessions_since(self, since: datetime) -> int:
        """How many sessions completed at or after ``since`` (for the daily growth cap)."""
        ...


def check_actor(actor_id: str) -> None:
    if not isinstance(actor_id, str) or not 1 <= len(actor_id) <= MAX_ACTOR_LENGTH:
        raise ValueError(f"actor_id must be 1 to {MAX_ACTOR_LENGTH} characters")


def check_storable(session: DiagnosticSession) -> None:
    """Refuse a session that carries an incident title: titles are joined at read time only."""
    for item in session.recent_changes.items:
        if item.kind == "incident" and not item.title_redacted:
            raise ValueError("a stored session must not carry an incident title")


def check_session_page(limit: int, offset: int) -> None:
    lifecycle.check_page(limit, offset, maximum=MAX_SESSION_PAGE_SIZE)
    if offset > MAX_SESSION_LIST_OFFSET:
        raise ValueError(f"offset must not exceed {MAX_SESSION_LIST_OFFSET}")


class InMemoryDiagnosticSessionRepository:
    """Unit-test implementation with the same rules as the PostgreSQL store."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, DiagnosticSession] = {}

    def save_session(self, session: DiagnosticSession, *, actor_id: str) -> None:
        check_actor(actor_id)
        check_storable(session)
        with self._lock:
            if session.run.id in self._sessions:
                raise StorageConflictError("the session already exists and is immutable")
            self._sessions[session.run.id] = session.model_copy(deep=True)

    def get_session(self, session_id: str) -> DiagnosticSession | None:
        if lifecycle.parse_id(ID_PREFIX, session_id) is None:
            return None
        with self._lock:
            stored = self._sessions.get(session_id)
            return None if stored is None else stored.model_copy(deep=True)

    def list_sessions(self, *, limit: int = 50, offset: int = 0) -> list[DiagnosticSessionSummary]:
        check_session_page(limit, offset)
        with self._lock:
            rows = list(self._sessions.values())
        rows.sort(key=lambda s: (s.run.completed_at, s.run.id), reverse=True)
        return [DiagnosticSessionSummary.from_session(row) for row in rows[offset : offset + limit]]

    def count_sessions_since(self, since: datetime) -> int:
        with self._lock:
            return sum(1 for row in self._sessions.values() if row.run.completed_at >= since)
