"""Read-time join of incident titles into a stored diagnostic session (security H1).

A stored session keeps an incident change only as a reference (id, severity, time). Its title is
looked up here, per read, and only for a caller who holds ``incidents:read`` *now*: a title that
was readable when the run happened must not outlive the reader's permission, and Management
(summary-only by human decision) must never receive one through a diagnostic. Anyone else, and any
lookup that fails, keeps the fixed placeholder. Nothing here raises to the caller and nothing leaks
a driver message.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping

from fastapi.concurrency import run_in_threadpool

from netsight_api.diagnostic_changes import clean_title
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.schemas_diagnostic_session import (
    DiagnosticChangeItem,
    DiagnosticSession,
)
from netsight_api.storage import IncidentRepository

_LOGGER = logging.getLogger("netsight_api")


def incident_refs(session: DiagnosticSession) -> list[str]:
    """The distinct incident ids a session refers to, in order."""
    seen: dict[str, None] = {}
    for item in session.recent_changes.items:
        if item.kind == "incident":
            seen.setdefault(item.ref_id)
    return list(seen)


def reveal_incident_titles(
    session: DiagnosticSession, titles: Mapping[str, str]
) -> DiagnosticSession:
    """A copy of ``session`` with the given incident titles filled in; the input is unchanged."""
    if not titles:
        return session
    items: list[DiagnosticChangeItem] = []
    for item in session.recent_changes.items:
        title = titles.get(item.ref_id) if item.kind == "incident" else None
        if title is None:
            items.append(item)
        else:
            items.append(item.model_copy(update={"title": title, "title_redacted": False}))
    changes = session.recent_changes.model_copy(update={"items": items})
    return session.model_copy(update={"recent_changes": changes})


def _lookup(store: IncidentRepository, refs: list[str]) -> dict[str, str]:
    found: dict[str, str] = {}
    for ref in refs:
        try:
            incident = store.get_incident(ref)
        except Exception as exc:  # noqa: BLE001 — a failed lookup keeps the placeholder
            _LOGGER.warning(
                "diagnostic incident title lookup failed", extra={"error_type": type(exc).__name__}
            )
            continue
        title = clean_title(incident.title) if incident is not None else ""
        if title:
            found[ref] = title
    return found


async def with_incident_titles(
    session: DiagnosticSession, identity: Identity, store: IncidentRepository | None
) -> DiagnosticSession:
    """Join titles for a caller holding ``incidents:read``; otherwise the session as stored."""
    if store is None or not is_allowed(identity, Permission.INCIDENTS_READ.value):
        return session
    refs = incident_refs(session)
    if not refs:
        return session
    titles = await run_in_threadpool(lambda: _lookup(store, refs))
    return reveal_incident_titles(session, titles)
