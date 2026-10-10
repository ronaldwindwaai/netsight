"""Shared building blocks of the incident routers: error maps, store wiring and read guards.

``incident_routes`` (detail, timeline, writes) and ``incident_list_routes`` (list, summary) both
build on these. ``get_optional_incident_store`` is the single dependency tests override.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from typing import Annotated, Any, NoReturn, cast

from fastapi import Depends, Path, Request

from netsight_api.auth.deps import get_current_identity
from netsight_api.contracts import validate
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.read_limit import enforce_read_limit
from netsight_api.schemas import INCIDENT_ID_PATTERN, ErrorEnvelope
from netsight_api.schemas_incidents import (
    IncidentDetailResponse,
    IncidentListResponse,
    IncidentSummaryListResponse,
    IncidentTimelineResponse,
)
from netsight_api.storage import IncidentRepository, StorageConfigurationError, StorageError

LOGGER = logging.getLogger("netsight_api")

READ_ERRORS: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorEnvelope, "description": "Authentication required"},
    403: {"model": ErrorEnvelope, "description": "Permission denied"},
    422: {"model": ErrorEnvelope, "description": "Invalid request"},
}
ITEM_READ_ERRORS: dict[int | str, dict[str, Any]] = {
    **READ_ERRORS,
    404: {"model": ErrorEnvelope, "description": "Incident not found"},
}
WRITE_ERRORS: dict[int | str, dict[str, Any]] = {
    **ITEM_READ_ERRORS,
    409: {"model": ErrorEnvelope, "description": "Illegal transition or concurrent change"},
    429: {"model": ErrorEnvelope, "description": "Write rate limit exceeded"},
    503: {"model": ErrorEnvelope, "description": "Incident store not connected or unavailable"},
}
STEP_UP_ERRORS: dict[int | str, dict[str, Any]] = {
    **WRITE_ERRORS,
    403: {
        "model": ErrorEnvelope,
        "description": "Permission denied, or STEP_UP_REQUIRED: recent MFA is needed (sign in again)",
    },
}


# --- store wiring -----------------------------------------------------------------------------


class _UnavailableStore:
    """Stands in when ``DATABASE_URL`` is set but unusable: every call fails as unavailable."""

    def __getattr__(self, name: str) -> Callable[..., NoReturn]:
        def unavailable(*_args: object, **_kwargs: object) -> NoReturn:
            raise StorageError("the incident store is not usable")

        return unavailable


def get_optional_incident_store() -> IncidentRepository | None:
    """PostgreSQL store for the app role (``DATABASE_URL``); ``None`` means not-connected.

    Only the least-privilege application DSN is ever read here, never the migrator's.
    A configured-but-invalid DSN yields a store whose calls fail, so the endpoints degrade
    to explicit ``unknown`` (configured does not imply connected) without echoing it.
    """
    if not os.environ.get("DATABASE_URL", "").strip():
        return None
    from netsight_api.storage.connection import PostgresSettings
    from netsight_api.storage.postgres import PostgresIncidentRepository

    try:
        settings = PostgresSettings.from_env()
    except StorageConfigurationError:
        return cast(IncidentRepository, _UnavailableStore())
    return PostgresIncidentRepository(settings)


OptionalIncidentStore = Annotated[IncidentRepository | None, Depends(get_optional_incident_store)]
CurrentIdentity = Annotated[Identity, Depends(get_current_identity)]
IncidentId = Annotated[str, Path(min_length=45, max_length=45, pattern=INCIDENT_ID_PATTERN)]


def correlation_id_of(request: Request) -> str:
    value = getattr(request.state, "correlation_id", None)
    return value if isinstance(value, str) else "unknown"


# --- authorisation, CSRF, rate limiting --------------------------------------------------------


def require_incident_reader(identity: CurrentIdentity) -> Identity:
    if not is_allowed(identity, Permission.INCIDENTS_READ.value):
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    enforce_read_limit(identity, "incidents")
    return identity


IncidentReader = Annotated[Identity, Depends(require_incident_reader)]


def require_incident_summary_reader(identity: CurrentIdentity) -> Identity:
    if not is_allowed(identity, Permission.INCIDENTS_READ_SUMMARY.value):
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    enforce_read_limit(identity, "incidents")
    return identity


IncidentSummaryReader = Annotated[Identity, Depends(require_incident_summary_reader)]


def log_read_failure(request: Request, exc: Exception) -> None:
    LOGGER.warning(
        "incident store read failed",
        extra={"correlation_id": correlation_id_of(request), "error_type": type(exc).__name__},
    )


def checked_response[
    M: IncidentListResponse
    | IncidentSummaryListResponse
    | IncidentDetailResponse
    | IncidentTimelineResponse
](name: str, body: M) -> M:
    """Canonical boundary validation applied on every successful return path."""
    validate(name, body.model_dump(mode="json", by_alias=True))
    return body
