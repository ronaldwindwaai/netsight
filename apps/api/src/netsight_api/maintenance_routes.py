"""Maintenance-window API (S6-3): list, get, create and cancel.

Same request pipeline as the alert-rule routes (``alert_rule_routes.py``): authorise (403) ->
CSRF + origin (403) -> rate limit (429); explicit ``not-connected`` / ``unknown`` read states
that never carry rows; every mutation audited from the worker thread with free-form values
(name, reason, scope reference) reduced to lengths and short hashes.

A window suppresses notifications for its scope, so creating one is bounded and guarded:

* it may last at most 30 days (contract), must not already have ended, and may not start more
  than a year ahead;
* a window with ``organisation`` scope silences everything and a window with evaluation
  ``disable`` stops rules from being evaluated at all: both need the separate
  ``maintenance:write-organisation`` permission (administrators only), whatever the scope kind
  of a disable window. Cancelling an organisation-scope window needs it too, judged on the
  locked row inside the store call;
* live windows are capped per scope reference and in total (``storage.lifecycle``);
* create and cancel audit records carry ``silencing``, scope kind, evaluation mode and a
  duration bucket (``alerting_audit.py``);
* ``active`` and ``expired`` are never stored: the ``active`` list filter derives them from
  the server clock (``get_now``), and a cancelled window never counts.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.concurrency import run_in_threadpool

from netsight_api.alerting_audit import window_silencing_details
from netsight_api.alerting_route_support import (
    CREATE_ERRORS,
    ITEM_READ_ERRORS,
    READ_ERRORS,
    WRITE_ERRORS,
    Now,
    OptionalAlertRuleStore,
    WindowId,
    audit_refusal,
    collection_writer,
    log_read_failure,
    mutate,
    reader,
    window_writer,
)
from netsight_api.audit import fingerprint
from netsight_api.contracts import validate
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.schemas import MaintenanceWindow, MaintenanceWindowDefinition, StoreState
from netsight_api.schemas_alerting import (
    MAX_MAINTENANCE_LEAD,
    MAX_RULE_LIST_OFFSET,
    MAX_RULE_PAGE_SIZE,
    MaintenanceWindowCreateRequest,
    MaintenanceWindowDetailResponse,
    MaintenanceWindowListResponse,
)
from netsight_api.storage import AlertRuleRepository, InvalidOperationError

router = APIRouter(prefix="/maintenance-windows", tags=["maintenance-windows"])
_NOUN = "Maintenance window"

_WindowReader = Annotated[Identity, Depends(reader(Permission.MAINTENANCE_READ, "maintenance"))]
_CreateActor = Annotated[
    Identity,
    Depends(collection_writer(Permission.MAINTENANCE_WRITE, action="maintenance.create")),
]
_CancelActor = Annotated[
    Identity,
    Depends(window_writer(Permission.MAINTENANCE_WRITE, action="maintenance.cancel")),
]


def _check_bounds(definition: MaintenanceWindowDefinition, now: datetime) -> None:
    """Domain bounds that depend on the clock; raised inside the audited boundary."""
    if definition.ends_at <= now:
        raise InvalidOperationError("the maintenance window has already ended")
    if definition.starts_at > now + MAX_MAINTENANCE_LEAD:
        raise InvalidOperationError("a maintenance window may start at most one year ahead")


def _create_details(body: MaintenanceWindowCreateRequest) -> dict[str, object]:
    return {
        **window_silencing_details("window-create", body.to_definition()),
        "scope_ref_hash": fingerprint(body.scope.ref),
        "scope_ref_length": len(body.scope.ref),
        "duration_seconds": int((body.ends_at - body.starts_at).total_seconds()),
        "starts_at": body.starts_at.isoformat(),
        "name_hash": fingerprint(body.name),
        "name_length": len(body.name),
        "reason_length": len(body.reason),
    }


def _checked[M: MaintenanceWindowListResponse | MaintenanceWindowDetailResponse](
    name: str, body: M
) -> M:
    validate(name, body.model_dump(mode="json", by_alias=True))
    return body


@router.get(
    "",
    response_model=MaintenanceWindowListResponse,
    responses=READ_ERRORS,
    operation_id="listMaintenanceWindows",
)
async def list_maintenance_windows(
    request: Request,
    _identity: _WindowReader,
    store: OptionalAlertRuleStore,
    now: Now,
    active: Annotated[bool, Query()] = False,
    include_cancelled: Annotated[bool, Query()] = False,
    limit: Annotated[int, Query(ge=1, le=MAX_RULE_PAGE_SIZE)] = 50,
    offset: Annotated[int, Query(ge=0, le=MAX_RULE_LIST_OFFSET)] = 0,
) -> MaintenanceWindowListResponse:
    """Windows by start time. ``active`` keeps only those running at the server clock."""

    def empty(state_name: StoreState) -> MaintenanceWindowListResponse:
        return _checked(
            "maintenance_window_list",
            MaintenanceWindowListResponse(
                state=state_name, windows=[], limit=limit, offset=offset, next_offset=None
            ),
        )

    if store is None:
        return empty("not-connected")
    repository = store
    try:
        rows = await run_in_threadpool(
            lambda: repository.list_windows(
                active_at=now if active else None,
                include_cancelled=include_cancelled,
                limit=limit,
                offset=offset,
            )
        )
        following = offset + limit
        more = len(rows) == limit and following <= MAX_RULE_LIST_OFFSET
        return _checked(
            "maintenance_window_list",
            MaintenanceWindowListResponse(
                state="ok",
                windows=rows,
                limit=limit,
                offset=offset,
                next_offset=following if more else None,
            ),
        )
    except Exception as exc:  # noqa: BLE001 - deliberate store/contract boundary
        log_read_failure(request, exc)
        return empty("unknown")


@router.get(
    "/{window_id}",
    response_model=MaintenanceWindowDetailResponse,
    responses=ITEM_READ_ERRORS,
    operation_id="getMaintenanceWindow",
)
async def get_maintenance_window(
    request: Request,
    window_id: WindowId,
    _identity: _WindowReader,
    store: OptionalAlertRuleStore,
) -> MaintenanceWindowDetailResponse:
    if store is None:
        return _checked(
            "maintenance_window_detail",
            MaintenanceWindowDetailResponse(state="not-connected", window=None),
        )
    repository = store
    try:
        window = await run_in_threadpool(repository.get_window, window_id)
    except Exception as exc:  # noqa: BLE001 - deliberate store boundary
        log_read_failure(request, exc)
        return _checked(
            "maintenance_window_detail",
            MaintenanceWindowDetailResponse(state="unknown", window=None),
        )
    if window is None:
        raise ApiError(404, "NOT_FOUND", f"{_NOUN} was not found")
    return _checked(
        "maintenance_window_detail", MaintenanceWindowDetailResponse(state="ok", window=window)
    )


@router.post(
    "",
    response_model=MaintenanceWindow,
    status_code=201,
    responses=CREATE_ERRORS,
    operation_id="createMaintenanceWindow",
)
async def create_maintenance_window(
    request: Request,
    body: MaintenanceWindowCreateRequest,
    actor: _CreateActor,
    store: OptionalAlertRuleStore,
    now: Now,
) -> MaintenanceWindow:
    """Schedule a window. Organisation scope and ``disable`` evaluation need the organisation
    permission."""
    organisation_allowed = is_allowed(actor, Permission.MAINTENANCE_WRITE_ORGANISATION.value)
    if body.scope.kind == "organisation" and not organisation_allowed:
        audit_refusal(request, "maintenance.create", actor, "organisation-scope", None)
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    if body.evaluation == "disable" and not organisation_allowed:
        audit_refusal(request, "maintenance.create", actor, "disable-evaluation", None)
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    actor_id = actor.id

    def operation(repository: AlertRuleRepository) -> MaintenanceWindow:
        # Re-validated against the strict model inside the audited boundary.
        definition = body.to_definition()
        _check_bounds(definition, now)
        # The two pre-checks above are re-applied inside the store (deny by default).
        return repository.create_window(
            definition, actor_id=actor_id, organisation_allowed=organisation_allowed
        )

    return await mutate(
        request,
        store,
        actor,
        action="maintenance.create",
        noun=_NOUN,
        operation=operation,
        target=None,
        target_of=lambda window: window.id,
        details=_create_details(body),
    )


@router.post(
    "/{window_id}/cancel",
    response_model=MaintenanceWindow,
    responses=WRITE_ERRORS,
    operation_id="cancelMaintenanceWindow",
)
async def cancel_maintenance_window(
    request: Request,
    window_id: WindowId,
    actor: _CancelActor,
    store: OptionalAlertRuleStore,
) -> MaintenanceWindow:
    """Cancel a scheduled window; a second cancellation is a 409.

    An organisation-scope window needs ``maintenance:write-organisation``; the store checks the
    scope of the locked row and refuses with an audited ``organisation-scope`` denial.
    """
    actor_id = actor.id
    organisation_allowed = is_allowed(actor, Permission.MAINTENANCE_WRITE_ORGANISATION.value)
    return await mutate(
        request,
        store,
        actor,
        action="maintenance.cancel",
        noun=_NOUN,
        operation=lambda repository: repository.cancel_window(
            window_id, actor_id=actor_id, organisation_allowed=organisation_allowed
        ),
        target=window_id,
        details_of=lambda window: window_silencing_details("window-cancel", window),
    )
