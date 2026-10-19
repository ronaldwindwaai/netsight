"""Controlled-action reads (Step 12): status, the list and one request with its history.

Read-only. ``actions:read`` is the only permission; the list and the detail carry operational
detail, so they are ``no-store``. A disabled engine is ``not-connected`` (status and list answer 200
with nothing in them; the detail is 503), never an empty success that looks like "nothing pending".
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response

from netsight_api import actions_route_support as support
from netsight_api.actions.catalog import CATALOG, definition_contract
from netsight_api.actions.errors import ActionNotFound
from netsight_api.actions.wiring import ActionRuntime
from netsight_api.rbac import Identity, Permission
from netsight_api.read_support import no_store, reader, rejected
from netsight_api.schemas_actions import (
    MAX_PAGE_SIZE,
    ActionDetailResponse,
    ActionListResponse,
    ActionStatusResponse,
    KillSwitchStatus,
    PolicyStatus,
    RequestState,
    StoreStatus,
)
from netsight_api.traffic import audit_trail

router = APIRouter(prefix="/actions")
_ALLOWED_QUERY = frozenset({"state", "page", "page_size"})
_RESPONSES = {k: v for k, v in support.ERRORS.items() if k not in (409,)}

StatusReader = Annotated[
    Identity,
    Depends(
        reader(
            Permission.ACTIONS_READ,
            "actions.status.read",
            "actions",
            lambda: support.READ_LIMIT_PER_MINUTE,
        )
    ),
]
ListReader = Annotated[
    Identity,
    Depends(
        reader(
            Permission.ACTIONS_READ,
            "actions.list.read",
            "actions",
            lambda: support.READ_LIMIT_PER_MINUTE,
        )
    ),
]
DetailReader = Annotated[Identity, Depends(support.item_reader("actions.item.read"))]


def status_body(runtime: ActionRuntime | None, now: support.Clock) -> ActionStatusResponse:
    generated_at = now()
    if runtime is None:
        return ActionStatusResponse(
            state="not-connected",
            generated_at=generated_at,
            dry_run_only=True,
            kill_switch=KillSwitchStatus(engaged=False, source="none", since=None),
            store=StoreStatus(kind="memory", durable=False),
            policy=PolicyStatus(self_execute_allowed=False),
            executors=[],
            definitions=[],
        )
    executors = [e.status() for e in runtime.executors]
    return ActionStatusResponse(
        state="ok",
        generated_at=generated_at,
        dry_run_only=not any(e.mode == "live" and e.state == "ok" for e in executors),
        kill_switch=runtime.kill_switch.status(),
        store=StoreStatus(kind="memory", durable=False),
        policy=PolicyStatus(self_execute_allowed=runtime.store.allow_self_execute),
        executors=executors,
        definitions=[definition_contract(d) for d in CATALOG.values()],
    )


@router.get(
    "/status",
    response_model=ActionStatusResponse,
    responses={k: v for k, v in _RESPONSES.items() if k not in (404, 422, 503)},
    operation_id="getActionStatus",
)
async def action_status(
    request: Request,
    response: Response,
    identity: StatusReader,
    runtime: support.Runtime,
    now: support.Clock,
) -> ActionStatusResponse:
    no_store(response)
    body = status_body(runtime, now)
    audit_trail.read(request, identity.id, "actions.status.read", state=body.state)
    return support.checked("action_status", body)  # type: ignore[no-any-return]


@router.get(
    "",
    response_model=ActionListResponse,
    responses={k: v for k, v in _RESPONSES.items() if k not in (404, 503)},
    operation_id="listActions",
)
async def list_actions(
    request: Request,
    response: Response,
    identity: ListReader,
    runtime: support.Runtime,
    now: support.Clock,
    state: Annotated[RequestState | None, Query()] = None,
    page: Annotated[int, Query(ge=1, le=1000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 25,
) -> ActionListResponse:
    no_store(response)
    if not _ALLOWED_QUERY.issuperset(request.query_params.keys()):
        raise rejected(request, identity, "actions.list.read")
    if runtime is None:
        body = ActionListResponse(
            state="not-connected",
            generated_at=now(),
            items=[],
            total=0,
            page=page,
            page_size=page_size,
        )
    else:
        items, total = await support.run_call(
            request,
            identity,
            "actions.list.read",
            None,
            lambda: runtime.store.list_requests(
                state=state, limit=page_size, offset=(page - 1) * page_size, now=now()
            ),
        )
        body = ActionListResponse(
            state="ok", generated_at=now(), items=items, total=total, page=page, page_size=page_size
        )
    audit_trail.read(
        request,
        identity.id,
        "actions.list.read",
        state=body.state,
        count=len(body.items),
        filters=",".join(k for k in request.query_params if k == "state"),
    )
    return support.checked("action_list", body)  # type: ignore[no-any-return]


@router.get(
    "/{action_id}",
    response_model=ActionDetailResponse,
    responses=_RESPONSES,
    operation_id="getAction",
)
async def get_action(
    request: Request,
    response: Response,
    action_id: support.ActionIdPath,
    identity: DetailReader,
    runtime: support.Runtime,
    now: support.Clock,
) -> ActionDetailResponse:
    no_store(response)
    active = support.require_runtime(request, identity, "actions.item.read", runtime)

    def load() -> ActionDetailResponse:
        active.store.expire_due(now())
        found = active.store.get(action_id)
        if found is None:
            raise ActionNotFound
        return ActionDetailResponse(
            generated_at=now(),
            request=found,
            history=active.store.history(action_id),
            chain_intact=active.store.verify_chain(action_id),
        )

    body = await support.run_call(request, identity, "actions.item.read", action_id, load)
    # A history whose hash chain does not verify is reported to the caller and audited as a failure.
    audit_trail.read(
        request,
        identity.id,
        "actions.item.read",
        failure=not body.chain_intact,
        state=body.request.state,
        chain_intact=body.chain_intact,
    )
    return support.checked("action_detail", body)  # type: ignore[no-any-return]
