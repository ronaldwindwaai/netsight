"""``/api/v1/actions``: the controlled remote action surface (Step 12, roadmap E11).

The routes are split by what they do: ``actions_read_routes`` (status, list, detail),
``actions_write_routes`` (propose, approve, reject, cancel, execute, the kill switch) and
``actions_route_support`` (dependencies, guards, errors, audit). Static paths are mounted before the
``/{action_id}`` routes so they are never read as an id.

There is no route that runs a command, and no action type outside ``actions.catalog.CATALOG``.
"""

from __future__ import annotations

from fastapi import APIRouter

from netsight_api.actions_read_routes import router as read_router
from netsight_api.actions_write_routes import router as write_router

router = APIRouter(tags=["actions"])
# Order matters: /status, /from-finding and /kill-switch before /{action_id}.
router.include_router(read_router)
router.include_router(write_router)

__all__ = ["router"]
