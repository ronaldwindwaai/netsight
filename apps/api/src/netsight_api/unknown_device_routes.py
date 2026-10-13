"""Unknown-device routes (Step 8c): the one router ``main`` mounts.

The reads (``unknown_device_read_routes``) are registered before the writes
(``unknown_device_write_routes``) so ``GET /summary`` is never read as a finding id; shared
dependencies, guards and error mapping are in ``unknown_device_support``. The names the tests and
``main`` override or import are re-exported here.
"""

from __future__ import annotations

from fastapi import APIRouter

from netsight_api import unknown_device_read_routes, unknown_device_write_routes
from netsight_api.unknown_device_support import (
    get_unknown_device_scanner,
    get_unknown_device_store,
)

router = APIRouter()
router.include_router(unknown_device_read_routes.router)
router.include_router(unknown_device_write_routes.router)

__all__ = ["get_unknown_device_scanner", "get_unknown_device_store", "router"]
