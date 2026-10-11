"""Shared building blocks of the Step 8 read routes (inventory, IPAM, unknown-device findings).

* ``reader`` builds the authorisation dependency: permission first (a refusal is audited), then the
  per-identity read budget (also audited), so an unauthorised caller never learns limiter state;
* ``no_store`` marks a response as not cacheable (asset and address data is operational detail);
* ``rejected`` is the one 422 for an unacceptable query: fixed message, nothing echoed, audited.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Request, Response

from netsight_api.auth.deps import get_current_identity
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.read_limit import enforce_read_limit
from netsight_api.traffic import audit_trail

CurrentIdentity = Annotated[Identity, Depends(get_current_identity)]


def reader(
    permission: Permission, action: str, family: str, limit: Callable[[], int]
) -> Callable[..., Identity]:
    """A dependency that authorises ``permission`` and spends one read from ``family``'s budget.

    ``limit`` is called per request so a module constant stays patchable in tests.
    """

    def dependency(request: Request, identity: CurrentIdentity) -> Identity:
        if not is_allowed(identity, permission.value):
            audit_trail.denied(request, identity.id, action, "permission")
            raise ApiError(403, "FORBIDDEN", "Permission is required")
        try:
            enforce_read_limit(identity, family, limit())
        except ApiError:
            audit_trail.denied(request, identity.id, action, "rate-limit")
            raise
        return identity

    return dependency


def no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


def rejected(request: Request, identity: Identity, action: str) -> ApiError:
    audit_trail.failed(request, identity.id, action, "invalid-request")
    return ApiError(422, "VALIDATION_ERROR", "Request validation failed")
