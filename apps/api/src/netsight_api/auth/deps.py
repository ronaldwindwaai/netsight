"""Request dependencies for session and identity resolution.

``get_current_identity`` is the single choke point every protected
route uses. It fails closed: an absent or invalid session yields 401.
The development identity bridge is strictly gated behind two explicit
environment flags and is never enabled in production.
"""

from __future__ import annotations

from fastapi import Request

from netsight_api.auth.session import Session, session_manager
from netsight_api.auth.settings import auth_settings
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity


def get_session(request: Request) -> Session | None:
    manager = session_manager()
    cookie = request.cookies.get(manager.policy.cookie_name)
    return manager.validate_cookie(cookie)


def get_current_identity(request: Request) -> Identity:
    """Resolve the caller identity from the verified session."""
    settings = auth_settings()
    if settings.environment == "development" and settings.enable_dev_identity:
        return Identity("dev-user", frozenset({"administrator"}))

    session = get_session(request)
    if session is None:
        raise ApiError(401, "AUTHENTICATION_REQUIRED", "Authentication is required")
    return Identity(id=session.identity_id, roles=session.roles)
