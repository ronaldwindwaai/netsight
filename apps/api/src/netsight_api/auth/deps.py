"""Request dependencies for session and identity resolution.

``get_current_identity`` is the single choke point every protected route uses. It
fails closed: an absent or invalid session yields 401.

The development identity bridge is gated behind two explicit environment flags
(``NETSIGHT_ENV=development`` and ``NETSIGHT_ENABLE_DEV_IDENTITY=true``). When on it
grants an administrator identity to *every* request that reaches the server, with no
cookie and no credential of any kind: it is an ambient credential, so a page on any
other origin that the developer's browser visits could drive writes at it. Mutating
routes therefore still demand the CSRF header and the origin allow-list for bridge
requests (see ``netsight_api.auth.csrf``). It must never be enabled outside local
development.

The session is resolved once per request and recorded on ``request.state.auth`` so the
identity decision and the CSRF decision are made against the very same session object.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal, cast

from fastapi import Request

from netsight_api.auth.session import Session, session_manager
from netsight_api.auth.settings import auth_settings
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity, PrincipalKind

AuthSource = Literal["session", "dev-bridge"]

_UNRESOLVED: Final = object()


@dataclass(frozen=True)
class AuthContext:
    """How the request's identity was established.

    ``session`` is None only for the dev bridge (or, defensively, when a session-sourced
    identity has lost its session, which consumers must treat as a failure).
    """

    source: AuthSource
    session: Session | None = None


def get_session(request: Request) -> Session | None:
    """Resolve the session cookie once per request (it also slides the inactivity timer)."""
    cached = getattr(request.state, "resolved_session", _UNRESOLVED)
    if cached is not _UNRESOLVED:
        return cast("Session | None", cached)
    manager = session_manager()
    session = manager.validate_cookie(request.cookies.get(manager.policy.cookie_name))
    request.state.resolved_session = session
    return session


def get_request_auth(request: Request) -> AuthContext | None:
    """The auth context recorded by ``get_current_identity``; None if it did not run."""
    context = getattr(request.state, "auth", None)
    return context if isinstance(context, AuthContext) else None


def dev_identity_bridge_enabled() -> bool:
    settings = auth_settings()
    return settings.environment == "development" and settings.enable_dev_identity


def get_current_identity(request: Request) -> Identity:
    """Resolve the caller identity from the verified session."""
    if dev_identity_bridge_enabled():
        request.state.auth = AuthContext(source="dev-bridge")
        return Identity("dev-user", frozenset({"administrator"}), PrincipalKind.HUMAN)

    session = get_session(request)
    if session is None:
        raise ApiError(401, "AUTHENTICATION_REQUIRED", "Authentication is required")
    request.state.auth = AuthContext(source="session", session=session)
    # Sessions are only issued after an interactive OIDC / MFA-backed local sign-in.
    return Identity(id=session.identity_id, roles=session.roles, principal=PrincipalKind.HUMAN)
