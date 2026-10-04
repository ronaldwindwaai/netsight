"""Authentication HTTP endpoints.

Implements the OIDC Authorization Code + PKCE round-trip, session
issuance/inspection and CSRF-protected logout. Every endpoint fails
closed and enforces the provider allow-lists.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request, Response
from fastapi.responses import RedirectResponse

from netsight_api.auth.deps import get_session
from netsight_api.auth.identity import build_identity
from netsight_api.auth.oidc import (
    OidcError,
    authorization_url,
    exchange_code,
    generate_code_verifier,
    generate_nonce,
    generate_state,
    validate_id_token,
)
from netsight_api.auth.pending import pending_auth_store
from netsight_api.auth.providers import MICROSOFT, ProviderId
from netsight_api.auth.rate_limit import rate_limiter
from netsight_api.auth.session import session_manager
from netsight_api.auth.settings import (
    ProviderSettings,
    auth_settings,
    clerk_settings,
    google_settings,
    microsoft_settings,
)
from netsight_api.errors import ApiError
from netsight_api.schemas import AuthProvidersResponse, ProviderState

router = APIRouter(prefix="/auth", tags=["auth"])

RATE_WINDOW_SECONDS = 60.0


def _provider_or_error(raw: str) -> ProviderId:
    try:
        return ProviderId(raw.lower())
    except ValueError as exc:
        raise ApiError(404, "PROVIDER_UNKNOWN", "Identity provider is not supported") from exc


def _provider_settings(provider: ProviderId) -> ProviderSettings:
    return microsoft_settings() if provider is MICROSOFT else google_settings()


def _safe_redirect(target: str | None) -> str:
    if not isinstance(target, str) or not target.startswith("/") or target.startswith("//"):
        return "/overview"
    return target


def _redirect_uri(request: Request) -> str:
    base = auth_settings().public_base_url.strip().rstrip("/")
    if not base:
        base = str(request.base_url).rstrip("/")
    return f"{base}/auth/callback"


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _rate_limit(request: Request, action: str) -> None:
    settings = auth_settings()
    key = f"auth:{action}:{_client_ip(request)}"
    if not rate_limiter().allow(key, settings.auth_rate_limit_per_minute, RATE_WINDOW_SECONDS):
        raise ApiError(429, "RATE_LIMITED", "Too many authentication requests")


@router.get(
    "/providers",
    response_model=AuthProvidersResponse,
    tags=["auth"],
)
async def providers() -> AuthProvidersResponse:
    """Public sign-in provider configuration state for the sign-in UI.

    Reports only whether each provider is connected. Client secrets and
    allow-list values are never exposed.
    """

    microsoft = microsoft_settings()
    google = google_settings()
    clerk = clerk_settings()
    return AuthProvidersResponse(
        providers={
            "microsoft": ProviderState(
                configured=bool(microsoft.enabled and microsoft.client_id)
            ),
            "google": ProviderState(configured=bool(google.enabled and google.client_id)),
            "clerk": ProviderState(configured=bool(clerk.enabled and clerk.client_id)),
        }
    )


@router.get("/login/{provider}")
async def login(provider: str, request: Request, redirect_to: str = "/overview") -> Response:
    resolved = _provider_or_error(provider)
    settings = _provider_settings(resolved)
    if not settings.enabled or not settings.client_id:
        raise ApiError(
            409,
            "PROVIDER_NOT_CONFIGURED",
            "This sign-in provider is not connected on this deployment",
        )

    _rate_limit(request, "login")

    state = generate_state()
    nonce = generate_nonce()
    code_verifier = generate_code_verifier()
    pending_auth_store().put(
        state=state,
        provider=resolved,
        nonce=nonce,
        code_verifier=code_verifier,
        redirect_to=_safe_redirect(redirect_to),
    )

    try:
        url = await authorization_url(
            resolved,
            settings,
            _redirect_uri(request),
            state,
            nonce,
            code_verifier,
        )
    except OidcError as exc:
        raise ApiError(502, "OIDC_UNAVAILABLE", exc.message) from exc

    return RedirectResponse(url, status_code=302)


@router.get("/callback")
async def callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> Response:
    _rate_limit(request, "callback")

    if error:
        raise ApiError(400, "AUTH_CALLBACK_ERROR", "Identity provider reported an error")

    if not code or not state:
        raise ApiError(400, "AUTH_CALLBACK_INVALID", "Callback was missing a code or state")

    pending = pending_auth_store().take(state)
    if pending is None:
        raise ApiError(400, "AUTH_STATE_INVALID", "Authentication state was unknown or expired")

    settings = _provider_settings(pending.provider)

    try:
        token = await exchange_code(
            pending.provider,
            settings,
            code,
            _redirect_uri(request),
            pending.code_verifier,
        )
        claims = await validate_id_token(
            pending.provider,
            settings,
            token.id_token,
            pending.nonce,
        )
    except OidcError as exc:
        raise ApiError(401, "AUTH_VERIFICATION_FAILED", exc.message) from exc

    identity = build_identity(claims.raw, auth_settings(), pending.provider.value)
    manager = session_manager()
    session = manager.create_session(
        subject=claims.subject,
        provider=pending.provider.value,
        roles=identity.roles,
        email=claims.email,
    )

    target = _safe_redirect(pending.redirect_to)
    response = RedirectResponse(target, status_code=302)
    response.set_cookie(value=manager.cookie_value(session), **manager.cookie_attributes())
    return response


@router.get("/session")
async def session_info(request: Request) -> dict[str, Any]:
    session = get_session(request)
    if session is None:
        raise ApiError(401, "AUTHENTICATION_REQUIRED", "Authentication is required")
    return {
        "authenticated": True,
        "identity_id": session.identity_id,
        "provider": session.provider,
        "email": session.email,
        "roles": sorted(session.roles),
    }


@router.get("/csrf")
async def csrf_token(request: Request) -> dict[str, str]:
    session = get_session(request)
    if session is None:
        raise ApiError(401, "AUTHENTICATION_REQUIRED", "Authentication is required")
    return {"csrf_token": session.csrf_token}


@router.post("/logout")
async def logout(request: Request) -> Response:
    manager = session_manager()
    session = get_session(request)

    if session is not None:
        supplied = request.headers.get("X-CSRF-Token", "")
        if supplied != session.csrf_token:
            raise ApiError(403, "CSRF_VALIDATION_FAILED", "Logout requires a valid CSRF token")
        manager.revoke(session.id)

    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie(
        manager.policy.cookie_name,
        path="/",
        domain=manager.policy.cookie_domain or None,
    )
    return response
