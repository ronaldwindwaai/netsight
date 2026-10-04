"""Authentication endpoint tests (login, callback, session, logout)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from netsight_api.auth.oidc import TokenResponse, VerifiedClaims
from netsight_api.main import app

CLEANUP_ENV = (
    "NETSIGHT_ENV",
    "NETSIGHT_ENABLE_DEV_IDENTITY",
    "NETSIGHT_PUBLIC_BASE_URL",
    "NETSIGHT_ROLE_CLAIM",
    "NETSIGHT_ROLE_MAPPING",
    "NETSIGHT_DEFAULT_ROLE",
    "NETSIGHT_AUTH_RATE_LIMIT_PER_MINUTE",
    "NETSIGHT_OIDC_MICROSOFT_ENABLED",
    "NETSIGHT_OIDC_MICROSOFT_CLIENT_ID",
    "NETSIGHT_OIDC_MICROSOFT_CLIENT_SECRET",
    "NETSIGHT_OIDC_MICROSOFT_AUTHORITY",
    "NETSIGHT_OIDC_MICROSOFT_TENANT_IDS",
    "NETSIGHT_OIDC_GOOGLE_ENABLED",
    "NETSIGHT_OIDC_GOOGLE_CLIENT_ID",
    "NETSIGHT_OIDC_GOOGLE_CLIENT_SECRET",
    "NETSIGHT_OIDC_GOOGLE_AUTHORITY",
    "NETSIGHT_SESSION_SECURE_COOKIE",
    "NETSIGHT_SESSION_COOKIE_NAME",
    "NETSIGHT_SESSION_SAME_SITE",
)


@pytest.fixture(autouse=True)
def _reset_auth_singletons(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    import netsight_api.auth.pending as pending_module
    import netsight_api.auth.rate_limit as rate_limit_module
    import netsight_api.auth.session as session_module

    for name in CLEANUP_ENV:
        monkeypatch.delenv(name, raising=False)

    session_module.session_policy.cache_clear()
    session_module._manager = None
    pending_module._pending_store = pending_module.PendingAuthStore()
    rate_limit_module._limiter = rate_limit_module.RateLimiter()

    yield

    session_module._manager = None
    session_module.session_policy.cache_clear()


def _enable_microsoft(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_OIDC_MICROSOFT_ENABLED", "true")
    monkeypatch.setenv("NETSIGHT_OIDC_MICROSOFT_CLIENT_ID", "netsight-client")
    monkeypatch.setenv("NETSIGHT_OIDC_MICROSOFT_CLIENT_SECRET", "super-secret")
    monkeypatch.setenv(
        "NETSIGHT_OIDC_MICROSOFT_AUTHORITY",
        "https://login.microsoftonline.com/contoso.com/v2.0",
    )
    monkeypatch.setenv("NETSIGHT_PUBLIC_BASE_URL", "https://netsight.test")


def test_login_rejects_unknown_provider() -> None:
    client = TestClient(app)
    response = client.get("/auth/login/weird", follow_redirects=False)
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "PROVIDER_UNKNOWN"


def test_login_fails_closed_when_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = TestClient(app)
    response = client.get("/auth/login/microsoft", follow_redirects=False)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PROVIDER_NOT_CONFIGURED"


def test_login_redirects_to_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_microsoft(monkeypatch)

    async def fake_authorization_url(*_args: Any, **_kwargs: Any) -> str:
        return "https://provider.example/authorize?state=xyz"

    monkeypatch.setattr(
        "netsight_api.auth.routes.authorization_url", fake_authorization_url
    )

    client = TestClient(app, follow_redirects=False)
    response = client.get(
        "/auth/login/microsoft", params={"redirect_to": "/devices"}
    )
    assert response.status_code == 302
    assert response.headers["location"] == "https://provider.example/authorize?state=xyz"


def test_callback_requires_code_and_state() -> None:
    client = TestClient(app)
    response = client.get("/auth/callback", follow_redirects=False)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "AUTH_CALLBACK_INVALID"


def test_callback_rejects_unknown_state() -> None:
    client = TestClient(app)
    response = client.get(
        "/auth/callback",
        params={"code": "c", "state": "unknown"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "AUTH_STATE_INVALID"


def test_session_and_csrf_require_authentication() -> None:
    client = TestClient(app)
    assert client.get("/auth/session").status_code == 401
    assert client.get("/auth/csrf").status_code == 401


def test_logout_without_session_clears_cookie() -> None:
    client = TestClient(app, follow_redirects=False)
    response = client.post("/auth/logout")
    assert response.status_code == 302
    assert response.headers["location"] == "/login"


def test_full_login_session_logout_roundtrip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_microsoft(monkeypatch)
    monkeypatch.setenv("NETSIGHT_ROLE_MAPPING", "admin:administrator")
    captured: dict[str, str] = {}

    async def fake_authorization_url(
        provider: Any,
        settings: Any,
        redirect_uri: str,
        state: str,
        nonce: str,
        code_verifier: str,
    ) -> str:
        captured["state"] = state
        captured["nonce"] = nonce
        captured["code_verifier"] = code_verifier
        return "https://provider.example/authorize"

    async def fake_exchange_code(
        provider: Any,
        settings: Any,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> TokenResponse:
        assert code_verifier == captured["code_verifier"]
        return TokenResponse(
            id_token="signed-id-token",
            access_token=None,
            expires_in=None,
            token_type=None,
        )

    async def fake_validate_id_token(
        provider: Any,
        settings: Any,
        id_token: str,
        expected_nonce: str,
    ) -> VerifiedClaims:
        assert expected_nonce == captured["nonce"]
        return VerifiedClaims(
            subject="user-1",
            issuer="https://login.microsoftonline.com/contoso.com/v2.0",
            audience="netsight-client",
            email="user@contoso.com",
            raw={"sub": "user-1", "roles": ["admin"]},
        )

    monkeypatch.setattr(
        "netsight_api.auth.routes.authorization_url", fake_authorization_url
    )
    monkeypatch.setattr(
        "netsight_api.auth.routes.exchange_code", fake_exchange_code
    )
    monkeypatch.setattr(
        "netsight_api.auth.routes.validate_id_token", fake_validate_id_token
    )

    client = TestClient(
        app,
        base_url="https://netsight.test",
        follow_redirects=False,
    )

    login = client.get("/auth/login/microsoft")
    assert login.status_code == 302

    callback = client.get(
        "/auth/callback",
        params={"code": "auth-code", "state": captured["state"]},
    )
    assert callback.status_code == 302
    assert callback.headers["location"] == "/overview"
    assert callback.cookies.get("netsight_session")
    assert "Secure" in callback.headers["set-cookie"]

    session_response = client.get("/auth/session")
    assert session_response.status_code == 200
    session_body = session_response.json()
    assert session_body["authenticated"] is True
    assert session_body["identity_id"] == "microsoft:user-1"
    assert "administrator" in session_body["roles"]

    csrf_token = client.get("/auth/csrf").json()["csrf_token"]

    logout = client.post("/auth/logout", headers={"X-CSRF-Token": csrf_token})
    assert logout.status_code == 302
    assert logout.headers["location"] == "/login"

    assert client.get("/auth/session").status_code == 401


def test_logout_rejects_missing_csrf_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_microsoft(monkeypatch)
    captured: dict[str, str] = {}

    async def fake_authorization_url(
        _provider: Any,
        _settings: Any,
        _redirect_uri: str,
        state: str,
        _nonce: str,
        _code_verifier: str,
    ) -> str:
        captured["state"] = state
        return "https://provider.example/authorize"

    async def fake_exchange_code(*_args: Any, **_kwargs: Any) -> TokenResponse:
        return TokenResponse(
            id_token="t", access_token=None, expires_in=None, token_type=None
        )

    async def fake_validate_id_token(*_args: Any, **_kwargs: Any) -> VerifiedClaims:
        return VerifiedClaims(
            subject="user-1",
            issuer="https://login.microsoftonline.com/contoso.com/v2.0",
            audience="netsight-client",
            email=None,
            raw={"sub": "user-1"},
        )

    monkeypatch.setattr(
        "netsight_api.auth.routes.authorization_url", fake_authorization_url
    )
    monkeypatch.setattr(
        "netsight_api.auth.routes.exchange_code", fake_exchange_code
    )
    monkeypatch.setattr(
        "netsight_api.auth.routes.validate_id_token", fake_validate_id_token
    )

    client = TestClient(
        app,
        base_url="https://netsight.test",
        follow_redirects=False,
    )
    client.get("/auth/login/microsoft")
    client.get(
        "/auth/callback",
        params={"code": "c", "state": captured["state"]},
    )

    response = client.post("/auth/logout", headers={"X-CSRF-Token": "wrong"})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"


def test_providers_reports_unconfigured_by_default() -> None:
    client = TestClient(app)
    response = client.get("/auth/providers")
    assert response.status_code == 200
    body = response.json()
    assert body == {
        "providers": {
            "microsoft": {"configured": False},
            "google": {"configured": False},
            "clerk": {"configured": False},
        }
    }


def test_providers_reports_configured_state_without_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_microsoft(monkeypatch)
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_ENABLED", "true")
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_CLIENT_ID", "google-client")
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_CLIENT_SECRET", "google-secret")

    client = TestClient(app)
    response = client.get("/auth/providers")
    assert response.status_code == 200
    body = response.json()
    assert body["providers"]["microsoft"]["configured"] is True
    assert body["providers"]["google"]["configured"] is True
    # Secrets and allow-list values must never appear in the response.
    assert "secret" not in response.text.lower()
    assert "netsight-client" not in response.text
    assert "google-client" not in response.text


def test_providers_requires_enabled_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A client id alone is not enough: the provider must be explicitly enabled.
    monkeypatch.setenv("NETSIGHT_OIDC_MICROSOFT_CLIENT_ID", "netsight-client")
    monkeypatch.setenv("NETSIGHT_OIDC_MICROSOFT_CLIENT_SECRET", "super-secret")

    client = TestClient(app)
    response = client.get("/auth/providers")
    assert response.status_code == 200
    assert response.json()["providers"]["microsoft"]["configured"] is False
