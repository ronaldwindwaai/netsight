"""Authentication endpoint tests (login, callback, session, logout)."""

from __future__ import annotations

import time
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
    response = client.get("/api/v1/auth/login/weird", follow_redirects=False)
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "PROVIDER_UNKNOWN"


def test_login_fails_closed_when_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = TestClient(app)
    response = client.get("/api/v1/auth/login/microsoft", follow_redirects=False)
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
        "/api/v1/auth/login/microsoft", params={"redirect_to": "/devices"}
    )
    assert response.status_code == 302
    assert response.headers["location"] == "https://provider.example/authorize?state=xyz"


def test_callback_requires_code_and_state() -> None:
    client = TestClient(app)
    response = client.get("/api/v1/auth/callback", follow_redirects=False)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "AUTH_CALLBACK_INVALID"


def test_callback_rejects_unknown_state() -> None:
    client = TestClient(app)
    response = client.get(
        "/api/v1/auth/callback",
        params={"code": "c", "state": "unknown"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "AUTH_STATE_INVALID"


def test_session_and_csrf_require_authentication() -> None:
    client = TestClient(app)
    assert client.get("/api/v1/auth/session").status_code == 401
    assert client.get("/api/v1/auth/csrf").status_code == 401


def test_logout_without_session_clears_cookie() -> None:
    client = TestClient(app, follow_redirects=False)
    response = client.post("/api/v1/auth/logout")
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
        step_up: bool = False,
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

    login = client.get("/api/v1/auth/login/microsoft")
    assert login.status_code == 302

    callback = client.get(
        "/api/v1/auth/callback",
        params={"code": "auth-code", "state": captured["state"]},
    )
    assert callback.status_code == 302
    assert callback.headers["location"] == "/overview"
    assert callback.cookies.get("netsight_session")
    assert "Secure" in callback.headers["set-cookie"]

    session_response = client.get("/api/v1/auth/session")
    assert session_response.status_code == 200
    session_body = session_response.json()
    assert session_body["authenticated"] is True
    assert session_body["identity_id"] == "microsoft:user-1"
    assert "administrator" in session_body["roles"]

    csrf_token = client.get("/api/v1/auth/csrf").json()["csrf_token"]

    logout = client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf_token})
    assert logout.status_code == 302
    assert logout.headers["location"] == "/login"

    assert client.get("/api/v1/auth/session").status_code == 401


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
        step_up: bool = False,
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
    client.get("/api/v1/auth/login/microsoft")
    client.get(
        "/api/v1/auth/callback",
        params={"code": "c", "state": captured["state"]},
    )

    response = client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": "wrong"})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"


def test_auth_is_served_only_under_the_versioned_prefix() -> None:
    """Guard the mount point the web server components depend on.

    The dashboard layout and landing page read the session through
    `/api/v1/auth/session`. Authentication was briefly mounted unversioned,
    which returned 404 and left the UI signed out after a successful sign-in.
    """

    client = TestClient(app)

    assert client.get("/api/v1/auth/providers").status_code == 200
    assert client.get("/auth/providers").status_code == 404


def test_providers_reports_unconfigured_by_default() -> None:
    client = TestClient(app)
    response = client.get("/api/v1/auth/providers")
    assert response.status_code == 200
    body = response.json()
    assert body == {
        "providers": {
            "microsoft": {"configured": False},
            "google": {"configured": False},
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
    response = client.get("/api/v1/auth/providers")
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
    response = client.get("/api/v1/auth/providers")
    assert response.status_code == 200
    assert response.json()["providers"]["microsoft"]["configured"] is False


# --- MFA recency stamp (step-up) ---------------------------------------------------------


@pytest.mark.parametrize(
    ("claims", "expected"),
    [
        ({"amr": ["pwd", "mfa"]}, True),
        ({"amr": ["MFA"]}, True),
        ({"amr": "mfa"}, True),
        ({"amr": ["pwd"]}, False),
        ({"amr": []}, False),
        ({"amr": None}, False),
        ({"amr": 1}, False),
        ({"amr": [["mfa"]]}, False),
        ({"amr": ["mfa-ish"]}, False),
        ({}, False),
        ({"acr": "mfa"}, False),
    ],
)
def test_only_an_explicit_amr_mfa_claim_counts_as_mfa(
    claims: dict[str, Any], expected: bool
) -> None:
    from netsight_api.auth.identity import mfa_asserted

    assert mfa_asserted(claims) is expected


def _sign_in(
    monkeypatch: pytest.MonkeyPatch, raw: dict[str, Any], login_query: str = ""
) -> TestClient:
    _enable_microsoft(monkeypatch)
    monkeypatch.setenv("NETSIGHT_ROLE_MAPPING", "admin:administrator")
    captured: dict[str, str] = {}

    async def fake_authorization_url(
        provider: Any,
        settings: Any,
        redirect_uri: str,
        state: str,
        nonce: str,
        verifier: str,
        step_up: bool = False,
    ) -> str:
        captured["state"] = state
        return "https://provider.example/authorize"

    async def fake_exchange_code(*_args: Any, **_kwargs: Any) -> TokenResponse:
        return TokenResponse(id_token="t", access_token=None, expires_in=None, token_type=None)

    async def fake_validate_id_token(*_args: Any, **_kwargs: Any) -> VerifiedClaims:
        return VerifiedClaims(
            subject="user-1", issuer="i", audience="a", email="u@contoso.com", raw=raw
        )

    monkeypatch.setattr("netsight_api.auth.routes.authorization_url", fake_authorization_url)
    monkeypatch.setattr("netsight_api.auth.routes.exchange_code", fake_exchange_code)
    monkeypatch.setattr("netsight_api.auth.routes.validate_id_token", fake_validate_id_token)
    client = TestClient(app, base_url="https://netsight.test", follow_redirects=False)
    client.get(f"/api/v1/auth/login/microsoft{login_query}")
    client.get("/api/v1/auth/callback", params={"code": "c", "state": captured["state"]})
    return client


def _stored_session(client: TestClient) -> Any:
    from netsight_api.auth.session import session_manager

    manager = session_manager()
    return manager.validate_cookie(client.cookies.get(manager.policy.cookie_name))


def test_an_oidc_sign_in_that_asserts_mfa_is_stamped(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = {"sub": "user-1", "roles": ["admin"], "amr": ["pwd", "mfa"], "auth_time": time.time() - 30}
    client = _sign_in(monkeypatch, raw)
    from netsight_api.auth.session import session_manager

    age = session_manager().mfa_age(_stored_session(client))
    # The stamp is the token's own auth_time on the store clock, not the session creation time.
    assert age is not None
    assert 29 <= age < 40


def test_an_oidc_sign_in_without_an_mfa_claim_is_not_stamped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _sign_in(monkeypatch, {"sub": "user-1", "roles": ["admin"]})
    assert _stored_session(client).mfa_verified_at is None


def test_session_info_lists_the_permissions_the_identity_holds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _sign_in(monkeypatch, {"sub": "user-1", "roles": ["admin"]})
    body = client.get("/api/v1/auth/session").json()
    assert body["permissions"] == sorted(body["permissions"])
    assert "incidents:resolve" in body["permissions"]
    assert "incidents:read" in body["permissions"]
    # Never a secret or token, only permission names.
    assert set(body) == {"authenticated", "identity_id", "provider", "email", "roles", "permissions"}


def test_management_session_lists_the_summary_permission_and_not_the_full_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NETSIGHT_DEFAULT_ROLE", "management")
    client = _sign_in(monkeypatch, {"sub": "user-1", "roles": ["unmapped"]})
    permissions = client.get("/api/v1/auth/session").json()["permissions"]
    assert "incidents:read-summary" in permissions
    assert "incidents:read" not in permissions
    assert not any(p.startswith("alert-rules:") for p in permissions)


@pytest.mark.parametrize(
    ("query", "expected"),
    [("", False), ("?step_up=true", True), ("?step_up=false", False)],
)
def test_login_passes_the_step_up_request_to_the_provider(
    monkeypatch: pytest.MonkeyPatch, query: str, expected: bool
) -> None:
    _enable_microsoft(monkeypatch)
    seen: dict[str, Any] = {}

    async def fake_authorization_url(*_args: Any, **kwargs: Any) -> str:
        seen.update(kwargs)
        return "https://provider.example/authorize"

    monkeypatch.setattr("netsight_api.auth.routes.authorization_url", fake_authorization_url)
    response = TestClient(app, follow_redirects=False).get(f"/api/v1/auth/login/microsoft{query}")
    assert response.status_code == 302
    assert seen["step_up"] is expected


def test_login_rejects_a_malformed_step_up_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_microsoft(monkeypatch)
    response = TestClient(app, follow_redirects=False).get(
        "/api/v1/auth/login/microsoft?step_up=maybe"
    )
    assert response.status_code == 422


def _mfa_claims(**extra: Any) -> dict[str, Any]:
    return {"sub": "user-1", "roles": ["admin"], "amr": ["pwd", "mfa"], **extra}


@pytest.mark.parametrize(
    ("extra", "reason"),
    [
        ({}, "auth-time-missing"),
        ({"auth_time": None}, "auth-time-missing"),
        ({"auth_time": "yesterday"}, "auth-time-invalid"),
        ({"auth_time": True}, "auth-time-invalid"),
        ({"auth_time": float("nan")}, "auth-time-invalid"),
        ({"auth_time": [1]}, "auth-time-invalid"),
        ({"auth_time": time.time() - 3600}, "auth-time-stale"),
        ({"auth_time": time.time() + 3600}, "auth-time-future"),
    ],
)
def test_an_mfa_assertion_without_a_usable_fresh_auth_time_is_not_verified(
    monkeypatch: pytest.MonkeyPatch, extra: dict[str, Any], reason: str, caplog: pytest.LogCaptureFixture
) -> None:
    import json
    import logging

    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        client = _sign_in(monkeypatch, _mfa_claims(**extra))
    assert client.get("/api/v1/auth/session").status_code == 200  # still signed in
    assert _stored_session(client).mfa_verified_at is None
    records = [json.loads(r.getMessage()) for r in caplog.records if r.name == "netsight_api.audit"]
    assert [r["reason"] for r in records if r["action"] == "auth.mfa"] == [reason]


def test_a_small_clock_skew_in_the_future_is_tolerated(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _sign_in(monkeypatch, _mfa_claims(auth_time=time.time() + 2))
    assert _stored_session(client).mfa_verified_at is not None


def test_the_window_follows_the_configured_step_up_max_age(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_STEP_UP_MAX_AGE_SECONDS", "60")
    stale = _sign_in(monkeypatch, _mfa_claims(auth_time=time.time() - 120))
    assert _stored_session(stale).mfa_verified_at is None


def test_a_step_up_must_authenticate_after_it_was_requested(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import json
    import logging

    # Fresh enough for the window, but older than the step-up request: a replayed token.
    replay = _mfa_claims(auth_time=time.time() - 30)
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        client = _sign_in(monkeypatch, replay, "?step_up=true")
    assert _stored_session(client).mfa_verified_at is None
    records = [json.loads(r.getMessage()) for r in caplog.records if r.name == "netsight_api.audit"]
    assert [r["reason"] for r in records if r["action"] == "auth.mfa"] == ["step-up-replay"]


def test_a_step_up_with_a_token_minted_after_the_request_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Later(dict):  # type: ignore[type-arg]
        """Claims whose auth_time is read after the login request, as a real IdP's would be."""

        def get(self, key: str, default: Any = None) -> Any:
            return time.time() if key == "auth_time" else super().get(key, default)

    client = _sign_in(monkeypatch, Later(_mfa_claims(auth_time=0)), "?step_up=true")
    assert _stored_session(client).mfa_verified_at is not None
