"""A new sign-in revokes the session the browser presented; denied MFA is audited by fingerprint."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import pytest
from fastapi.testclient import TestClient
from test_auth_routes import (  # noqa: F401 -- the autouse fixture must be in scope here
    _mfa_claims,
    _reset_auth_singletons,
    _sign_in,
)

from netsight_api.auth.oidc import VerifiedClaims
from netsight_api.main import app


def _complete_sign_in(
    monkeypatch: pytest.MonkeyPatch, client: TestClient, raw: dict[str, Any]
) -> None:
    """Sign in again on an existing client (it keeps the cookie it already holds)."""
    captured: dict[str, str] = {}

    async def fake_authorization_url(
        _p: Any, _s: Any, _r: str, state: str, _n: str, _v: str, step_up: bool = False
    ) -> str:
        captured["state"] = state
        return "https://provider.example/authorize"

    async def fake_validate_id_token(*_args: Any, **_kwargs: Any) -> VerifiedClaims:
        return VerifiedClaims(subject="user-1", issuer="i", audience="a", email=None, raw=raw)

    monkeypatch.setattr("netsight_api.auth.routes.authorization_url", fake_authorization_url)
    monkeypatch.setattr("netsight_api.auth.routes.validate_id_token", fake_validate_id_token)
    client.get("/api/v1/auth/login/microsoft")
    client.get("/api/v1/auth/callback", params={"code": "c", "state": captured["state"]})


def test_signing_in_again_revokes_the_session_the_browser_presented(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from netsight_api.auth.session import session_manager

    raw = {"sub": "user-1", "roles": ["admin"]}
    client = _sign_in(monkeypatch, raw)
    manager = session_manager()
    old_cookie = client.cookies.get(manager.policy.cookie_name)
    assert manager.validate_cookie(old_cookie) is not None

    _complete_sign_in(monkeypatch, client, raw)

    new_cookie = client.cookies.get(manager.policy.cookie_name)
    assert new_cookie != old_cookie
    assert manager.validate_cookie(old_cookie) is None
    assert manager.validate_cookie(new_cookie) is not None


def test_a_forged_cookie_at_sign_in_revokes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    from netsight_api.auth.session import session_manager

    raw = {"sub": "user-2", "roles": ["admin"]}
    other = _sign_in(monkeypatch, raw)
    manager = session_manager()
    assert manager.validate_cookie(other.cookies.get(manager.policy.cookie_name)) is not None

    attacker = TestClient(app, base_url="https://netsight.test", follow_redirects=False)
    attacker.cookies.set(manager.policy.cookie_name, "not-a-valid-cookie")
    _complete_sign_in(monkeypatch, attacker, raw)

    assert manager.validate_cookie(other.cookies.get(manager.policy.cookie_name)) is not None


def test_a_denied_mfa_audit_carries_a_fingerprint_of_the_identity_not_the_identity(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from netsight_api.audit import fingerprint

    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        _sign_in(monkeypatch, _mfa_claims(auth_time=time.time() - 3600))
    records = [json.loads(r.getMessage()) for r in caplog.records if r.name == "netsight_api.audit"]
    denied = [r for r in records if r["action"] == "auth.mfa"]
    assert [r["identity_fingerprint"] for r in denied] == [fingerprint("microsoft:user-1")]
    assert "user-1" not in json.dumps(denied)
