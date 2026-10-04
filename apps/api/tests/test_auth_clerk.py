"""Clerk federated provider tests.

A Clerk instance may permit self-service sign-up, so these tests assert that
instance membership alone never grants access: the issuer must be the exact
configured instance, the identity must be on the Netsight allow-list, and an
unverified email is rejected.
"""

from __future__ import annotations

import base64
import time
from collections.abc import Iterator
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from netsight_api.auth import oidc
from netsight_api.auth.oidc import OidcError, validate_id_token
from netsight_api.auth.providers import CLERK
from netsight_api.auth.settings import ProviderSettings
from netsight_api.main import app

CLERK_AUTHORITY = "https://netsight-prod-42.clerk.accounts.dev"
OTHER_CLERK_AUTHORITY = "https://evil-tenant-99.clerk.accounts.dev"

CLEANUP_ENV = (
    "NETSIGHT_ENV",
    "NETSIGHT_ENABLE_DEV_IDENTITY",
    "NETSIGHT_PUBLIC_BASE_URL",
    "NETSIGHT_OIDC_CLERK_ENABLED",
    "NETSIGHT_OIDC_CLERK_CLIENT_ID",
    "NETSIGHT_OIDC_CLERK_CLIENT_SECRET",
    "NETSIGHT_OIDC_CLERK_AUTHORITY",
    "NETSIGHT_OIDC_CLERK_ALLOWED_IDENTITIES",
)


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in CLEANUP_ENV:
        monkeypatch.delenv(name, raising=False)
    oidc._metadata_cache.clear()
    oidc._jwks_cache.clear()
    yield
    oidc._metadata_cache.clear()
    oidc._jwks_cache.clear()


def _rsa_key_and_jwk() -> tuple[rsa.RSAPrivateKey, dict[str, Any]]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()

    def b64u_int(value: int) -> str:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    jwk = {
        "kty": "RSA",
        "kid": "test-key-1",
        "use": "sig",
        "alg": "RS256",
        "n": b64u_int(numbers.n),
        "e": b64u_int(numbers.e),
    }
    return private_key, jwk


def _settings(**overrides: Any) -> ProviderSettings:
    base: dict[str, Any] = {
        "enabled": True,
        "client_id": "netsight-client",
        "client_secret": "clerk-secret",
        "authority": CLERK_AUTHORITY,
        "allowed_identities": ["user_2approved"],
    }
    base.update(overrides)
    return ProviderSettings(**base)


def _token(
    monkeypatch: pytest.MonkeyPatch,
    settings: ProviderSettings,
    *,
    issuer: str,
    nonce: str = "n-1",
    subject: str = "user_2approved",
    email: str | None = "ops@example.test",
    email_verified: object = None,
    audience: str | None = None,
    expires_in: int = 300,
) -> str:
    private_key, jwk = _rsa_key_and_jwk()
    metadata = {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "jwks_uri": f"{issuer}/jwks",
    }

    async def fake_discover(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return metadata

    async def fake_jwks(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"keys": [jwk]}

    monkeypatch.setattr(oidc, "discover", fake_discover)
    monkeypatch.setattr(oidc, "_jwks", fake_jwks)

    now = int(time.time())
    payload: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "aud": audience or settings.client_id,
        "exp": now + expires_in,
        "iat": now,
        "nonce": nonce,
    }
    if email is not None:
        payload["email"] = email
    if email_verified is not None:
        payload["email_verified"] = email_verified
    return pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key-1"})


# --- issuer pinning -------------------------------------------------------


@pytest.mark.asyncio
async def test_clerk_accepts_the_configured_instance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    token = _token(monkeypatch, settings, issuer=CLERK_AUTHORITY)
    claims = await validate_id_token(CLERK, settings, token, "n-1")
    assert claims.issuer == CLERK_AUTHORITY
    assert claims.subject == "user_2approved"
    assert claims.email == "ops@example.test"


@pytest.mark.asyncio
async def test_clerk_rejects_a_token_from_another_instance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A different Clerk instance is a different security domain."""
    settings = _settings()
    token = _token(monkeypatch, settings, issuer=OTHER_CLERK_AUTHORITY)
    with pytest.raises(OidcError) as exc:
        await validate_id_token(CLERK, settings, token, "n-1")
    assert exc.value.code == "OIDC_ISSUER_INVALID"


@pytest.mark.asyncio
async def test_clerk_rejects_a_lookalike_issuer_substring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prefix/suffix tricks must not pass the exact-instance check."""
    settings = _settings()
    token = _token(
        monkeypatch,
        settings,
        issuer=f"{CLERK_AUTHORITY}.attacker.example",
    )
    with pytest.raises(OidcError) as exc:
        await validate_id_token(CLERK, settings, token, "n-1")
    assert exc.value.code == "OIDC_ISSUER_INVALID"


@pytest.mark.asyncio
async def test_clerk_rejects_a_foreign_issuer_entirely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Microsoft/Google token must not be accepted for Clerk."""
    settings = _settings()
    token = _token(monkeypatch, settings, issuer="https://accounts.google.com")
    with pytest.raises(OidcError) as exc:
        await validate_id_token(CLERK, settings, token, "n-1")
    assert exc.value.code == "OIDC_ISSUER_INVALID"


# --- identity allow-list --------------------------------------------------


@pytest.mark.asyncio
async def test_clerk_empty_allowlist_denies_every_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail closed: an unconfigured allow-list must not admit anyone."""
    settings = _settings(allowed_identities=[])
    token = _token(monkeypatch, settings, issuer=CLERK_AUTHORITY)
    with pytest.raises(OidcError) as exc:
        await validate_id_token(CLERK, settings, token, "n-1")
    assert exc.value.code == "OIDC_IDENTITY_NOT_ALLOWED"


@pytest.mark.asyncio
async def test_clerk_rejects_an_unapproved_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    token = _token(
        monkeypatch,
        settings,
        issuer=CLERK_AUTHORITY,
        subject="user_selfsigned",
        email="intruder@evil.example",
    )
    with pytest.raises(OidcError) as exc:
        await validate_id_token(CLERK, settings, token, "n-1")
    assert exc.value.code == "OIDC_IDENTITY_NOT_ALLOWED"


@pytest.mark.asyncio
async def test_clerk_accepts_an_allowlisted_email(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(allowed_identities=["ops@example.test"])
    token = _token(monkeypatch, settings, issuer=CLERK_AUTHORITY)
    claims = await validate_id_token(CLERK, settings, token, "n-1")
    assert claims.email == "ops@example.test"


@pytest.mark.asyncio
async def test_clerk_rejects_unverified_email(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    token = _token(
        monkeypatch,
        settings,
        issuer=CLERK_AUTHORITY,
        email_verified=False,
    )
    with pytest.raises(OidcError) as exc:
        await validate_id_token(CLERK, settings, token, "n-1")
    assert exc.value.code == "OIDC_EMAIL_NOT_VERIFIED"


# --- standard OIDC guarantees still apply ---------------------------------


@pytest.mark.asyncio
async def test_clerk_rejects_wrong_audience(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings()
    token = _token(
        monkeypatch,
        settings,
        issuer=CLERK_AUTHORITY,
        audience="some-other-app",
    )
    with pytest.raises(OidcError) as exc:
        await validate_id_token(CLERK, settings, token, "n-1")
    assert exc.value.code == "OIDC_AUDIENCE_INVALID"


@pytest.mark.asyncio
async def test_clerk_rejects_expired_token(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings()
    token = _token(monkeypatch, settings, issuer=CLERK_AUTHORITY, expires_in=-60)
    with pytest.raises(OidcError) as exc:
        await validate_id_token(CLERK, settings, token, "n-1")
    assert exc.value.code == "OIDC_TOKEN_EXPIRED"


@pytest.mark.asyncio
async def test_clerk_rejects_nonce_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings()
    token = _token(monkeypatch, settings, issuer=CLERK_AUTHORITY, nonce="other")
    with pytest.raises(OidcError) as exc:
        await validate_id_token(CLERK, settings, token, "n-1")
    assert exc.value.code == "OIDC_NONCE_INVALID"


# --- HTTP surface ---------------------------------------------------------


def test_clerk_login_fails_closed_when_unconfigured() -> None:
    response = TestClient(app).get("/auth/login/clerk", follow_redirects=False)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PROVIDER_NOT_CONFIGURED"


def test_clerk_is_reported_as_unconfigured_by_default() -> None:
    response = TestClient(app).get("/auth/providers")
    assert response.status_code == 200
    assert response.json()["providers"]["clerk"] == {"configured": False}


def test_clerk_configuration_state_is_reported_without_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NETSIGHT_OIDC_CLERK_ENABLED", "true")
    monkeypatch.setenv("NETSIGHT_OIDC_CLERK_CLIENT_ID", "netsight-client")
    monkeypatch.setenv("NETSIGHT_OIDC_CLERK_CLIENT_SECRET", "clerk-secret")
    monkeypatch.setenv("NETSIGHT_OIDC_CLERK_AUTHORITY", CLERK_AUTHORITY)
    monkeypatch.setenv("NETSIGHT_OIDC_CLERK_ALLOWED_IDENTITIES", "user_2approved")

    response = TestClient(app).get("/auth/providers")

    assert response.status_code == 200
    assert response.json()["providers"]["clerk"] == {"configured": True}
    body = response.text
    assert "clerk-secret" not in body
    assert CLERK_AUTHORITY not in body
    assert "user_2approved" not in body