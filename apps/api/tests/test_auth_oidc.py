"""OIDC PKCE, issuer/allow-list and id_token validation tests."""

from __future__ import annotations

import base64
import time
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from netsight_api.auth import oidc
from netsight_api.auth.oidc import (
    OidcError,
    _validate_google_allowlist,
    _validate_issuer,
    code_challenge,
    generate_code_verifier,
    generate_nonce,
    generate_state,
    validate_id_token,
)
from netsight_api.auth.providers import GOOGLE, MICROSOFT
from netsight_api.auth.settings import ProviderSettings

# RFC 7636 Appendix B known-answer vector.
RFC7636_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
RFC7636_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_code_challenge_known_vector() -> None:
    assert code_challenge(RFC7636_VERIFIER) == RFC7636_CHALLENGE


def test_generators_are_unique_and_sized() -> None:
    states = {generate_state() for _ in range(12)}
    nonces = {generate_nonce() for _ in range(12)}
    verifiers = {generate_code_verifier() for _ in range(12)}

    assert len(states) == 12
    assert len(nonces) == 12
    assert len(verifiers) == 12
    for verifier in verifiers:
        assert 43 <= len(verifier) <= 128


def test_validate_issuer_microsoft_allowed_tenant() -> None:
    settings = ProviderSettings(tenant_ids=["contoso.com"])
    issuer = "https://login.microsoftonline.com/contoso.com/v2.0"
    assert _validate_issuer(MICROSOFT, issuer, settings) == issuer


def test_validate_issuer_microsoft_disallowed_tenant() -> None:
    settings = ProviderSettings(tenant_ids=["contoso.com"])
    with pytest.raises(OidcError):
        _validate_issuer(MICROSOFT, "https://login.microsoftonline.com/evil.com/v2.0", settings)


def test_validate_issuer_microsoft_wrong_cloud() -> None:
    settings = ProviderSettings(tenant_ids=["contoso.com"])
    with pytest.raises(OidcError):
        _validate_issuer(MICROSOFT, "https://login.microsoftonline.us/contoso.com/v2.0", settings)


def test_validate_issuer_microsoft_missing_tenant_allowlist_is_denied() -> None:
    settings = ProviderSettings(tenant_ids=[])
    issuer = "https://login.microsoftonline.com/any-tenant/v2.0"
    with pytest.raises(OidcError) as exc_info:
        _validate_issuer(MICROSOFT, issuer, settings)
    assert exc_info.value.code == "OIDC_TENANT_NOT_ALLOWED"


def test_validate_issuer_google_exact() -> None:
    settings = ProviderSettings()
    assert _validate_issuer(GOOGLE, "https://accounts.google.com", settings) == (
        "https://accounts.google.com"
    )
    with pytest.raises(OidcError):
        _validate_issuer(GOOGLE, "https://accounts.google.co.uk", settings)


def test_validate_issuer_rejects_non_string() -> None:
    with pytest.raises(OidcError):
        _validate_issuer(MICROSOFT, None, ProviderSettings())  # type: ignore[arg-type]


def test_google_domain_allowlist() -> None:
    settings = ProviderSettings(hosted_domains=["example.com"])
    _validate_google_allowlist(
        {"hd": "example.com", "sub": "1", "email": "a@example.com"}, settings
    )
    with pytest.raises(OidcError):
        _validate_google_allowlist({"hd": "evil.com", "sub": "1"}, settings)


def test_google_identity_allowlist() -> None:
    settings = ProviderSettings(allowed_identities=["approved@example.com"])
    _validate_google_allowlist({"sub": "1", "email": "approved@example.com"}, settings)
    with pytest.raises(OidcError):
        _validate_google_allowlist({"sub": "2", "email": "other@example.com"}, settings)


def test_google_missing_domain_and_identity_allowlists_is_denied() -> None:
    settings = ProviderSettings(hosted_domains=[], allowed_identities=[])
    with pytest.raises(OidcError) as exc_info:
        _validate_google_allowlist(
            {"hd": "example.com", "sub": "1", "email": "a@example.com"},
            settings,
        )
    assert exc_info.value.code == "OIDC_IDENTITY_NOT_ALLOWED"


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


def _encode(private_key: rsa.RSAPrivateKey, claims: dict[str, Any]) -> str:
    return pyjwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-key-1"})


@pytest.fixture
def provider_stubs(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    private_key, jwk = _rsa_key_and_jwk()
    metadata = {
        "authorization_endpoint": "https://provider.example/authorize",
        "token_endpoint": "https://provider.example/token",
        "jwks_uri": "https://provider.example/jwks",
    }

    async def fake_discover(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return metadata

    async def fake_jwks(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"keys": [jwk]}

    monkeypatch.setattr(oidc, "discover", fake_discover)
    monkeypatch.setattr(oidc, "_jwks", fake_jwks)
    return {"private_key": private_key, "jwk": jwk, "metadata": metadata}


@pytest.mark.asyncio
async def test_validate_id_token_accepts_valid_token(
    monkeypatch: pytest.MonkeyPatch, provider_stubs: dict[str, Any]
) -> None:
    private_key = provider_stubs["private_key"]
    settings = ProviderSettings(client_id="netsight-client", tenant_ids=["contoso.com"])
    now = int(time.time())
    claims = {
        "iss": "https://login.microsoftonline.com/contoso.com/v2.0",
        "aud": "netsight-client",
        "sub": "user-123",
        "email": "user@contoso.com",
        "iat": now,
        "exp": now + 300,
        "nonce": "expected-nonce",
    }
    token = _encode(private_key, claims)

    verified = await validate_id_token(MICROSOFT, settings, token, "expected-nonce")
    assert verified.subject == "user-123"
    assert verified.email == "user@contoso.com"
    assert verified.audience == "netsight-client"


@pytest.mark.asyncio
async def test_validate_id_token_rejects_wrong_audience(
    monkeypatch: pytest.MonkeyPatch, provider_stubs: dict[str, Any]
) -> None:
    private_key = provider_stubs["private_key"]
    settings = ProviderSettings(client_id="netsight-client", tenant_ids=["contoso.com"])
    now = int(time.time())
    claims = {
        "iss": "https://login.microsoftonline.com/contoso.com/v2.0",
        "aud": "other-client",
        "sub": "user-123",
        "iat": now,
        "exp": now + 300,
        "nonce": "expected-nonce",
    }
    token = _encode(private_key, claims)

    with pytest.raises(OidcError) as excinfo:
        await validate_id_token(MICROSOFT, settings, token, "expected-nonce")
    assert excinfo.value.code == "OIDC_AUDIENCE_INVALID"


@pytest.mark.asyncio
async def test_validate_id_token_rejects_expired(
    monkeypatch: pytest.MonkeyPatch, provider_stubs: dict[str, Any]
) -> None:
    private_key = provider_stubs["private_key"]
    settings = ProviderSettings(client_id="netsight-client", tenant_ids=["contoso.com"])
    now = int(time.time())
    claims = {
        "iss": "https://login.microsoftonline.com/contoso.com/v2.0",
        "aud": "netsight-client",
        "sub": "user-123",
        "iat": now - 400,
        "exp": now - 100,
        "nonce": "expected-nonce",
    }
    token = _encode(private_key, claims)

    with pytest.raises(OidcError) as excinfo:
        await validate_id_token(MICROSOFT, settings, token, "expected-nonce")
    assert excinfo.value.code == "OIDC_TOKEN_EXPIRED"


@pytest.mark.asyncio
async def test_validate_id_token_rejects_wrong_nonce(
    monkeypatch: pytest.MonkeyPatch, provider_stubs: dict[str, Any]
) -> None:
    private_key = provider_stubs["private_key"]
    settings = ProviderSettings(client_id="netsight-client", tenant_ids=["contoso.com"])
    now = int(time.time())
    claims = {
        "iss": "https://login.microsoftonline.com/contoso.com/v2.0",
        "aud": "netsight-client",
        "sub": "user-123",
        "iat": now,
        "exp": now + 300,
        "nonce": "attacker-nonce",
    }
    token = _encode(private_key, claims)

    with pytest.raises(OidcError) as excinfo:
        await validate_id_token(MICROSOFT, settings, token, "expected-nonce")
    assert excinfo.value.code == "OIDC_NONCE_INVALID"


@pytest.mark.asyncio
async def test_validate_id_token_rejects_disallowed_tenant(
    monkeypatch: pytest.MonkeyPatch, provider_stubs: dict[str, Any]
) -> None:
    private_key = provider_stubs["private_key"]
    settings = ProviderSettings(client_id="netsight-client", tenant_ids=["contoso.com"])
    now = int(time.time())
    claims = {
        "iss": "https://login.microsoftonline.com/evil.com/v2.0",
        "aud": "netsight-client",
        "sub": "user-123",
        "iat": now,
        "exp": now + 300,
        "nonce": "expected-nonce",
    }
    token = _encode(private_key, claims)

    with pytest.raises(OidcError) as excinfo:
        await validate_id_token(MICROSOFT, settings, token, "expected-nonce")
    assert excinfo.value.code == "OIDC_TENANT_NOT_ALLOWED"


@pytest.mark.asyncio
async def test_validate_id_token_rejects_bad_signature(
    monkeypatch: pytest.MonkeyPatch, provider_stubs: dict[str, Any]
) -> None:
    # Sign with a key that is not in the published JWKS.
    rogue_key, _ = _rsa_key_and_jwk()
    settings = ProviderSettings(client_id="netsight-client", tenant_ids=["contoso.com"])
    now = int(time.time())
    claims = {
        "iss": "https://login.microsoftonline.com/contoso.com/v2.0",
        "aud": "netsight-client",
        "sub": "user-123",
        "iat": now,
        "exp": now + 300,
        "nonce": "expected-nonce",
    }
    token = _encode(rogue_key, claims)

    with pytest.raises(OidcError) as excinfo:
        await validate_id_token(MICROSOFT, settings, token, "expected-nonce")
    assert excinfo.value.code in {"OIDC_KID_NOT_FOUND", "OIDC_TOKEN_INVALID"}


@pytest.mark.asyncio
async def test_validate_id_token_rejects_unsupported_algorithm(
    monkeypatch: pytest.MonkeyPatch, provider_stubs: dict[str, Any]
) -> None:
    settings = ProviderSettings(client_id="netsight-client", tenant_ids=["contoso.com"])
    now = int(time.time())
    claims = {
        "iss": "https://login.microsoftonline.com/contoso.com/v2.0",
        "aud": "netsight-client",
        "sub": "user-123",
        "iat": now,
        "exp": now + 300,
        "nonce": "expected-nonce",
    }
    token = pyjwt.encode(claims, "hmac-secret", algorithm="HS256", headers={"kid": "test-key-1"})

    with pytest.raises(OidcError) as excinfo:
        await validate_id_token(MICROSOFT, settings, token, "expected-nonce")
    assert excinfo.value.code == "OIDC_ALG_UNSUPPORTED"


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", [MICROSOFT, GOOGLE])
async def test_authorization_url_asks_the_provider_to_choose_an_account_by_default(
    provider_stubs: dict[str, Any], provider: Any
) -> None:
    from urllib.parse import parse_qs, urlsplit

    url = await oidc.authorization_url(
        provider, ProviderSettings(client_id="c"), "https://app/cb", "s", "n", "v" * 43
    )
    query = parse_qs(urlsplit(url).query)
    assert query["prompt"] == ["select_account"]
    assert "max_age" not in query


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", [MICROSOFT, GOOGLE])
async def test_a_step_up_authorization_forces_a_fresh_interactive_sign_in(
    provider_stubs: dict[str, Any], provider: Any
) -> None:
    from urllib.parse import parse_qs, urlsplit

    url = await oidc.authorization_url(
        provider,
        ProviderSettings(client_id="c"),
        "https://app/cb",
        "s",
        "n",
        "v" * 43,
        step_up=True,
    )
    query = parse_qs(urlsplit(url).query)
    assert query["prompt"] == ["login"]
    assert query["max_age"] == ["0"]
    assert query["code_challenge_method"] == ["S256"]  # the rest of the request is unchanged
