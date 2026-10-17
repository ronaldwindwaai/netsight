"""Security regression gates for the PyJWT minimum and custom JWKS client."""
from __future__ import annotations

import time
from typing import Any

import httpx
import pytest
from test_auth_oidc import _encode, _rsa_key_and_jwk

from netsight_api.auth import oidc
from netsight_api.auth.providers import GOOGLE, MICROSOFT
from netsight_api.auth.settings import ProviderSettings


@pytest.fixture
def provider_stubs(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    private_key, jwk = _rsa_key_and_jwk()

    async def metadata(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {"jwks_uri": "https://www.googleapis.com/keys"}

    async def keys(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {"keys": [jwk]}

    monkeypatch.setattr(oidc, "discover", metadata)
    monkeypatch.setattr(oidc, "_jwks", keys)
    return {"private_key": private_key}


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["iss", "aud", "sub", "exp", "iat", "nonce"])
async def test_required_claims_fail_closed(
    provider_stubs: dict[str, Any], missing: str,
) -> None:
    claims = {
        "iss": "https://accounts.google.com", "aud": "client", "sub": "user",
        "iat": int(time.time()), "exp": int(time.time()) + 300,
        "nonce": "nonce", "hd": "example.com",
    }
    del claims[missing]
    token = _encode(provider_stubs["private_key"], claims)
    with pytest.raises(oidc.OidcError, match="signature or claims"):
        await oidc.validate_id_token(
            GOOGLE, ProviderSettings(client_id="client", hosted_domains=["example.com"]),
            token, "nonce",
        )


@pytest.mark.parametrize("suffix", ["/v2.0/extra", "/v1.0", "/v2.0?x=1", ""])
def test_entra_issuer_must_match_exactly(suffix: str) -> None:
    with pytest.raises(oidc.OidcError):
        oidc._validate_issuer(
            MICROSOFT, f"https://login.microsoftonline.com/tenant{suffix}",
            ProviderSettings(tenant_ids=["tenant"]),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("token", ["broken", "x" * 32769, "e30.e30.invalid"])
async def test_malformed_token_rejected_without_network(token: str) -> None:
    with pytest.raises(oidc.OidcError):
        await oidc.validate_id_token(GOOGLE, ProviderSettings(), token, "nonce")


@pytest.mark.asyncio
@pytest.mark.parametrize("uri", [
    "http://www.googleapis.com/keys", "https://127.0.0.1/keys",
    "https://www.googleapis.com.attacker.example/keys",
    "https://user:password@www.googleapis.com/keys",
    "https://www.googleapis.com:8443/keys", "https://www.googleapis.com/keys#fragment",
])
async def test_untrusted_jwks_uri_rejected_without_network(uri: str) -> None:
    with pytest.raises(oidc.OidcError):
        await oidc._jwks({"jwks_uri": uri})


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [{}, {"keys": []}, {"keys": [None]}, {"keys": [{}] * 101}])
async def test_malformed_jwks_not_cached(
    monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any],
) -> None:
    oidc._jwks_cache.clear()
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json=payload)
    )) as client:
        monkeypatch.setattr(oidc, "_http", lambda: client)
        with pytest.raises(oidc.OidcError):
            await oidc._jwks({"jwks_uri": "https://www.googleapis.com/keys"})
    assert not oidc._jwks_cache


@pytest.mark.asyncio
async def test_jwks_redirect_is_not_followed(monkeypatch: pytest.MonkeyPatch) -> None:
    oidc._jwks_cache.clear()
    requests: list[str] = []

    def response(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://127.0.0.1/private"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        monkeypatch.setattr(oidc, "_http", lambda: client)
        with pytest.raises(oidc.OidcError):
            await oidc._jwks({"jwks_uri": "https://www.googleapis.com/keys"})
    assert requests == ["https://www.googleapis.com/keys"]
    assert not oidc._jwks_cache


@pytest.mark.asyncio
async def test_valid_google_token_with_trailing_padding(provider_stubs: dict[str, Any]) -> None:
    token = _encode(provider_stubs["private_key"], {
        "iss": "https://accounts.google.com", "aud": "client", "sub": "user",
        "iat": int(time.time()), "exp": int(time.time()) + 300,
        "nonce": "nonce", "hd": "example.com",
    })
    token += "=" * (-len(token.rsplit(".", 1)[1]) % 4)
    result = await oidc.validate_id_token(
        GOOGLE, ProviderSettings(client_id="client", hosted_domains=["example.com"]),
        token, "nonce",
    )
    assert result.subject == "user"


@pytest.mark.asyncio
async def test_jwks_size_limit_and_cache_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    oidc._jwks_cache.clear()
    uri = "https://www.googleapis.com/keys"
    responses = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal responses
        responses += 1
        if responses == 1:
            return httpx.Response(200, json={"keys": [{"kid": "current"}]})
        return httpx.Response(200, content=b" " * 262145)

    try:
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            monkeypatch.setattr(oidc, "_http", lambda: client)
            first = await oidc._jwks({"jwks_uri": uri})
            assert await oidc._jwks({"jwks_uri": uri}) == first
            assert responses == 1
            oidc._jwks_cache[uri] = (time.monotonic() - oidc.JWKS_TTL_SECONDS - 1, first)
            with pytest.raises(oidc.OidcError, match="size limit"):
                await oidc._jwks({"jwks_uri": uri})
            assert responses == 2
    finally:
        oidc._jwks_cache.clear()


@pytest.mark.asyncio
async def test_malformed_signing_key_is_a_controlled_rejection(
    monkeypatch: pytest.MonkeyPatch, provider_stubs: dict[str, Any],
) -> None:
    async def invalid_keys(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {"keys": [{"kid": "test-key-1", "kty": "RSA"}]}

    monkeypatch.setattr(oidc, "_jwks", invalid_keys)
    token = _encode(provider_stubs["private_key"], {
        "iss": "https://accounts.google.com", "aud": "client", "sub": "user",
        "iat": int(time.time()), "exp": int(time.time()) + 300, "nonce": "nonce",
    })
    with pytest.raises(oidc.OidcError, match="signature or claims"):
        await oidc.validate_id_token(GOOGLE, ProviderSettings(client_id="client"), token, "nonce")
