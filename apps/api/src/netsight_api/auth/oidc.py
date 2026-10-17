"""OpenID Connect client (Authorization Code flow with PKCE).

Implements only the parts Netsight needs and validates every claim the
security specification requires: signature (via provider JWKS), issuer,
audience, expiry, nonce, and the provider-specific allow-lists
(Microsoft tenant IDs, Google hosted domains / approved identities).

Telemetry and provider responses are treated as untrusted data.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx
import jwt
from jwt.algorithms import ECAlgorithm, OKPAlgorithm, RSAAlgorithm

from netsight_api.auth.providers import GOOGLE, MICROSOFT, ProviderId
from netsight_api.auth.settings import ProviderSettings

HTTP_TIMEOUT = httpx.Timeout(15.0, connect=10.0)
METADATA_TTL_SECONDS = 3600.0
JWKS_TTL_SECONDS = 3600.0
MAX_ID_TOKEN_BYTES = 32_768
# Only the approved providers may supply signing keys. Never follow a JWKS
# redirect into an internal service or a host supplied by an untrusted token.
JWKS_HOSTS = frozenset({
    "login.microsoftonline.com", "www.googleapis.com", "oauth2.googleapis.com",
    "accounts.google.com",
})


class OidcError(Exception):
    """Raised when an OIDC step fails or a claim is rejected."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class TokenResponse:
    id_token: str
    access_token: str | None
    expires_in: int | None
    token_type: str | None


@dataclass(frozen=True)
class VerifiedClaims:
    subject: str
    issuer: str
    audience: str
    email: str | None
    raw: dict[str, Any]


_client: httpx.AsyncClient | None = None
_metadata_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_jwks_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def _http() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=False)
    return _client


async def aclose() -> None:
    global _client
    if _client is not None and not _client.is_closed:
        await _client.aclose()
    _client = None


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_state() -> str:
    return secrets.token_urlsafe(32)


def generate_nonce() -> str:
    return secrets.token_urlsafe(32)


def generate_code_verifier() -> str:
    # 43-128 characters per RFC 7636.
    return _b64url(secrets.token_bytes(48))


def code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return _b64url(digest)


def _metadata_url(provider: ProviderId, authority: str) -> str:
    base = authority.rstrip("/")
    return f"{base}/.well-known/openid-configuration"


async def discover(provider: ProviderId, settings: ProviderSettings) -> dict[str, Any]:
    if not settings.authority:
        raise OidcError("OIDC_NOT_CONFIGURED", f"{provider.value} authority is not configured")

    url = _metadata_url(provider, settings.authority)
    cached = _metadata_cache.get(url)
    now = time.monotonic()
    if cached is not None and now - cached[0] < METADATA_TTL_SECONDS:
        return cached[1]

    try:
        response = await _http().get(url)
        response.raise_for_status()
        metadata = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OidcError("OIDC_DISCOVERY_FAILED", "Identity provider discovery failed") from exc

    if not isinstance(metadata, dict) or "authorization_endpoint" not in metadata:
        raise OidcError("OIDC_DISCOVERY_INVALID", "Identity provider metadata was invalid")

    _metadata_cache[url] = (now, metadata)
    return metadata


async def _jwks(metadata: dict[str, Any]) -> dict[str, Any]:
    jwks_uri = metadata.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri.startswith("https://"):
        raise OidcError("OIDC_JWKS_MISSING", "Provider did not publish an HTTPS JWKS URI")

    try:
        parsed = urlsplit(jwks_uri)
    except ValueError as exc:
        raise OidcError("OIDC_JWKS_INVALID", "Provider JWKS URI is invalid") from exc
    if (
        parsed.hostname not in JWKS_HOSTS or parsed.username is not None
        or parsed.password is not None or parsed.netloc != parsed.hostname
        or parsed.fragment
    ):
        raise OidcError("OIDC_JWKS_INVALID", "Provider JWKS URI is not approved")

    now = time.monotonic()
    cached = _jwks_cache.get(jwks_uri)
    if cached is not None and now - cached[0] < JWKS_TTL_SECONDS:
        return cached[1]

    try:
        async with _http().stream("GET", jwks_uri) as response:
            response.raise_for_status()
            document = bytearray()
            async for chunk in response.aiter_bytes():
                document.extend(chunk)
                if len(document) > 262_144:
                    raise OidcError("OIDC_JWKS_INVALID", "Provider JWKS exceeds the size limit")
            keys = json.loads(document)
    except (httpx.HTTPError, ValueError, RecursionError) as exc:
        raise OidcError("OIDC_JWKS_FETCH_FAILED", "Provider signing keys could not be fetched") from exc

    if (
        not isinstance(keys, dict) or not isinstance(keys.get("keys"), list)
        or not keys["keys"] or len(keys["keys"]) > 100
        or any(not isinstance(key, dict) for key in keys["keys"])
    ):
        raise OidcError("OIDC_JWKS_INVALID", "Provider JWKS was invalid")

    _jwks_cache[jwks_uri] = (now, keys)
    return keys


def _jwk_to_key(jwk: dict[str, Any]) -> Any:
    kty = jwk.get("kty")
    if kty == "RSA":
        return RSAAlgorithm.from_jwk(jwk)
    if kty == "EC":
        return ECAlgorithm.from_jwk(jwk)
    if kty == "OKP":
        return OKPAlgorithm.from_jwk(jwk)
    raise OidcError("OIDC_JWK_UNSUPPORTED", "Provider used an unsupported key type")


def _find_jwk(keys: dict[str, Any], kid: str | None) -> dict[str, Any] | None:
    for jwk in keys.get("keys", []):
        if not isinstance(jwk, dict):
            continue
        if kid is not None and jwk.get("kid") == kid:
            return jwk
        if kid is None and "kid" not in jwk:
            return jwk
    return None


async def authorization_url(
    provider: ProviderId,
    settings: ProviderSettings,
    redirect_uri: str,
    state: str,
    nonce: str,
    code_verifier: str,
    *,
    step_up: bool = False,
) -> str:
    """Build the authorization request.

    ``step_up`` asks the provider for a fresh interactive sign-in (``prompt=login``,
    ``max_age=0``) so the returned token can prove a *recent* second factor; the default
    lets the provider reuse its session and merely offer the account chooser.
    """
    metadata = await discover(provider, settings)
    endpoint = metadata.get("authorization_endpoint")
    if not isinstance(endpoint, str):
        raise OidcError("OIDC_METADATA_INVALID", "Provider authorization endpoint was missing")

    params: dict[str, str] = {
        "response_type": "code",
        "client_id": settings.client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge(code_verifier),
        "code_challenge_method": "S256",
        "prompt": "login" if step_up else "select_account",
    }
    if step_up:
        params["max_age"] = "0"
    if provider is MICROSOFT:
        params["response_mode"] = "query"

    query = httpx.QueryParams(params)
    return f"{endpoint}?{query}"


async def exchange_code(
    provider: ProviderId,
    settings: ProviderSettings,
    code: str,
    redirect_uri: str,
    code_verifier: str,
) -> TokenResponse:
    metadata = await discover(provider, settings)
    endpoint = metadata.get("token_endpoint")
    if not isinstance(endpoint, str):
        raise OidcError("OIDC_METADATA_INVALID", "Provider token endpoint was missing")

    data = {
        "grant_type": "authorization_code",
        "client_id": settings.client_id,
        "client_secret": settings.client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    try:
        response = await _http().post(
            endpoint,
            data=data,
            headers={"Accept": "application/json"},
        )
    except httpx.HTTPError as exc:
        raise OidcError("OIDC_TOKEN_REQUEST_FAILED", "Token exchange could not reach the provider") from exc

    if response.status_code != 200:
        raise OidcError("OIDC_TOKEN_REJECTED", "Identity provider rejected the authorization code")

    try:
        payload = response.json()
    except ValueError as exc:
        raise OidcError("OIDC_TOKEN_INVALID", "Token response was not valid JSON") from exc

    if not isinstance(payload, dict) or not isinstance(payload.get("id_token"), str):
        raise OidcError("OIDC_TOKEN_INVALID", "Token response did not include an id_token")

    return TokenResponse(
        id_token=payload["id_token"],
        access_token=payload.get("access_token") if isinstance(payload.get("access_token"), str) else None,
        expires_in=payload.get("expires_in") if isinstance(payload.get("expires_in"), int) else None,
        token_type=payload.get("token_type") if isinstance(payload.get("token_type"), str) else None,
    )


def _validate_issuer(provider: ProviderId, issuer: object, settings: ProviderSettings) -> str:
    if not isinstance(issuer, str):
        raise OidcError("OIDC_ISSUER_INVALID", "Token issuer was missing")

    if provider is MICROSOFT:
        expected_prefix = "https://login.microsoftonline.com/"
        if not issuer.startswith(expected_prefix):
            raise OidcError("OIDC_ISSUER_INVALID", "Token issuer is not a Microsoft Entra authority")
        # issuer shape: .../login.microsoftonline.com/{tenant}/v2.0
        remainder = issuer[len(expected_prefix) :].split("/")
        tenant = remainder[0] if remainder else ""
        if tenant not in settings.tenant_ids:
            raise OidcError("OIDC_TENANT_NOT_ALLOWED", "Token was issued by a non-approved Microsoft tenant")
        if issuer != f"{expected_prefix}{tenant}/v2.0":
            raise OidcError("OIDC_ISSUER_INVALID", "Token issuer is not an exact Entra v2 issuer")
        return issuer

    if provider is GOOGLE:
        if issuer != "https://accounts.google.com":
            raise OidcError("OIDC_ISSUER_INVALID", "Token issuer is not Google Workspace")
        return issuer

    raise OidcError("OIDC_PROVIDER_UNKNOWN", "Unknown identity provider")


def _validate_google_allowlist(claims: dict[str, Any], settings: ProviderSettings) -> None:
    subject = claims.get("sub")
    email = claims.get("email")
    hosted_domain = claims.get("hd")

    if not settings.hosted_domains and not settings.allowed_identities:
        raise OidcError("OIDC_IDENTITY_NOT_ALLOWED", "Google identity is not approved")

    if settings.hosted_domains and hosted_domain not in settings.hosted_domains:
        raise OidcError("OIDC_DOMAIN_NOT_ALLOWED", "Google Workspace domain is not approved")

    if settings.allowed_identities:
        approved = settings.allowed_identities
        if subject not in approved and email not in approved:
            raise OidcError("OIDC_IDENTITY_NOT_ALLOWED", "Google identity is not approved")


async def validate_id_token(
    provider: ProviderId,
    settings: ProviderSettings,
    id_token: str,
    expected_nonce: str,
) -> VerifiedClaims:
    if len(id_token) > MAX_ID_TOKEN_BYTES:
        raise OidcError("OIDC_TOKEN_INVALID", "Identity token exceeds the size limit")
    try:
        header = jwt.get_unverified_header(id_token)
    except (jwt.PyJWKError, ValueError, TypeError, RecursionError) as exc:
        raise OidcError("OIDC_TOKEN_INVALID", "Identity token could not be parsed") from exc
    except jwt.InvalidTokenError as exc:
        raise OidcError("OIDC_TOKEN_INVALID", "Identity token could not be parsed") from exc

    alg = header.get("alg")
    kid = header.get("kid")
    if not isinstance(alg, str) or alg not in {"RS256", "ES256", "ES384", "ES512", "PS256"}:
        raise OidcError("OIDC_ALG_UNSUPPORTED", "Identity token uses an unsupported algorithm")

    metadata = await discover(provider, settings)
    keys = await _jwks(metadata)
    jwk = _find_jwk(keys, kid if isinstance(kid, str) else None)
    if jwk is None:
        raise OidcError("OIDC_KID_NOT_FOUND", "No provider signing key matched the token")

    try:
        key = _jwk_to_key(jwk)
        claims = jwt.decode(
            id_token,
            key,
            algorithms=[alg],
            audience=settings.client_id,
            options={
                "require": ["iss", "aud", "sub", "exp", "iat", "nonce"],
                "verify_signature": True,
                "verify_aud": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_iss": False,  # validated explicitly below against the allow-list
            },
        )
    except jwt.ExpiredSignatureError as exc:
        raise OidcError("OIDC_TOKEN_EXPIRED", "Identity token has expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise OidcError("OIDC_AUDIENCE_INVALID", "Identity token audience is not this application") from exc
    except (jwt.PyJWTError, ValueError, TypeError, KeyError, RecursionError) as exc:
        raise OidcError("OIDC_TOKEN_INVALID", "Identity token signature or claims were invalid") from exc

    if not isinstance(claims, dict):
        raise OidcError("OIDC_TOKEN_INVALID", "Identity token claims were malformed")

    issuer = _validate_issuer(provider, claims.get("iss"), settings)

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise OidcError("OIDC_SUBJECT_INVALID", "Identity token has no usable subject")

    if provider is GOOGLE:
        _validate_google_allowlist(claims, settings)

    token_nonce = claims.get("nonce")
    if not isinstance(token_nonce, str) or token_nonce != expected_nonce:
        raise OidcError("OIDC_NONCE_INVALID", "Identity token nonce did not match the request")

    email = claims.get("email") if isinstance(claims.get("email"), str) else None
    return VerifiedClaims(
        subject=subject,
        issuer=issuer,
        audience=settings.client_id,
        email=email,
        raw=claims,
    )
