"""CSRF and origin guards for state-changing requests.

Three independent layers, cheapest and strongest first:

* the session CSRF token (``X-CSRF-Token``) compared in constant time, bytes-safe;
* an Origin (else Referer) allow-list: a browser always labels cross-site writes with
  the page's origin, which a page cannot forge, so a foreign or ``null`` origin is
  refused even when the token is somehow known;
* the SameSite cookie attribute (``SessionPolicy``), the browser-side backstop.

Failure is closed: an identity that claims to come from a session but has none, or a
human identity whose provenance was not recorded, is refused. Only the development
bridge (no session exists, so there is no token to compare) and non-human principals
(no browser, hence no ambient cookie) take a different path.

The allow-list comes from configuration only. The request's own Host header is never
trusted: DNS rebinding makes ``Origin == Host`` attacker-satisfiable.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

from fastapi import Request

from netsight_api.auth.deps import get_request_auth
from netsight_api.auth.session import constant_time_equals
from netsight_api.auth.settings import auth_settings
from netsight_api.rbac import Identity, PrincipalKind

CSRF_HEADER = "X-CSRF-Token"
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class Refusal:
    """Why a write was refused: audit ``reason`` plus the client-facing error."""

    reason: str
    code: str
    message: str


_CSRF_REFUSAL = Refusal("csrf", "CSRF_VALIDATION_FAILED", "A valid CSRF token is required")
_ORIGIN_REFUSAL = Refusal("origin", "ORIGIN_NOT_ALLOWED", "The request origin is not allowed")


def normalize_origin(value: str, *, allow_path: bool) -> str | None:
    """``scheme://host[:port]`` lower-cased with default ports dropped; None if not an origin.

    ``allow_path`` accepts a URL (configuration, Referer); the Origin header itself is
    never allowed a path, query or fragment. ``"null"`` and anything with credentials
    are not origins.
    """
    try:
        parts: SplitResult = urlsplit(value.strip())
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS or not host or parts.username or parts.password:
        return None
    if not allow_path and (parts.path or parts.query or parts.fragment):
        return None
    shown = f"[{host}]" if ":" in host else host
    suffix = "" if port is None or port == _DEFAULT_PORTS[scheme] else f":{port}"
    return f"{scheme}://{shown}{suffix}"


def trusted_origins() -> frozenset[str]:
    settings = auth_settings()
    candidates = [*settings.allowed_origins, settings.public_base_url]
    normalised = (normalize_origin(item, allow_path=True) for item in candidates if item.strip())
    return frozenset(origin for origin in normalised if origin is not None)


def origin_allowed(headers: Mapping[str, str], allowed: frozenset[str]) -> bool:
    """Origin wins; Referer is the fallback; neither present means a non-browser client."""
    origin = headers.get("origin")
    if origin is not None:
        normalised = normalize_origin(origin, allow_path=False)
        return normalised is not None and normalised in allowed
    referer = headers.get("referer")
    if referer is not None:
        normalised = normalize_origin(referer, allow_path=True)
        return normalised is not None and normalised in allowed
    return True


def _token_refusal(request: Request, identity: Identity) -> Refusal | None:
    auth = get_request_auth(request)
    supplied = request.headers.get(CSRF_HEADER, "")
    if auth is None:
        if identity.principal is not PrincipalKind.HUMAN:
            return None  # no browser, no ambient cookie, nothing to forge
        return _CSRF_REFUSAL  # a human identity of unknown provenance: fail closed
    if auth.source == "dev-bridge":
        # No session, hence no per-session token: require a non-empty custom header. A
        # cross-site page cannot set one without a CORS preflight, which this API never
        # grants, and the origin allow-list below still applies.
        return None if supplied else _CSRF_REFUSAL
    if auth.session is None:
        return _CSRF_REFUSAL
    return None if constant_time_equals(supplied, auth.session.csrf_token) else _CSRF_REFUSAL


def write_refusal(request: Request, identity: Identity) -> Refusal | None:
    """None when a state-changing request may proceed; otherwise the reason it must not."""
    refusal = _token_refusal(request, identity)
    if refusal is not None:
        return refusal
    if get_request_auth(request) is None:
        return None
    if not origin_allowed(request.headers, trusted_origins()):
        return _ORIGIN_REFUSAL
    return None
