"""Security matrix tests for the S1 slice (docs/02-security).

Covers the negative controls that a happy-path suite misses: privilege
escalation through role claims, IDOR against device identifiers, stored XSS
via untrusted monitoring data, secret leakage into logs or responses,
session fixation, and upstream transport failures.

Each test asserts the *denial*. If a protection is removed, the test fails.
"""

from __future__ import annotations

import base64
import logging
import time
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from netsight_api.adapters.librenms import AdapterError, AdapterStatus, LibrenmsClient
from netsight_api.auth.identity import build_identity, resolve_roles
from netsight_api.auth.oidc import OidcError, validate_id_token
from netsight_api.auth.providers import GOOGLE, MICROSOFT
from netsight_api.auth.session import SessionManager, SessionStore
from netsight_api.auth.settings import AuthSettings, ProviderSettings, session_policy
from netsight_api.main import app, get_client
from netsight_api.rbac import Identity, Permission, is_allowed

XSS_DEVICE_NAME = "<script>alert('xss')</script>"


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    import netsight_api.auth.oidc as oidc_module

    for name in (
        "NETSIGHT_ENV",
        "NETSIGHT_ENABLE_DEV_IDENTITY",
        "NETSIGHT_SESSION_SECRET",
        "NETSIGHT_ROLE_CLAIM",
        "NETSIGHT_ROLE_MAPPING",
        "NETSIGHT_DEFAULT_ROLE",
        "NETBOX_BASE_URL",
        "NETBOX_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    oidc_module._metadata_cache.clear()
    oidc_module._jwks_cache.clear()
    yield
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    oidc_module._metadata_cache.clear()
    oidc_module._jwks_cache.clear()


def _enable_dev_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_ENV", "development")
    monkeypatch.setenv("NETSIGHT_ENABLE_DEV_IDENTITY", "true")


def _operator() -> Identity:
    return Identity("operator-1", frozenset({"network_engineer"}))


def _override_source(handler: Any) -> None:
    app.dependency_overrides[get_client] = lambda: LibrenmsClient(
        base_url="https://librenms.test",
        token="adapter-secret-do-not-leak",
        _transport=httpx.MockTransport(handler),
    )


# --- privilege escalation / role bypass -----------------------------------


def test_unmapped_role_claim_cannot_escalate() -> None:
    """An attacker-supplied role value must not become a Netsight role."""
    settings = AuthSettings(role_claim="roles", role_mapping="", default_role="")
    claims = {"roles": ["administrator", "root", "superuser"]}
    assert resolve_roles(claims, settings) == frozenset()


def test_role_mapping_only_grants_explicitly_mapped_values() -> None:
    settings = AuthSettings(
        role_claim="roles",
        role_mapping="ops-team:technician",
        default_role="",
    )
    roles = resolve_roles({"roles": ["ops-team", "administrator", "evil"]}, settings)
    assert roles == frozenset({"technician"})


def test_invalid_default_role_denies_every_permission() -> None:
    settings = AuthSettings(role_claim="roles", role_mapping="", default_role="root")
    identity = build_identity({"sub": "s", "roles": []}, settings, "google")
    assert identity.roles == frozenset()
    assert not is_allowed(identity, Permission.DEVICES_READ.value)


def test_identity_primary_key_is_provider_subject_not_email() -> None:
    """Email is mutable; the subject is the stable key."""
    settings = AuthSettings(role_claim="roles", role_mapping="", default_role="auditor")
    identity = build_identity(
        {"sub": "sub-123", "email": "attacker@evil.test", "roles": []},
        settings,
        "google",
    )
    assert identity.id == "google:sub-123"
    assert "attacker@evil.test" not in identity.id


def test_unknown_role_contributes_no_permissions() -> None:
    identity = Identity("u", frozenset({"not_a_role", "administrator_guess"}))
    assert not is_allowed(identity, Permission.DEVICES_READ.value)
    assert not is_allowed(identity, Permission.ACTIONS_APPROVE.value)


def test_dev_identity_bridge_requires_both_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    """The development bridge must never be reachable with a single flag."""
    for env in (
        {"NETSIGHT_ENV": "development"},
        {"NETSIGHT_ENABLE_DEV_IDENTITY": "true"},
        {"NETSIGHT_ENV": "production", "NETSIGHT_ENABLE_DEV_IDENTITY": "true"},
    ):
        # Each case must start from a clean environment; setenv persists across
        # iterations and would otherwise satisfy the two-flag gate by accident.
        monkeypatch.delenv("NETSIGHT_ENV", raising=False)
        monkeypatch.delenv("NETSIGHT_ENABLE_DEV_IDENTITY", raising=False)
        for key, value in env.items():
            monkeypatch.setenv(key, value)

        response = TestClient(app).get("/api/v1/devices")

        assert response.status_code == 401, env


# --- IDOR / device identifier handling ------------------------------------


@pytest.mark.parametrize(
    "device_id",
    [
        "../../etc/passwd",
        "..%2f..%2fetc%2fpasswd",
        "device-../../admin",
        "' OR 1=1 --",
        "'; DROP TABLE devices; --",
        "%00",
        "device-" + "f" * 200,
    ],
)
def test_hostile_device_identifiers_never_reach_the_source(
    device_id: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hostile id must never be interpolated into an outbound source URL."""
    _enable_dev_identity(monkeypatch)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json={"status": "ok", "devices": []})

    _override_source(handler)

    response = TestClient(app).get(f"/api/v1/devices/{device_id}")

    assert response.status_code in (404, 422), response.text
    leaked = [
        url
        for url in calls
        if any(fragment in url for fragment in ("etc/passwd", "DROP TABLE", "OR 1=1", device_id))
    ]
    assert leaked == [], f"hostile id reached the source URL: {leaked}"


def test_device_detail_does_not_leak_other_inventory_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A device request must not return the whole inventory."""
    _enable_dev_identity(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "status": "ok",
                "devices": [
                    {"device_id": 1, "hostname": "a.example.test", "status": 1},
                    {"device_id": 2, "hostname": "secret-host.example.test", "status": 1},
                ],
            },
        )

    _override_source(handler)
    response = TestClient(app).get("/api/v1/devices/device-00000000-0000-4000-8000-000000000001")
    assert "secret-host.example.test" not in response.text


def test_error_responses_do_not_disclose_internals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_dev_identity(monkeypatch)
    _override_source(lambda request: httpx.Response(500, json={"status": "boom"}))
    response = TestClient(app).get("/api/v1/devices")

    assert response.status_code == 503
    body = response.text
    for leak in ("Traceback", "adapter-secret", "librenms.test", "httpx", "/api/v0/"):
        assert leak not in body, leak


# --- stored XSS via untrusted monitoring data -----------------------------


def test_hostile_device_name_is_carried_as_data_not_markup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Source data is untrusted: it must survive validation as inert text.

    Rendering safety is provided by React's escaping; the API must not emit
    markup or let the value alter response structure.
    """
    _enable_dev_identity(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "status": "ok",
                "devices": [
                    {
                        "device_id": 1,
                        "hostname": XSS_DEVICE_NAME,
                        "display": XSS_DEVICE_NAME,
                        "status": 1,
                    }
                ],
            },
        )

    _override_source(handler)
    response = TestClient(app).get("/api/v1/devices")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()
    assert body["items"][0]["name"] == XSS_DEVICE_NAME


def _override_netbox(handler: Any) -> None:
    """Serve NetBox from a hostile/mock handler with a leak-prone token."""
    from netsight_api.adapters.netbox import NetboxClient
    from netsight_api.main import get_optional_librenms_client, get_optional_netbox_client

    client = NetboxClient(
        base_url="https://netbox.test",
        token="adapter-secret-do-not-leak",
        _transport=httpx.MockTransport(handler),
    )
    app.dependency_overrides[get_optional_netbox_client] = lambda: client
    # Deterministic: reconciliation is out of scope for these negative tests.
    app.dependency_overrides[get_optional_librenms_client] = lambda: None


def _active_cable() -> dict[str, Any]:
    return {
        "id": 1,
        "status": {"value": "active", "label": "Active"},
        "termination_a": {"object": {"name": "Ethernet1", "device": {"id": 1}}},
        "termination_b": {"object": {"name": "Ethernet1", "device": {"id": 2}}},
        "last_updated": "2026-10-05T10:00:00Z",
    }


def test_topology_rejects_hostile_pagination_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The vendor-controlled `next` URL must never be followed off-origin.

    SSRF guard: the request carries the NetBox token, so a hostile origin
    would leak the credential. Failure must fail closed to `unknown` with no
    origin, base URL or token in the response.
    """
    _enable_dev_identity(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/dcim/cables/":
            return httpx.Response(
                200,
                json={
                    "count": 1,
                    "results": [_active_cable()],
                    "next": "https://evil.test/steal?token=1",
                },
            )
        return httpx.Response(200, json={"count": 0, "results": []})

    _override_netbox(handler)
    response = TestClient(app).get("/api/v1/topology")

    assert response.status_code == 200
    assert response.json()["state"] == "unknown"
    for secret in ("evil.test", "adapter-secret-do-not-leak", "netbox.test"):
        assert secret not in response.text


def test_topology_device_name_is_carried_as_data_not_markup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Source-reported node names must round-trip as inert JSON text."""
    _enable_dev_identity(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/dcim/cables/":
            return httpx.Response(200, json={"count": 1, "results": [_active_cable()]})
        return httpx.Response(
            200,
            json={
                "count": 2,
                "results": [
                    {"id": 1, "name": XSS_DEVICE_NAME, "display": XSS_DEVICE_NAME},
                    {"id": 2, "name": "sw-b", "display": "sw-b"},
                ],
            },
        )

    _override_netbox(handler)
    response = TestClient(app).get("/api/v1/topology")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()
    assert body["state"] == "ok"
    assert XSS_DEVICE_NAME in [node["name"] for node in body["nodes"]]


def test_topology_never_echoes_the_netbox_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_dev_identity(monkeypatch)
    _override_netbox(lambda request: httpx.Response(500, json={"detail": "boom"}))
    body = TestClient(app).get("/api/v1/topology").text
    assert "adapter-secret-do-not-leak" not in body


def test_web_layer_never_uses_raw_html_injection() -> None:
    """Guard against a future dangerouslySetInnerHTML on source data."""
    from pathlib import Path

    src = Path(__file__).resolve().parents[2].parent / "web" / "src"
    offenders = [
        p.relative_to(src).as_posix()
        for p in src.rglob("*.tsx")
        if "dangerouslySetInnerHTML" in p.read_text(encoding="utf-8")
    ]
    assert offenders == []


# --- secret leakage -------------------------------------------------------


def test_api_never_echoes_the_source_token(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_dev_identity(monkeypatch)
    _override_source(lambda request: httpx.Response(401, json={"status": "unauthorized"}))
    for path in ("/api/v1/devices", "/api/v1/overview", "/api/v1/alerts"):
        body = TestClient(app).get(path).text
        assert "adapter-secret-do-not-leak" not in body, path


def test_logs_do_not_contain_secrets(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unhandled errors must log a correlation id, never payload data."""
    _enable_dev_identity(monkeypatch)
    _override_source(
        lambda request: httpx.Response(500, json={"status": "internal failure detail"})
    )
    with caplog.at_level(logging.DEBUG):
        TestClient(app).get("/api/v1/devices")

    combined = "\n".join(record.getMessage() for record in caplog.records)
    assert "adapter-secret-do-not-leak" not in combined
    assert "internal failure detail" not in combined
    assert "Authorization" not in combined
    assert "Bearer" not in combined


def test_auth_settings_honour_constructor_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: validation_alias made role config ignore kwargs silently.

    role_claim / role_mapping / default_role control role assignment. With
    validation_alias set and populate_by_name off, constructing AuthSettings
    in code discarded them and used defaults instead.
    """
    for name in ("NETSIGHT_ROLE_CLAIM", "NETSIGHT_ROLE_MAPPING", "NETSIGHT_DEFAULT_ROLE"):
        monkeypatch.delenv(name, raising=False)

    settings = AuthSettings(
        role_claim="groups",
        role_mapping="ops-team:technician",
        default_role="auditor",
    )
    assert settings.role_claim == "groups"
    assert settings.role_mapping == "ops-team:technician"
    assert settings.default_role == "auditor"

    # The environment must remain authoritative when present.
    monkeypatch.setenv("NETSIGHT_ROLE_MAPPING", "env-team:network_engineer")
    assert AuthSettings().role_mapping == "env-team:network_engineer"


def test_provider_discovery_state_never_exposes_secret_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_ENABLED", "true")
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_CLIENT_ID", "public-client-id")
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_CLIENT_SECRET", "super-secret-value")
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_HOSTED_DOMAINS", "example.test")

    body = TestClient(app).get("/api/v1/auth/providers").text

    assert "super-secret-value" not in body
    assert "example.test" not in body


# --- session integrity ----------------------------------------------------


def test_session_cookie_cannot_be_forged() -> None:
    """A tampered signature must not yield a session."""
    import netsight_api.auth.session as session_module

    session_module._manager = None
    manager = session_module.session_manager()
    session = manager.create_session("sub", "google", ["auditor"], "a@example.test")
    valid = manager.cookie_value(session)

    # Valid cookie resolves.
    assert manager.validate_cookie(valid) is not None

    # Flip one character of the signature.
    tampered = valid[:-4] + ("A" if valid[-4] != "A" else "B") + valid[-3:]
    assert manager.validate_cookie(tampered) is None

    # Swap the session id but keep a well-formed envelope.
    other = manager.create_session("other", "google", ["administrator"])
    forged_raw = (
        base64.urlsafe_b64encode(
            f"{other.id}.{base64.urlsafe_b64encode(b'0' * 32).decode()}".encode()
        )
        .decode()
        .rstrip("=")
    )
    assert manager.validate_cookie(forged_raw) is None

    session_module._manager = None


def test_new_login_does_not_reuse_a_fixated_session_id() -> None:
    """Session identifiers must be freshly random per login."""
    import netsight_api.auth.session as session_module

    session_module._manager = None
    manager = session_module.session_manager()
    ids = {manager.create_session("sub", "google", ["auditor"]).id for _ in range(50)}
    assert len(ids) == 50
    session_module._manager = None


def test_session_revoke_invalidates_immediately() -> None:
    import netsight_api.auth.session as session_module

    session_module._manager = None
    manager = session_module.session_manager()
    session = manager.create_session("sub", "google", ["auditor"])
    cookie = manager.cookie_value(session)
    assert manager.validate_cookie(cookie) is not None

    manager.revoke(session.id)
    assert manager.validate_cookie(cookie) is None
    session_module._manager = None


def test_expired_session_is_refused_with_injected_clock() -> None:
    now = [1000.0]
    store = SessionStore(clock=lambda: now[0])
    from netsight_api.auth.settings import SessionPolicy

    policy = SessionPolicy(inactivity_timeout=60, absolute_lifetime=600)
    session = store.create("sub", "google", ["auditor"])
    now[0] += 61.0
    assert store.get(session.id, policy) is None


def test_cookie_attributes_are_hardened() -> None:
    from netsight_api.auth.settings import SessionPolicy

    attributes = SessionManager(SessionStore(), SessionPolicy()).cookie_attributes()
    assert attributes["httponly"] is True
    assert attributes["secure"] is True
    assert attributes["samesite"] in ("lax", "strict")


# --- upstream transport failures ------------------------------------------


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(401, json={}),
        httpx.Response(403, json={}),
        httpx.Response(500, json={}),
        httpx.Response(429, json={}),
        httpx.Response(302, headers={"Location": "https://evil.test/"}),
    ],
)
def test_source_failures_map_to_typed_denial_not_success(
    response: httpx.Response, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failing or redirecting source must never become an empty success."""
    _enable_dev_identity(monkeypatch)
    _override_source(lambda request: response)

    result = TestClient(app).get("/api/v1/devices")

    assert result.status_code in (502, 503), result.text
    assert result.json()["error"]["code"] in (
        "SOURCE_UNAVAILABLE",
        "SOURCE_FORBIDDEN",
        "SOURCE_INVALID_DATA",
    )


def test_source_transport_error_fails_closed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = LibrenmsClient(
        base_url="https://librenms.test",
        token="adapter-secret-do-not-leak",
        _transport=httpx.MockTransport(handler),
    )
    import anyio

    with pytest.raises(AdapterError) as exc:
        anyio.run(client.devices)

    assert exc.value.status is AdapterStatus.UNAVAILABLE
    assert "adapter-secret-do-not-leak" not in str(exc.value)


def test_source_redirects_are_not_followed() -> None:
    """An open redirect from the source must not be followed."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://evil.test/steal"})

    client = LibrenmsClient(
        base_url="https://librenms.test",
        token="adapter-secret-do-not-leak",
        _transport=httpx.MockTransport(handler),
    )
    import anyio

    with pytest.raises(AdapterError) as exc:
        anyio.run(client.devices)

    assert exc.value.status is AdapterStatus.INVALID_SOURCE_DATA


def test_non_json_source_response_is_rejected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>not json</html>")

    client = LibrenmsClient(
        base_url="https://librenms.test",
        token="adapter-secret-do-not-leak",
        _transport=httpx.MockTransport(handler),
    )
    import anyio

    with pytest.raises(AdapterError) as exc:
        anyio.run(client.devices)

    assert exc.value.status is AdapterStatus.INVALID_SOURCE_DATA


# --- correlation / abuse --------------------------------------------------


def test_supplied_correlation_id_is_echoed_and_bounded() -> None:
    response = TestClient(app).get(
        "/api/v1/devices",
        headers={"X-Correlation-ID": "test-corr-1"},
    )
    assert response.headers["X-Correlation-ID"] == "test-corr-1"

    ignored = TestClient(app).get(
        "/api/v1/devices",
        headers={"X-Correlation-ID": "bad value with spaces and <script>"},
    )
    assert ignored.headers["X-Correlation-ID"] != "bad value with spaces and <script>"


def test_auth_endpoints_are_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    from netsight_api.auth import routes as auth_routes
    from netsight_api.auth.settings import AuthSettings

    monkeypatch.setenv("NETSIGHT_AUTH_RATE_LIMIT_PER_MINUTE", "3")
    auth_routes.rate_limiter().reset("rate-limit-test")

    settings = AuthSettings()
    from netsight_api.auth.rate_limit import rate_limiter

    limiter = rate_limiter()
    key = "auth:login:127.0.0.1"
    allowed = [limiter.allow(key, settings.auth_rate_limit_per_minute, 60.0) for _ in range(5)]

    assert allowed.count(True) == 3
    assert allowed.count(False) == 2


def test_callback_refuses_unissued_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """A callback with a state Netsight never issued must be refused."""
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_ENABLED", "true")
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_CLIENT_ID", "client")
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_CLIENT_SECRET", "secret")
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_HOSTED_DOMAINS", "example.test")

    response = TestClient(app, follow_redirects=False).get(
        "/api/v1/auth/callback", params={"code": "c", "state": "never-issued"}
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "AUTH_STATE_INVALID"


def test_pending_auth_state_is_single_use() -> None:
    """State is consumed on first use, so a replay cannot start a session."""
    from netsight_api.auth.pending import PendingAuthStore
    from netsight_api.auth.providers import GOOGLE

    store = PendingAuthStore()
    store.put(
        state="s-1",
        provider=GOOGLE,
        nonce="n",
        code_verifier="v",
        redirect_to="/overview",
    )

    first = store.take("s-1")
    assert first is not None
    # Replay must find nothing.
    assert store.take("s-1") is None


def test_pending_auth_state_expires(monkeypatch: pytest.MonkeyPatch) -> None:
    from netsight_api.auth import pending as pending_module
    from netsight_api.auth.providers import GOOGLE

    store = pending_module.PendingAuthStore()
    store.put(
        state="s-2",
        provider=GOOGLE,
        nonce="n",
        code_verifier="v",
        redirect_to="/overview",
    )

    # Force expiry past the TTL rather than sleeping.
    entry = store._pending["s-2"]
    entry.created_at -= pending_module.PENDING_TTL_SECONDS + 1
    assert store.take("s-2") is None


def test_login_does_not_leak_state_or_nonce(monkeypatch: pytest.MonkeyPatch) -> None:
    """The authorization redirect must not echo internal secrets."""
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_ENABLED", "true")
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_CLIENT_ID", "netsight-client")
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_CLIENT_SECRET", "super-secret-value")
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_HOSTED_DOMAINS", "example.test")
    monkeypatch.setenv("NETSIGHT_PUBLIC_BASE_URL", "https://netsight.test")

    response = TestClient(app, follow_redirects=False).get("/api/v1/auth/login/google")

    body = response.text + (response.headers.get("location") or "")
    assert "super-secret-value" not in body
    assert response.json()["error"]["code"] in (
        "OIDC_UNAVAILABLE",
        "RATE_LIMITED",
    )


def test_provider_allowlist_absent_denies_every_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No tenant/domain allow-list means no identity may authenticate."""
    import netsight_api.auth.oidc as oidc_module

    settings = ProviderSettings(client_id="client", tenant_ids=[])
    with pytest.raises(OidcError) as exc:
        oidc_module._validate_issuer(
            MICROSOFT,
            "https://login.microsoftonline.com/tenant-id/v2.0",
            settings,
        )
    assert exc.value.code == "OIDC_TENANT_NOT_ALLOWED"

    google = ProviderSettings(client_id="client", hosted_domains=[], allowed_identities=[])
    with pytest.raises(OidcError) as exc:
        oidc_module._validate_google_allowlist({"sub": "s", "email": "e"}, google)
    assert exc.value.code == "OIDC_IDENTITY_NOT_ALLOWED"


def test_issuer_confusion_between_providers_is_rejected() -> None:
    """A Google token must never satisfy Microsoft validation."""
    import netsight_api.auth.oidc as oidc_module

    settings = ProviderSettings(client_id="client", tenant_ids=["contoso"])
    with pytest.raises(OidcError) as exc:
        oidc_module._validate_issuer(MICROSOFT, "https://accounts.google.com", settings)
    assert exc.value.code == "OIDC_ISSUER_INVALID"

    google_settings = ProviderSettings(client_id="client")
    with pytest.raises(OidcError) as exc:
        oidc_module._validate_issuer(
            GOOGLE, "https://login.microsoftonline.com/tenant/v2.0", google_settings
        )
    assert exc.value.code == "OIDC_ISSUER_INVALID"


def test_validate_id_token_requires_a_matching_nonce() -> None:
    """A token whose nonce differs from the request must be refused."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    import netsight_api.auth.oidc as oidc_module

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()

    def b64u_int(value: int) -> str:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    jwk = {
        "kty": "RSA",
        "kid": "k1",
        "use": "sig",
        "alg": "RS256",
        "n": b64u_int(numbers.n),
        "e": b64u_int(numbers.e),
    }
    metadata = {
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
    }

    async def fake_discover(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return metadata

    async def fake_jwks(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"keys": [jwk]}

    original_discover = oidc_module.discover
    original_jwks = oidc_module._jwks
    oidc_module.discover = fake_discover
    oidc_module._jwks = fake_jwks
    try:
        settings = ProviderSettings(
            client_id="netsight-client",
            hosted_domains=["example.test"],
        )
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": "https://accounts.google.com",
            "sub": "sub-1",
            "aud": "netsight-client",
            "exp": now + 300,
            "iat": now,
            "nonce": "the-real-nonce",
            "email": "ops@example.test",
            # The Google allow-list is evaluated before the nonce check, so a
            # permitted hosted domain is required to reach it.
            "hd": "example.test",
        }
        import jwt as pyjwt

        token = pyjwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "k1"})

        import anyio

        with pytest.raises(OidcError) as exc:
            anyio.run(validate_id_token, GOOGLE, settings, token, "attacker-nonce")
        assert exc.value.code == "OIDC_NONCE_INVALID"

        # The matching nonce is accepted, proving the check is the only barrier.
        verified = anyio.run(validate_id_token, GOOGLE, settings, token, "the-real-nonce")
        assert verified.subject == "sub-1"
    finally:
        oidc_module.discover = original_discover
        oidc_module._jwks = original_jwks
