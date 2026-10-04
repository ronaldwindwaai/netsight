"""Allow-list settings parsing regression tests.

These cover a latent defect: pydantic-settings JSON-decodes complex (list)
fields from the environment *before* field validators run, so a plain
``NETSIGHT_OIDC_<P>_ALLOWED_IDENTITIES=a,b`` value raised SettingsError and
turned every auth endpoint into a 500. `NoDecode` fixes it.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from netsight_api.auth.settings import (
    SessionPolicy,
    clerk_settings,
    google_settings,
    microsoft_settings,
    session_policy,
)
from netsight_api.main import app

CLEANUP_ENV = (
    "NETSIGHT_OIDC_MICROSOFT_ENABLED",
    "NETSIGHT_OIDC_MICROSOFT_CLIENT_ID",
    "NETSIGHT_OIDC_MICROSOFT_TENANT_IDS",
    "NETSIGHT_OIDC_GOOGLE_ENABLED",
    "NETSIGHT_OIDC_GOOGLE_CLIENT_ID",
    "NETSIGHT_OIDC_GOOGLE_HOSTED_DOMAINS",
    "NETSIGHT_OIDC_GOOGLE_ALLOWED_IDENTITIES",
    "NETSIGHT_OIDC_CLERK_ENABLED",
    "NETSIGHT_OIDC_CLERK_CLIENT_ID",
    "NETSIGHT_OIDC_CLERK_ALLOWED_IDENTITIES",
)


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in CLEANUP_ENV:
        monkeypatch.delenv(name, raising=False)
    yield


def test_comma_separated_clerk_identities_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_OIDC_CLERK_ALLOWED_IDENTITIES", "user_a, user_b ,user_c")
    assert clerk_settings().allowed_identities == ["user_a", "user_b", "user_c"]


def test_comma_separated_google_values_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_HOSTED_DOMAINS", "example.test,example.org")
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_ALLOWED_IDENTITIES", "ops@example.test")
    settings = google_settings()
    assert settings.hosted_domains == ["example.test", "example.org"]
    assert settings.allowed_identities == ["ops@example.test"]


def test_comma_separated_microsoft_tenant_ids_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_OIDC_MICROSOFT_TENANT_IDS", "contoso.onmicrosoft.com,fabrikam")
    assert microsoft_settings().tenant_ids == ["contoso.onmicrosoft.com", "fabrikam"]


def test_single_value_without_commas_parses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_OIDC_CLERK_ALLOWED_IDENTITIES", "solo")
    assert clerk_settings().allowed_identities == ["solo"]


def test_empty_value_yields_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_OIDC_CLERK_ALLOWED_IDENTITIES", "")
    assert clerk_settings().allowed_identities == []


def test_absent_value_yields_empty_list() -> None:
    assert clerk_settings().allowed_identities == []


def test_allow_list_env_does_not_break_auth_endpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    """The regression that motivated NoDecode: auth routes must not 500."""
    monkeypatch.setenv("NETSIGHT_OIDC_CLERK_ENABLED", "true")
    monkeypatch.setenv("NETSIGHT_OIDC_CLERK_CLIENT_ID", "netsight-client")
    monkeypatch.setenv("NETSIGHT_OIDC_CLERK_ALLOWED_IDENTITIES", "user_a,user_b")

    client = TestClient(app, raise_server_exceptions=False)
    assert client.get("/auth/providers").status_code == 200
    assert client.get("/auth/session").status_code == 401
    assert client.get("/api/v1/devices").status_code == 401


def test_session_policy_reads_env() -> None:
    policy = SessionPolicy(
        secret="x" * 32, inactivity_timeout=120, absolute_lifetime=900, secure_cookie=True
    )
    assert policy.inactivity_timeout == 120
    session_policy.cache_clear()