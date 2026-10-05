"""Allow-list settings parsing regression tests.

These cover a latent defect: pydantic-settings JSON-decodes complex (list)
fields from the environment *before* field validators run, so a plain
``NETSIGHT_OIDC_<P>_TENANT_IDS=a,b`` value raised SettingsError and turned
every auth endpoint into a 500. ``NoDecode`` fixes it.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from netsight_api.auth.providers import ProviderId
from netsight_api.auth.settings import (
    _PROVIDER_SETTINGS,
    google_settings,
    microsoft_settings,
    provider_settings,
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
)


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in CLEANUP_ENV:
        monkeypatch.delenv(name, raising=False)
    yield


def test_comma_separated_microsoft_tenant_ids_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_OIDC_MICROSOFT_TENANT_IDS", "contoso.onmicrosoft.com,fabrikam")
    assert microsoft_settings().tenant_ids == ["contoso.onmicrosoft.com", "fabrikam"]


def test_comma_separated_google_values_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_HOSTED_DOMAINS", "example.test,example.org")
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_ALLOWED_IDENTITIES", "ops@example.test")
    settings = google_settings()
    assert settings.hosted_domains == ["example.test", "example.org"]
    assert settings.allowed_identities == ["ops@example.test"]


def test_single_value_without_commas_parses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_HOSTED_DOMAINS", "solo")
    assert google_settings().hosted_domains == ["solo"]


def test_empty_value_yields_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_HOSTED_DOMAINS", "")
    assert google_settings().hosted_domains == []


def test_absent_value_yields_empty_list() -> None:
    assert google_settings().hosted_domains == []


def test_allow_list_env_does_not_break_auth_endpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    """The regression that motivated NoDecode: auth routes must not 500."""
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_ENABLED", "true")
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_CLIENT_ID", "netsight-client")
    monkeypatch.setenv("NETSIGHT_OIDC_GOOGLE_HOSTED_DOMAINS", "example.test,example.org")

    client = TestClient(app, raise_server_exceptions=False)
    assert client.get("/auth/providers").status_code == 200
    assert client.get("/auth/session").status_code == 401
    assert client.get("/api/v1/devices").status_code == 401


def test_every_provider_has_settings_wiring() -> None:
    """A provider must not be declared without its configuration path."""
    assert set(_PROVIDER_SETTINGS) == set(ProviderId)


@pytest.mark.parametrize("provider", list(ProviderId))
def test_provider_settings_resolves_to_its_own_configuration(
    provider: ProviderId,
) -> None:
    """No provider may inherit another provider's configuration.

    Regression: a two-branch helper mapped every non-Microsoft provider to
    Google settings, so a configured provider reported itself unconfigured.
    """
    prefix = f"NETSIGHT_OIDC_{provider.upper()}_"
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv(f"{prefix}ENABLED", "true")
        mp.setenv(f"{prefix}CLIENT_ID", f"client-{provider.value}")
        resolved = provider_settings(provider)

    assert resolved.enabled is True, provider
    assert resolved.client_id == f"client-{provider.value}", provider


def test_provider_settings_rejects_an_unregistered_provider() -> None:
    with pytest.raises(KeyError):
        provider_settings("not-a-provider")  # type: ignore[arg-type]