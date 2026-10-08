"""Authentication and session settings.

All values are configuration-driven. Secrets are read from the environment
and are never logged or persisted to source. Provider allow-lists are
enforced explicitly (ADR 0002, docs/02-security/AUTHENTICATION-AUTHORIZATION.md).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from netsight_api.auth.providers import GOOGLE, MICROSOFT, ProviderId


class ProviderSettings(BaseSettings):
    """Per-provider OIDC configuration."""

    model_config = SettingsConfigDict(extra="ignore")

    enabled: bool = False
    client_id: str = ""
    client_secret: str = ""
    # Microsoft: Entra authority, e.g. https://login.microsoftonline.com/{tenant}
    # Google: https://accounts.google.com
    authority: str = ""
    # Microsoft only: explicitly allowed tenant IDs (empty = allow none).
    tenant_ids: Annotated[list[str], NoDecode] = Field(default_factory=list)
    # Google only: explicitly allowed hosted domains (empty = allow none).
    hosted_domains: Annotated[list[str], NoDecode] = Field(default_factory=list)
    # Approved individual identities (sub or email) allowed when the Google
    # hosted-domain allow-list alone is not sufficient.
    allowed_identities: Annotated[list[str], NoDecode] = Field(default_factory=list)

    @field_validator("tenant_ids", "hosted_domains", "allowed_identities", mode="before")
    @classmethod
    def _split_list(cls, value: object) -> object:
        """Accept a comma-separated string for allow-list variables.

        ``NoDecode`` stops pydantic-settings from JSON-decoding these fields
        first, which would otherwise raise SettingsError for a plain
        ``VAR=a,b`` value before this validator ever ran.
        """
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value


def _provider_settings(provider: ProviderId) -> ProviderSettings:
    """Build provider settings from a provider-specific env prefix."""
    return ProviderSettings(
        _env_prefix=f"NETSIGHT_OIDC_{provider.upper()}_",
        _case_sensitive=False,
    )  # type: ignore[call-arg]  # Pydantic BaseSettings runtime-only kwargs.


def microsoft_settings() -> ProviderSettings:
    return _provider_settings(MICROSOFT)


def google_settings() -> ProviderSettings:
    return _provider_settings(GOOGLE)


_PROVIDER_SETTINGS = {
    MICROSOFT: microsoft_settings,
    GOOGLE: google_settings,
}


def provider_settings(provider: ProviderId) -> ProviderSettings:
    """Return the configuration for ``provider``.

    Keyed by every ``ProviderId`` member and looked up rather than branched on,
    so a provider can never silently inherit another provider's configuration
    (an earlier two-branch helper mapped every non-Microsoft provider to
    Google, which made a configured provider report itself unconfigured).
    """
    factory = _PROVIDER_SETTINGS.get(provider)
    if factory is None:
        raise KeyError(f"no settings registered for provider: {provider}")
    return factory()


def assert_all_providers_registered() -> None:
    """Fail fast at import time if a provider lacks settings wiring."""
    missing = set(ProviderId) - set(_PROVIDER_SETTINGS)
    if missing:
        raise RuntimeError(f"providers without settings wiring: {sorted(str(m) for m in missing)}")


assert_all_providers_registered()


class SessionPolicy(BaseSettings):
    """Server-side session policy."""

    model_config = SettingsConfigDict(env_prefix="NETSIGHT_SESSION_", extra="ignore")

    # Opaque cookie signing secret (required in production).
    secret: str = ""
    cookie_name: str = "netsight_session"
    same_site: Literal["lax", "strict", "none"] = "lax"
    # Sliding inactivity timeout (seconds).
    inactivity_timeout: int = 3600
    # Absolute maximum session lifetime (seconds).
    absolute_lifetime: int = 28800
    # Use Secure cookie attribute (true when served over HTTPS).
    secure_cookie: bool = True
    # Domain for the session cookie (empty = host-only).
    cookie_domain: str = ""
    # SameSite=None sends the session cookie on cross-site requests, removing the browser's
    # CSRF backstop; it must be opted into explicitly (and requires a Secure cookie).
    allow_same_site_none: bool = False

    @model_validator(mode="after")
    def _guard_same_site_none(self) -> SessionPolicy:
        if self.same_site != "none":
            return self
        if not self.allow_same_site_none:
            raise ValueError(
                "same_site=none sends the session cookie on cross-site requests; "
                "set NETSIGHT_SESSION_ALLOW_SAME_SITE_NONE=true to accept that explicitly"
            )
        if not self.secure_cookie:
            raise ValueError("same_site=none requires a secure cookie (secure_cookie=true)")
        return self


class AuthSettings(BaseSettings):
    """Top-level authentication settings.

    Env var names are explicit so they match the deployment
    conventions already used by the platform (``NETSIGHT_ENV``,
    ``NETSIGHT_ENABLE_DEV_IDENTITY``).
    """

    # populate_by_name is required: with `validation_alias` set, pydantic
    # otherwise ignores constructor keywords and populates the field ONLY from
    # the environment variable. That silently discarded role_claim /
    # role_mapping / default_role whenever AuthSettings was constructed in
    # code, misconfiguring role assignment. Both sources now work.
    model_config = SettingsConfigDict(extra="ignore", populate_by_name=True)

    public_base_url: str = Field(default="", validation_alias="NETSIGHT_PUBLIC_BASE_URL")
    role_claim: str = Field(default="roles", validation_alias="NETSIGHT_ROLE_CLAIM")
    role_mapping: str = Field(default="", validation_alias="NETSIGHT_ROLE_MAPPING")
    # Deny unmapped identities unless an operator explicitly configures a fallback role.
    default_role: str = Field(default="", validation_alias="NETSIGHT_DEFAULT_ROLE")
    enable_dev_identity: bool = Field(
        default=False, validation_alias="NETSIGHT_ENABLE_DEV_IDENTITY"
    )
    environment: str = Field(default="production", validation_alias="NETSIGHT_ENV")
    # Browser origins allowed to make cookie-authenticated writes (comma separated, for
    # example the web app's origin when it is not the public base URL). The origin of
    # ``public_base_url`` is always allowed. Empty and no base URL means no browser origin.
    allowed_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=list, validation_alias="NETSIGHT_ALLOWED_ORIGINS"
    )
    auth_rate_limit_per_minute: int = Field(
        default=30, validation_alias="NETSIGHT_AUTH_RATE_LIMIT_PER_MINUTE"
    )

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def _split_allowed_origins(cls, value: object) -> object:
        """Comma-separated list (``NoDecode`` stops a JSON parse of a plain value)."""
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value


def parse_role_mapping(raw: str) -> dict[str, str]:
    """Parse ``value:role,value:role`` into a mapping dictionary."""
    mapping: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair:
            continue
        claim_value, _, role = pair.partition(":")
        claim_value = claim_value.strip()
        role = role.strip()
        if claim_value and role:
            mapping[claim_value] = role
    return mapping


def auth_settings() -> AuthSettings:
    """Return authentication settings, reading the environment fresh.

    Deliberately not cached: authentication decisions and the
    gated development bridge must observe environment changes
    immediately (and per-request in tests).
    """
    return AuthSettings()


@lru_cache(maxsize=1)
def session_policy() -> SessionPolicy:
    return SessionPolicy()
