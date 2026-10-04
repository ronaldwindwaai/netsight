"""Supported federated identity providers (ADR 0002, ADR 0009)."""

from __future__ import annotations

from enum import StrEnum


class ProviderId(StrEnum):
    MICROSOFT = "microsoft"
    GOOGLE = "google"
    CLERK = "clerk"


MICROSOFT = ProviderId.MICROSOFT
GOOGLE = ProviderId.GOOGLE
CLERK = ProviderId.CLERK

# Reference discovery documents. Per-provider configuration always supplies
# its own ``authority``; these document the expected shape and the issuer
# each provider's tokens must carry.
PROVIDER_METADATA_URL: dict[ProviderId, str] = {
    MICROSOFT: "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
    GOOGLE: "https://accounts.google.com/.well-known/openid-configuration",
    # Clerk instances are per-tenant; there is no shared multi-tenant authority.
    CLERK: "https://<instance>.clerk.accounts.dev/.well-known/openid-configuration",
}

# Expected issuer identifiers, used to reject tokens from other clouds.
EXPECTED_ISSUER: dict[ProviderId, str] = {
    MICROSOFT: "https://login.microsoftonline.com/",
    GOOGLE: "https://accounts.google.com",
    CLERK: "https://<instance>.clerk.accounts.dev",
}