"""Supported federated identity providers (ADR 0002).

Only the providers approved by ADR 0002 are registered. Adding a provider
requires an ADR plus settings wiring; ``settings.assert_all_providers_registered``
enforces the wiring so a provider cannot be declared without configuration.
"""

from __future__ import annotations

from enum import StrEnum


class ProviderId(StrEnum):
    MICROSOFT = "microsoft"
    GOOGLE = "google"


MICROSOFT = ProviderId.MICROSOFT
GOOGLE = ProviderId.GOOGLE

# Reference discovery documents. Per-provider configuration always supplies
# its own ``authority``; these document the expected shape and the issuer
# each provider's tokens must carry.
PROVIDER_METADATA_URL: dict[ProviderId, str] = {
    MICROSOFT: "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
    GOOGLE: "https://accounts.google.com/.well-known/openid-configuration",
}

# Expected issuer identifiers, used to reject tokens from other clouds.
EXPECTED_ISSUER: dict[ProviderId, str] = {
    MICROSOFT: "https://login.microsoftonline.com/",
    GOOGLE: "https://accounts.google.com",
}