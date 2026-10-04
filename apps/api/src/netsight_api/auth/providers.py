"""Supported federated identity providers (ADR 0002)."""

from __future__ import annotations

from enum import StrEnum


class ProviderId(StrEnum):
    MICROSOFT = "microsoft"
    GOOGLE = "google"


MICROSOFT = ProviderId.MICROSOFT
GOOGLE = ProviderId.GOOGLE

# Well-known OpenID Connect discovery documents.
PROVIDER_METADATA_URL: dict[ProviderId, str] = {
    MICROSOFT: "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
    GOOGLE: "https://accounts.google.com/.well-known/openid-configuration",
}

# Expected issuer identifiers, used to reject tokens from other clouds.
EXPECTED_ISSUER: dict[ProviderId, str] = {
    MICROSOFT: "https://login.microsoftonline.com/",
    GOOGLE: "https://accounts.google.com",
}
