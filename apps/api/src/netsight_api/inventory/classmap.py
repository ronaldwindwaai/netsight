"""The operator's NetBox role/type -> asset class map (Step 8a).

Format (``NETSIGHT_INVENTORY_CLASS_MAP_FILE`` path, or ``NETSIGHT_INVENTORY_CLASS_MAP`` inline JSON)::

    {"version": 1,
     "roles": {"core-switch": "network-device", "wifi-ap": "access-point"},
     "device_types": {"camera-x": "cctv"}}

Keys are NetBox slugs (lower case); values are one of the seven classes below. ``unknown-asset``
(an asset NetBox does not know) and ``unclassified`` (a NetBox asset the map does not name) are
decided by the system and cannot be assigned here. The role is consulted first, then the device
type; matching is exact on the slug (no prefix or substring). A map that does not validate is
``invalid`` and classifies nothing: half a map is never applied.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final, cast

from netsight_api.inventory.operator_file import DocumentState, read_operator_document
from netsight_api.schemas_inventory import AssetClass, ClassBasis

CLASS_MAP_ENV: Final = "NETSIGHT_INVENTORY_CLASS_MAP"
CLASS_MAP_FILE_ENV: Final = "NETSIGHT_INVENTORY_CLASS_MAP_FILE"
MAX_ENTRIES: Final = 500
SUPPORTED_VERSION: Final = 1
_SLUG: Final = re.compile(r"^[a-z0-9][a-z0-9_-]{0,99}$")
_ASSIGNABLE: Final = frozenset(
    {"network-device", "server", "access-point", "endpoint", "cctv", "printer", "iot"}
)
_TOP_LEVEL: Final = frozenset({"version", "roles", "device_types"})
_UNCLASSIFIED: Final[tuple[AssetClass, ClassBasis]] = ("unclassified", "unmapped")

MapState = DocumentState


class _MapError(ValueError):
    """The map does not validate (static message, never document content)."""


@dataclass(frozen=True)
class ClassMap:
    state: MapState
    roles: Mapping[str, AssetClass] = field(default_factory=dict)
    device_types: Mapping[str, AssetClass] = field(default_factory=dict)

    def classify(
        self, role_slug: str | None, type_slug: str | None
    ) -> tuple[AssetClass, ClassBasis]:
        """The class and why. Role first, then type, else unclassified: never guessed."""
        if role_slug is not None and (mapped := self.roles.get(role_slug.lower())) is not None:
            return mapped, "role-map"
        if (
            type_slug is not None
            and (mapped := self.device_types.get(type_slug.lower())) is not None
        ):
            return mapped, "type-map"
        return _UNCLASSIFIED


def _table(value: object) -> dict[str, AssetClass]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > MAX_ENTRIES:
        raise _MapError("a table is an object of at most the entry limit")
    table: dict[str, AssetClass] = {}
    for slug, asset_class in value.items():
        if not isinstance(slug, str) or _SLUG.fullmatch(slug) is None:
            raise _MapError("keys are lower-case NetBox slugs")
        if not isinstance(asset_class, str) or asset_class not in _ASSIGNABLE:
            raise _MapError("values are assignable asset classes")
        table[slug] = cast(AssetClass, asset_class)
    return table


def _parse(document: object) -> ClassMap:
    if not isinstance(document, dict) or not set(document) <= _TOP_LEVEL:
        raise _MapError("unexpected document shape")
    if document.get("version") != SUPPORTED_VERSION:
        raise _MapError("unsupported version")
    return ClassMap(
        "configured", _table(document.get("roles")), _table(document.get("device_types"))
    )


def load_class_map(env: Mapping[str, str]) -> ClassMap:
    """The configured map. Never raises: an unusable one is ``invalid`` and classifies nothing."""
    document = read_operator_document(env, CLASS_MAP_ENV, CLASS_MAP_FILE_ENV)
    if document.state == "not-configured":
        return ClassMap("not-configured")
    if document.state == "invalid":
        return ClassMap("invalid")
    try:
        return _parse(document.data)
    except _MapError:
        return ClassMap("invalid")
