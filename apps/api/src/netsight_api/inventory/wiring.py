"""Building the inventory service from the environment (Step 8).

NetBox, LibreNMS and Wazuh are the clients the rest of the platform already uses, read-only. The
class map is parsed once per distinct configuration (a bad one is logged once, not on every
request) and the one-entry snapshot cache is shared by every request in the process.
"""

from __future__ import annotations

import dataclasses
import os
from datetime import UTC, datetime
from functools import cache
from typing import Final

from netsight_api.adapters.wazuh import WazuhIndexerClient
from netsight_api.identity.netbox_source import AGENT_FIELD_ENV, agent_key_field_from_env
from netsight_api.inventory.cache import TtlCache
from netsight_api.inventory.classmap import (
    CLASS_MAP_ENV,
    CLASS_MAP_FILE_ENV,
    ClassMap,
    load_class_map,
)
from netsight_api.inventory.service import (
    CACHE_TTL_SECONDS,
    AgentReader,
    InventoryService,
    InventorySnapshot,
)

AGENTS_INDEX_ENV: Final = "WAZUH_AGENTS_INDEX"
DEFAULT_AGENTS_INDEX: Final = "wazuh-monitoring-*"


def utc_now() -> datetime:
    return datetime.now(UTC)


@cache
def _class_map_for(inline: str, path: str) -> ClassMap:
    return load_class_map({CLASS_MAP_ENV: inline, CLASS_MAP_FILE_ENV: path})


def configured_class_map() -> ClassMap:
    return _class_map_for(os.environ.get(CLASS_MAP_ENV, ""), os.environ.get(CLASS_MAP_FILE_ENV, ""))


@cache
def _shared_cache() -> TtlCache[InventorySnapshot]:
    return TtlCache(CACHE_TTL_SECONDS)


def configured_wazuh() -> AgentReader | None:
    """The Wazuh indexer client reading the agent-status index, or ``None`` when not configured."""
    from netsight_api.security_routes import get_optional_security_source

    indexer = get_optional_security_source()
    if not isinstance(indexer, WazuhIndexerClient):
        return None
    pattern = os.environ.get(AGENTS_INDEX_ENV, "").strip() or DEFAULT_AGENTS_INDEX
    return dataclasses.replace(indexer, agents_index_pattern=pattern)


def build_inventory_service() -> InventoryService:
    from netsight_api import main  # lazy: main owns the NetBox and LibreNMS factories

    return InventoryService(
        netbox=main.get_optional_netbox_client(),
        librenms=main.get_optional_librenms_client(),
        wazuh=configured_wazuh(),
        agent_field=agent_key_field_from_env(os.environ.get(AGENT_FIELD_ENV, "")),
        class_map=configured_class_map(),
        clock=utc_now,
        cache=_shared_cache(),
    )


def reset_for_tests() -> None:
    _class_map_for.cache_clear()
    _shared_cache().clear()
