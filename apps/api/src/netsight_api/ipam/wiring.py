"""Building the IPAM service from the environment (Step 8b): the same read-only clients as the rest."""

from __future__ import annotations

import os
from datetime import timedelta
from functools import cache

from netsight_api.inventory.cache import TtlCache
from netsight_api.inventory.wiring import configured_wazuh, utc_now
from netsight_api.ipam.service import (
    CACHE_TTL_SECONDS,
    STALE_WINDOW_ENV,
    IpamService,
    IpamSnapshot,
    stale_window_from_env,
)


@cache
def _window_for(raw: str) -> timedelta | None:
    """Parsed once per distinct setting, so an invalid one is logged once, not on every request."""
    return stale_window_from_env({STALE_WINDOW_ENV: raw})


@cache
def _shared_cache() -> TtlCache[IpamSnapshot]:
    return TtlCache(CACHE_TTL_SECONDS)


def build_ipam_service() -> IpamService:
    from netsight_api import main  # lazy: main owns the NetBox and LibreNMS factories

    return IpamService(
        netbox=main.get_optional_netbox_client(),
        librenms=main.get_optional_librenms_client(),
        wazuh=configured_wazuh(),
        stale_window=_window_for(os.environ.get(STALE_WINDOW_ENV, "")),
        clock=utc_now,
        cache=_shared_cache(),
    )


def reset_for_tests() -> None:
    _window_for.cache_clear()
    _shared_cache().clear()
