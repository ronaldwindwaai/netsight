"""Address classes for the traffic surface."""

from __future__ import annotations

import ipaddress
from typing import Final

_PRIVATE: Final = tuple(
    ipaddress.ip_network(net)
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)


def is_internal_address(address: str) -> bool:
    """Private, loopback, link-local, shared (CGNAT), multicast or unspecified space; or not an IP.

    Documentation ranges are *not* internal here: the first-seen list is about where traffic goes
    outside the organisation, and a lab or documentation prefix is as external as any other. An
    organisation's own public blocks can not be known from here and are not excluded.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return True
    mapped = getattr(parsed, "ipv4_mapped", None)
    if mapped is not None:
        parsed = mapped
    if parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_unspecified:
        return True
    return any(parsed in net for net in _PRIVATE if net.version == parsed.version)
