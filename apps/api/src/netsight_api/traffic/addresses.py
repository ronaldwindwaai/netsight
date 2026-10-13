"""The one classifier of "inside the organisation" for the traffic surface.

Three rules rest on it, so they can never disagree about what is internal:

* a destination inside the organisation is not listed to the aggregate tier;
* a first-seen destination must be external;
* the cohort denominator counts **internal endpoints only** (``clickhouse_queries`` binds
  ``internal_prefix_texts()`` into the same test, in the store).

The built-in prefixes are the private, shared (CGNAT), link-local, unique-local and reserved
internal-use space (RFC 1918, 6598, 3927, 4193, 2544, 6890 and the "reserved for future use" block).
``NETSIGHT_INTERNAL_PREFIXES`` (comma-separated CIDRs) **adds** the organisation's own public blocks:
it can never remove a built-in prefix, because dropping one would make an internal server look
external. A list that is malformed, has an entry broader than /8 (IPv6: /16), or holds more than
``MAX_PREFIXES`` entries is ignored whole and logged once (the built-ins stay in force).

Documentation ranges are *not* internal: a lab or documentation prefix is as external as any other.
Multicast, loopback and unspecified addresses, and text that is not an address, count as internal for
the hidden-destination rule (they are never an endpoint to be counted or listed).
"""

from __future__ import annotations

import ipaddress
import logging
import os
from typing import Final

_LOGGER = logging.getLogger("netsight_api")

PREFIXES_ENV: Final = "NETSIGHT_INTERNAL_PREFIXES"
MAX_PREFIXES: Final = 256
MIN_PREFIX_V4: Final = 8
MIN_PREFIX_V6: Final = 16

Network = ipaddress.IPv4Network | ipaddress.IPv6Network

_BUILT_IN: Final = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "240.0.0.0/4",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)
_warned: set[str] = set()
_parsed: tuple[str, tuple[Network, ...]] | None = None


def _warn_once(raw: str, reason: str) -> None:
    if raw in _warned:
        return
    _warned.add(raw)
    _LOGGER.warning(
        "%s is ignored (%s); only the built-in internal prefixes apply", PREFIXES_ENV, reason
    )


def _configured(raw: str) -> tuple[Network, ...]:
    """The extra prefixes in ``raw``, or none at all when any entry is unacceptable."""
    entries = [item.strip() for item in raw.split(",")]
    if len(entries) > MAX_PREFIXES:
        _warn_once(raw, f"more than {MAX_PREFIXES} entries")
        return ()
    found: list[Network] = []
    for entry in entries:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            _warn_once(raw, "not a list of CIDR prefixes")
            return ()
        if network.prefixlen < (MIN_PREFIX_V4 if network.version == 4 else MIN_PREFIX_V6):
            _warn_once(raw, "an entry is broader than /8 (IPv6: /16)")
            return ()
        found.append(network)
    return tuple(found)


def internal_prefixes() -> tuple[Network, ...]:
    """Built-in plus configured prefixes, de-duplicated and sorted (the SQL binds the same list)."""
    global _parsed
    raw = os.environ.get(PREFIXES_ENV, "").strip()
    if _parsed is not None and _parsed[0] == raw:
        return _parsed[1]
    extra = _configured(raw) if raw else ()
    merged = tuple(sorted({*_BUILT_IN, *extra}, key=lambda net: (net.version, str(net))))
    _parsed = (raw, merged)
    return merged


def internal_prefix_texts() -> tuple[str, ...]:
    """The prefixes as text, for binding into a store query."""
    return tuple(sorted({str(net) for net in internal_prefixes()}))


def reset_for_tests() -> None:
    global _parsed
    _parsed = None
    _warned.clear()


def is_internal_address(address: str) -> bool:
    """Inside the organisation's address space; or multicast, unspecified, or not an IP at all."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return True
    mapped = getattr(parsed, "ipv4_mapped", None)
    if mapped is not None:
        parsed = mapped
    if parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_unspecified:
        return True
    return any(parsed in net for net in internal_prefixes() if net.version == parsed.version)
