"""Flow Explorer filters: an allow-list of fields, canonical values, nothing echoed on refusal.

The filters are the only caller-controlled input that reaches a ClickHouse query. Three rules keep
that safe:

* only the names in ``FILTER_NAMES`` are accepted, each with one fixed type and range; any other
  parameter name is refused (422), not ignored, so a typo can never silently widen a query;
* values are canonicalised here (an address has one spelling) and bound as typed ``param_*``
  placeholders by the adapter; text never becomes SQL, so characters such as quotes are plain data;
* a refusal names the field and a static reason, never the value, so a hostile value is not reflected
  into an error body or a log line.

Filtering by an address narrows a query to one endpoint, and a device or a VLAN to a handful of them
(a floor, a closet), so ``ENDPOINT_FILTERS`` need the endpoint-level traffic permission
(``traffic:read-detail``) just as the flow rows do. Everything the aggregate tier may filter on
(application, protocol, port, country, ASN, direction) describes traffic, not a place.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final

from netsight_api.schemas_traffic import FilterName, FlowFilters

FILTER_NAMES: Final[tuple[FilterName, ...]] = (
    "source_ip",
    "destination_ip",
    "device",
    "vlan",
    "application",
    "protocol",
    "port",
    "country",
    "asn",
    "direction",
)
ENDPOINT_FILTERS: Final[frozenset[str]] = frozenset(
    {"source_ip", "destination_ip", "device", "vlan"}
)
MAX_TEXT_FILTER: Final = 128
MAX_RAW_VALUE: Final = 2048  # refuse before doing any work on a pathological value

_PROTOCOLS: Final = frozenset({"tcp", "udp", "icmp", "other"})
_DIRECTIONS: Final = frozenset({"inbound", "outbound", "internal"})
_DIGITS = re.compile(r"[0-9]{1,10}")
_COUNTRY = re.compile(r"[A-Z]{2}")


class FilterError(ValueError):
    """A refused parameter. ``field`` is an allow-listed name or ``parameter``; never caller text."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"The {field} filter is not valid: {reason}")
        self.field = field
        self.reason = reason


def reject_unknown_parameters(items: Iterable[tuple[str, str]], allowed: frozenset[str]) -> None:
    """Refuse a name outside ``allowed`` and any parameter given twice (nothing is echoed)."""
    seen: set[str] = set()
    for name, _ in items:
        if name not in allowed:
            raise FilterError("parameter", "unknown parameter")
        if name in seen:
            raise FilterError("parameter", "repeated parameter")
        seen.add(name)


@dataclass(frozen=True)
class FlowFilterSet:
    """Validated, canonical filters. Immutable; ``None`` means the filter is not applied."""

    source_ip: str | None = None
    destination_ip: str | None = None
    device: str | None = None
    vlan: int | None = None
    application: str | None = None
    protocol: str | None = None
    port: int | None = None
    country: str | None = None
    asn: int | None = None
    direction: str | None = None

    def active(self) -> tuple[FilterName, ...]:
        """The names of the filters in use, in the fixed allow-list order."""
        return tuple(name for name in FILTER_NAMES if getattr(self, name) is not None)

    def endpoint_level(self) -> bool:
        """True when a filter narrows the read to one address, device or VLAN (endpoint level)."""
        return any(name in ENDPOINT_FILTERS for name in self.active())

    def to_model(self) -> FlowFilters:
        return FlowFilters.model_validate({name: getattr(self, name) for name in FILTER_NAMES})


def ip_candidates(address: str) -> tuple[str, ...]:
    """Every spelling under which the flow store may hold ``address``.

    An IPv4 address is stored either plain (IPv4 column) or IPv4-mapped (IPv6 column), so a filter
    matches both; the textual form is compared after ``toString`` on the column.
    """
    parsed = ipaddress.ip_address(address)
    if parsed.version == 4:
        return (str(parsed), f"::ffff:{parsed}")
    return (str(parsed),)


def _ip(name: str, raw: str) -> str:
    text = raw.strip()
    if not text or "%" in text or "/" in text:
        raise FilterError(name, "expected one IPv4 or IPv6 address")
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError as error:
        raise FilterError(name, "expected one IPv4 or IPv6 address") from error
    mapped = getattr(parsed, "ipv4_mapped", None)
    return str(mapped if mapped is not None else parsed)


def _number(name: str, raw: str, low: int, high: int) -> int:
    if not _DIGITS.fullmatch(raw):
        raise FilterError(name, "expected a whole number")
    value = int(raw)
    if not low <= value <= high:
        raise FilterError(name, f"expected {low} to {high}")
    return value


def _text(name: str, raw: str) -> str:
    value = raw.strip()
    if not value or len(value) > MAX_TEXT_FILTER:
        raise FilterError(name, f"expected 1 to {MAX_TEXT_FILTER} characters")
    for char in value:
        if unicodedata.category(char).startswith("C") or (char != " " and char.isspace()):
            raise FilterError(name, "control and invisible characters are not allowed")
    return value


def _choice(name: str, raw: str, allowed: frozenset[str]) -> str:
    if raw not in allowed:
        raise FilterError(name, "not one of the allowed values")
    return raw


def parse_filters(params: Mapping[str, str]) -> FlowFilterSet:
    """Validate the filter parameters; anything outside the allow-list is a ``FilterError``."""
    for name, value in params.items():
        if name not in FILTER_NAMES:
            raise FilterError("parameter", "unknown parameter")
        if len(value) > MAX_RAW_VALUE:
            raise FilterError(name, "value is too long")
    fields: dict[str, object] = {}
    for name in FILTER_NAMES:
        raw = params.get(name)
        if raw is None:
            continue
        if name in ("source_ip", "destination_ip"):
            fields[name] = _ip(name, raw)
        elif name in ("device", "application"):
            fields[name] = _text(name, raw)
        elif name == "vlan":
            fields[name] = _number(name, raw, 0, 4094)
        elif name == "port":
            fields[name] = _number(name, raw, 0, 65535)
        elif name == "asn":
            fields[name] = _number(name, raw, 1, 4294967295)
        elif name == "country":
            if not _COUNTRY.fullmatch(raw):
                raise FilterError(name, "expected a two-letter upper-case country code")
            fields[name] = raw
        elif name == "protocol":
            fields[name] = _choice(name, raw, _PROTOCOLS)
        else:
            fields[name] = _choice(name, raw, _DIRECTIONS)
    return FlowFilterSet(**fields)  # type: ignore[arg-type]
