"""The operator traffic policy: the only source of approval, risk, reputation and working hours.

Netsight does not decide that an application is approved, that a destination is trustworthy or that
a time is "after hours". The operator says so in one JSON file (``NETSIGHT_TRAFFIC_POLICY_FILE``),
and every classification in the API traces to an entry in it. No file means ``unknown`` everywhere; a
file that does not validate means ``invalid`` and *also* ``unknown`` everywhere (fail closed: half a
policy is never applied). The file is read-only input, bounded in size and entry count, and parsed
with duplicate keys refused. See docs/12-implementation/TRAFFIC-BASELINES.md for the format.

Two deliberate asymmetries:

* a **hostname may deny but never allow**. Reverse DNS is controlled by whoever owns the address, so
  an allow-listing earned by a hostname would be spoofable; allow entries are addresses, ranges and
  ASNs only, and a domain in ``allow`` invalidates the file. Deny wins over allow;
* application names match **exactly** (``casefold`` only), never by prefix or substring, so a hostile
  label such as ``Zoom-malware`` can not borrow an approval. A label that changes under NFKC
  (full-width letters, ligatures, no-break spaces: a look-alike of an ASCII name) is *unknown*, never
  folded onto the name it imitates; a policy entry like that is refused with the whole file. The
  folding also never lets a non-ASCII letter collapse onto ASCII (``ß`` and ``ẞ`` are one letter, and
  neither equals ``ss``); two risk names that fold to the same text refuse the file;

A destination ``allow`` range is refused when it is wide enough to cover a large part of the Internet
(IPv4 shorter than /8, IPv6 shorter than /32): one slip would make nearly everything "allow-listed".
Deny ranges may be as broad as the operator likes (denying too much fails safe). The file is opened
once and measured with ``fstat`` on that handle, so a swap between a size check and the read can not
slip past the limit.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import stat
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime, time, timedelta
from typing import Any, Final, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_LOGGER = logging.getLogger("netsight_api")

POLICY_FILE_ENV: Final = "NETSIGHT_TRAFFIC_POLICY_FILE"
MAX_POLICY_BYTES: Final = 256 * 1024
MAX_ENTRIES: Final = 1000
MAX_TEXT: Final = 255
SUPPORTED_VERSION: Final = 1

PolicyState = Literal["not-configured", "configured", "invalid"]
Approval = Literal["approved", "unapproved", "unknown"]
Risk = Literal["low", "medium", "high", "unknown"]
Reputation = Literal["allow-listed", "deny-listed", "unknown"]

_DAYS: Final = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_RISKS: Final = frozenset({"low", "medium", "high"})
_CLOCK = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
END_OF_DAY: Final = "24:00"
MINUTES_PER_DAY: Final = 24 * 60
MIN_ALLOW_PREFIX_V4: Final = 8
MIN_ALLOW_PREFIX_V6: Final = 32
_DST_PROBE: Final = timedelta(hours=6)
_ZONE = re.compile(r"^[A-Za-z][A-Za-z0-9_+-]*(?:/[A-Za-z0-9_+-]+){0,2}$")
_ASN = re.compile(r"^AS([1-9]\d{0,9})$")
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$"
)
_MAX_ASN: Final = 4294967295


class _PolicyError(ValueError):
    """The file does not validate; the message is a static reason (never file content)."""


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _PolicyError("duplicate key")
        result[key] = value
    return result


def _text(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise _PolicyError(f"{what} must be text")
    stripped = value.strip()
    if not stripped or len(stripped) > MAX_TEXT:
        raise _PolicyError(f"{what} must be 1 to {MAX_TEXT} characters")
    if any(unicodedata.category(char).startswith("C") for char in stripped):
        raise _PolicyError(f"{what} must not contain control characters")
    return stripped


def _stable(value: str) -> bool:
    """True when NFKC leaves the text alone (no compatibility form that imitates another name)."""
    return unicodedata.normalize("NFKC", value) == value


def _fold_char(char: str) -> str:
    """Case-fold one character, but never let a non-ASCII letter collapse onto ASCII.

    Full case folding turns ``ß`` into ``ss`` (and ``ẞ``, the Kelvin sign, the long s ... into ASCII
    too), which would let a look-alike borrow the approval or risk of the ASCII name. Such a character
    is only lower-cased (``ẞ`` and ``ß`` stay one letter) and otherwise left alone.
    """
    if char.isascii():
        return char.casefold()
    folded = char.casefold()
    if folded.isascii():
        lowered = char.lower()
        return char if lowered.isascii() else lowered
    return folded


def _fold(value: str) -> str:
    """The comparison form of a label: stripped, case-folded, with ASCII-equality semantics."""
    return "".join(_fold_char(char) for char in value.strip())


def _entry(value: str) -> str:
    """A policy entry in comparison form; an entry that changes under NFKC could never match."""
    if not _stable(value):
        raise _PolicyError("names must not contain compatibility characters (NFKC-stable only)")
    return _fold(value)


def _strings(value: object, what: str) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_ENTRIES:
        raise _PolicyError(f"{what} must be a list of at most {MAX_ENTRIES}")
    return [_text(item, what) for item in value]


def _mapping(value: object, what: str, allowed: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or not set(value) <= allowed:
        raise _PolicyError(f"{what} has unknown or malformed keys")
    return value


@dataclass(frozen=True)
class _WorkingHours:
    zone: ZoneInfo
    zone_name: str
    days: frozenset[int]
    start: int  # minutes after local midnight
    end: int  # minutes after local midnight; 1440 is the end of the day ("24:00")

    def contains(self, bucket_start: datetime) -> bool:
        """True when the whole hour from ``bucket_start`` falls inside working hours."""
        local_start = bucket_start.astimezone(self.zone)
        local_end = (bucket_start + timedelta(hours=1)).astimezone(self.zone)
        if local_start.weekday() not in self.days:
            return False
        if local_end.date() == local_start.date():
            end_minute = local_end.hour * 60 + local_end.minute
        elif (
            local_end.date() == local_start.date() + timedelta(days=1)
            and local_end.time() == time()
        ):
            end_minute = MINUTES_PER_DAY  # the hour ends exactly at local midnight
        else:
            return False
        return self.start <= local_start.hour * 60 + local_start.minute and end_minute <= self.end


def _parse_working_hours(value: object) -> _WorkingHours:
    block = _mapping(value, "working_hours", {"timezone", "days", "start", "end"})
    if set(block) != {"timezone", "days", "start", "end"}:
        raise _PolicyError("working_hours needs timezone, days, start and end")
    name = _text(block["timezone"], "timezone")
    if not _ZONE.fullmatch(name):
        raise _PolicyError("timezone is not an IANA zone name")
    try:
        zone = ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError) as error:
        raise _PolicyError("unknown timezone") from error
    days = _strings(block["days"], "days")
    if not days or len(set(days)) != len(days) or not set(days) <= set(_DAYS):
        raise _PolicyError("days are distinct weekday names (mon..sun)")
    start, end = (_clock(block["start"]), _clock(block["end"], allow_end_of_day=True))
    if not start < end:
        raise _PolicyError("start must be before end (no overnight hours)")
    return _WorkingHours(zone, name, frozenset(_DAYS.index(day) for day in days), start, end)


def _clock(value: object, *, allow_end_of_day: bool = False) -> int:
    """Minutes after midnight for ``HH:MM``; ``24:00`` (the end of the day) only where allowed."""
    if allow_end_of_day and value == END_OF_DAY:
        return MINUTES_PER_DAY
    match = _CLOCK.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise _PolicyError("times are HH:MM (an end may be 24:00)")
    return int(match.group(1)) * 60 + int(match.group(2))


@dataclass(frozen=True)
class _Matchers:
    """Destination entries split by kind so a hostname can never reach the allow side."""

    addresses: frozenset[str] = frozenset()
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    asns: frozenset[int] = frozenset()
    domains: frozenset[str] = frozenset()

    def matches(self, address: str | None, domain: str | None, asn: int | None) -> bool:
        if asn is not None and asn in self.asns:
            return True
        parsed = _parse_address(address)
        if parsed is not None and (
            str(parsed) in self.addresses or any(parsed in net for net in self.networks)
        ):
            return True
        return domain is not None and self._domain_matches(domain)

    def _domain_matches(self, domain: str) -> bool:
        if not _stable(domain):
            return False
        name = _fold(domain).rstrip(".")
        return any(name == entry or name.endswith("." + entry) for entry in self.domains)


def _parse_address(
    value: str | None,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    mapped = getattr(address, "ipv4_mapped", None)
    return mapped if mapped is not None else address


def _check_breadth(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> None:
    floor = MIN_ALLOW_PREFIX_V4 if network.version == 4 else MIN_ALLOW_PREFIX_V6
    if network.prefixlen < floor:
        raise _PolicyError("an allow range that wide would allow-list most of the Internet")


def _parse_destinations(entries: list[str], *, allow_domains: bool) -> _Matchers:
    addresses: set[str] = set()
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    asns: set[int] = set()
    domains: set[str] = set()
    for entry in entries:
        asn = _ASN.fullmatch(entry)
        if asn is not None:
            number = int(asn.group(1))
            if number > _MAX_ASN:
                raise _PolicyError("ASN out of range")
            asns.add(number)
            continue
        try:
            if "/" in entry:
                network = ipaddress.ip_network(entry, strict=False)
                if not allow_domains:  # the allow side
                    _check_breadth(network)
                networks.append(network)
            else:
                addresses.add(str(ipaddress.ip_address(entry)))
            continue
        except ValueError:
            pass
        name = _entry(entry).rstrip(".")
        if not _DOMAIN.fullmatch(name):
            raise _PolicyError("destination entries are addresses, ranges, ASNs or domains")
        if not allow_domains:
            raise _PolicyError("a hostname can deny but never allow (reverse DNS is spoofable)")
        domains.add(name)
    return _Matchers(frozenset(addresses), tuple(networks), frozenset(asns), frozenset(domains))


@dataclass(frozen=True)
class TrafficPolicy:
    """A validated operator policy, or the reason there is none. Immutable; classify only."""

    state: PolicyState
    _working_hours: _WorkingHours | None = None
    _approved: frozenset[str] = frozenset()
    _unapproved: frozenset[str] = frozenset()
    _risk: dict[str, Risk] = field(default_factory=dict)
    _allow: _Matchers = field(default_factory=_Matchers)
    _deny: _Matchers = field(default_factory=_Matchers)

    @property
    def working_hours_state(self) -> PolicyState:
        if self.state == "invalid":
            return "invalid"
        return "configured" if self._working_hours is not None else "not-configured"

    @property
    def timezone_name(self) -> str | None:
        return self._working_hours.zone_name if self._working_hours is not None else None

    def application_approval(self, name: str) -> Approval:
        if not _stable(name):
            return "unknown"
        folded = _fold(name)
        if folded in self._approved:
            return "approved"
        return "unapproved" if folded in self._unapproved else "unknown"

    def application_risk(self, name: str) -> Risk:
        return self._risk.get(_fold(name), "unknown") if _stable(name) else "unknown"

    def destination_reputation(
        self, address: str | None, domain: str | None, asn: int | None
    ) -> Reputation:
        """Deny wins; a hostname can only ever deny (see the module docstring)."""
        if self._deny.matches(address, domain, asn):
            return "deny-listed"
        if self._allow.matches(address, None, asn):
            return "allow-listed"
        return "unknown"

    def outside_working_hours(self, bucket_start: datetime) -> bool | None:
        """Whether the hour starting at ``bucket_start`` is not wholly inside working hours.

        ``None`` when no valid working hours are configured: never assumed.
        """
        if self._working_hours is None:
            return None
        if bucket_start.tzinfo is None:
            bucket_start = bucket_start.replace(tzinfo=UTC)
        return not self._working_hours.contains(bucket_start)

    def daylight_saving_change(self, start: datetime, end: datetime) -> bool | None:
        """Whether the policy zone's UTC offset differs anywhere between ``start`` and ``end``.

        The baseline compares fixed 168-hour UTC weeks, so a clock change inside the span shifts the
        *local* hour of the weeks before it. ``None`` when no zone is configured (nothing to say).
        The offset is probed every six hours, which cannot miss a real transition.
        """
        if self._working_hours is None:
            return None
        zone = self._working_hours.zone
        if start.tzinfo is None:
            start = start.replace(tzinfo=UTC)
        first = start.astimezone(zone).utcoffset()
        moment = start
        while moment < end:
            if moment.astimezone(zone).utcoffset() != first:
                return True
            moment += _DST_PROBE
        return end.astimezone(zone).utcoffset() != first


def _parse_document(document: object) -> TrafficPolicy:
    root = _mapping(
        document, "policy", {"version", "working_hours", "applications", "destinations"}
    )
    version = root.get("version")
    if isinstance(version, bool) or version != SUPPORTED_VERSION:
        raise _PolicyError("unsupported version")
    hours = _parse_working_hours(root["working_hours"]) if "working_hours" in root else None
    approved: frozenset[str] = frozenset()
    unapproved: frozenset[str] = frozenset()
    risk: dict[str, Risk] = {}
    if "applications" in root:
        block = _mapping(root["applications"], "applications", {"approved", "unapproved", "risk"})
        approved = frozenset(_entry(n) for n in _strings(block.get("approved", []), "approved"))
        unapproved = frozenset(
            _entry(n) for n in _strings(block.get("unapproved", []), "unapproved")
        )
        if approved & unapproved:
            raise _PolicyError("an application can not be both approved and unapproved")
        risk = _parse_risk(block.get("risk", {}))
    allow = deny = _Matchers()
    if "destinations" in root:
        block = _mapping(root["destinations"], "destinations", {"allow", "deny"})
        allow = _parse_destinations(_strings(block.get("allow", []), "allow"), allow_domains=False)
        deny = _parse_destinations(_strings(block.get("deny", []), "deny"), allow_domains=True)
    return TrafficPolicy("configured", hours, approved, unapproved, risk, allow, deny)


def _parse_risk(value: object) -> dict[str, Risk]:
    if not isinstance(value, dict) or len(value) > MAX_ENTRIES:
        raise _PolicyError("risk must be a mapping of at most the entry limit")
    result: dict[str, Risk] = {}
    for name, level in value.items():
        if not isinstance(level, str) or level not in _RISKS:
            raise _PolicyError("risk is low, medium or high")
        key = _entry(_text(name, "risk name"))
        if key in result:
            raise _PolicyError("two risk names are the same after folding")
        result[key] = level  # type: ignore[assignment]
    return result


_INVALID = TrafficPolicy("invalid")
_NOT_CONFIGURED = TrafficPolicy("not-configured")


def _read_document(handle: Any) -> bytes:
    """The file's bytes through one handle: a regular file, measured by ``fstat``, read bounded."""
    info = os.fstat(handle.fileno())
    if not stat.S_ISREG(info.st_mode):
        raise _PolicyError("the policy path is not a regular file")
    if info.st_size > MAX_POLICY_BYTES:
        raise _PolicyError("the file is too large")
    raw: bytes = handle.read(MAX_POLICY_BYTES + 1)  # bounded even if the file grew since fstat
    if len(raw) > MAX_POLICY_BYTES:
        raise _PolicyError("the file is too large")
    return raw


def _parse_bytes(raw: bytes) -> TrafficPolicy:
    document = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    return _parse_document(document)


def _invalid(error: BaseException) -> TrafficPolicy:
    _LOGGER.warning(
        "traffic policy is invalid; every classification is unknown",
        extra={"error_type": type(error).__name__},
    )
    return _INVALID


def _from_handle(handle: Any) -> TrafficPolicy:
    try:
        return _parse_bytes(_read_document(handle))
    except (_PolicyError, OSError, ValueError, TypeError, RecursionError) as error:
        # TypeError: a value of the wrong JSON type that slipped a check is still just a bad file.
        return _invalid(error)


def load_policy(path: str | None) -> TrafficPolicy:
    """Read and validate the policy file. Never raises: a bad file is ``invalid`` (and logged)."""
    if path is None or not path.strip():
        return _NOT_CONFIGURED
    try:
        with open(path.strip(), "rb") as handle:
            return _from_handle(handle)
    except OSError as error:
        return _invalid(error)


_cache: tuple[tuple[str, int, int], TrafficPolicy] | None = None


def policy_from_environment() -> TrafficPolicy:
    """The policy named by ``NETSIGHT_TRAFFIC_POLICY_FILE``, re-read when the file changes.

    The file is opened once per call; its ``fstat`` (modification time and size) decides whether the
    cached policy is still current, and the same handle supplies the bytes when it is not.
    """
    global _cache
    path = os.environ.get(POLICY_FILE_ENV, "").strip()
    if not path:
        return _NOT_CONFIGURED
    try:
        with open(path, "rb") as handle:
            info = os.fstat(handle.fileno())
            key = (path, info.st_mtime_ns, info.st_size)
            if _cache is not None and _cache[0] == key:
                return _cache[1]
            policy = _from_handle(handle)
    except OSError as error:  # missing, unreadable or a directory: never cached
        _cache = None
        return _invalid(error)
    _cache = (key, policy)
    return policy
