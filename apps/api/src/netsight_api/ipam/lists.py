"""Filtering and paging of the IPAM lists (Step 8b): pure, over rows already built and validated."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from netsight_api.schemas_ipam import Activity, AddressSource, IpamAddress, IpamPrefix, IpamVlan


def _contains(needle: str, *values: str | None) -> bool:
    folded = needle.casefold()
    return any(value is not None and folded in value.casefold() for value in values)


@dataclass(frozen=True)
class PrefixFilters:
    site: str | None = None
    status: str | None = None
    family: int | None = None
    q: str | None = None

    def active(self) -> list[str]:
        return [name for name in self.__dataclass_fields__ if getattr(self, name) is not None]


@dataclass(frozen=True)
class VlanFilters:
    site: str | None = None
    q: str | None = None

    def active(self) -> list[str]:
        return [name for name in self.__dataclass_fields__ if getattr(self, name) is not None]


@dataclass(frozen=True)
class AddressFilters:
    activity: Activity | None = None
    source: AddressSource | None = None
    prefix: str | None = None
    q: str | None = None

    def active(self) -> list[str]:
        return [name for name in self.__dataclass_fields__ if getattr(self, name) is not None]


def filter_prefixes(items: Sequence[IpamPrefix], f: PrefixFilters) -> list[IpamPrefix]:
    return [
        p
        for p in items
        if (f.site is None or p.site == f.site)
        and (f.status is None or p.status == f.status)
        and (f.family is None or p.version == f.family)
        and (
            f.q is None or _contains(f.q, p.prefix, p.description, p.vlan.name if p.vlan else None)
        )
    ]


def filter_vlans(items: Sequence[IpamVlan], f: VlanFilters) -> list[IpamVlan]:
    return [
        v
        for v in items
        if (f.site is None or v.site == f.site)
        and (f.q is None or _contains(f.q, v.name, str(v.vid)))
    ]


def filter_addresses(items: Sequence[IpamAddress], f: AddressFilters) -> list[IpamAddress]:
    return [
        a
        for a in items
        if (f.activity is None or a.activity == f.activity)
        and (f.source is None or a.source == f.source)
        and (f.prefix is None or a.prefix_id == f.prefix)
        and (f.q is None or _contains(f.q, a.address, a.dns_name, a.description))
    ]


def page_of[T](items: Sequence[T], *, page: int, page_size: int) -> list[T]:
    start = (page - 1) * page_size
    return list(items[start : start + page_size])
