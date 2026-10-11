"""The per-source read status shared by the inventory and IPAM responses (Step 8).

Mirrors ``common.schema.json#/$defs/sourceStatus`` (OpenAPI ``DataSourceStatus``). A response names
every source it consulted so "NetBox said nothing" and "Wazuh was not asked" never look the same:
an ``ok`` read carries the time it was made; ``not-connected`` (not configured) and ``unknown``
(configured but unreadable) carry none.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

from pydantic import AwareDatetime, model_validator

from netsight_api.schemas import ApiModel

SourceName = Literal["netbox", "librenms", "wazuh"]
ReadState = Literal["ok", "not-connected", "unknown"]


class SourceStatus(ApiModel):
    source: SourceName
    state: ReadState
    observed_at: AwareDatetime | None

    @model_validator(mode="after")
    def _only_an_ok_read_has_a_time(self) -> SourceStatus:
        if (self.state == "ok") != (self.observed_at is not None):
            raise ValueError("only an ok read carries a time")
        return self


def check_unique_sources(sources: Sequence[SourceStatus], *, must_include: SourceName) -> None:
    """Each source appears once, and the authority for the response is always listed."""
    names = [s.source for s in sources]
    if len(set(names)) != len(names):
        raise ValueError("a source is listed once")
    if must_include not in names:
        raise ValueError(f"{must_include} must be listed")
