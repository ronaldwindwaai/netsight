"""Maintenance windows: active / expired are derived from the clock, never stored.

A window is half-open, ``starts_at <= now < ends_at`` (the same rule the store's
``active_at`` filter uses), so two back-to-back windows leave no gap and never double count.

ALERT-ENGINE.md: maintenance suppresses notifications and actions but retains evaluation
evidence unless the window explicitly disables evaluation. Several windows can overlap an
entity (organisation + site + device scopes, or repeated windows): the effect is the union,
and ``disable`` beats ``retain``.
"""

from __future__ import annotations

from collections.abc import Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

from netsight_api.schemas import AlertScope

WindowPhase = Literal["upcoming", "active", "expired", "cancelled"]
EffectKind = Literal["none", "suppress", "disable"]


class WindowLike(Protocol):
    """The five fields the engine reads; ``MaintenanceWindow`` satisfies this."""

    @property
    def scope(self) -> AlertScope: ...
    @property
    def starts_at(self) -> datetime: ...
    @property
    def ends_at(self) -> datetime: ...
    @property
    def evaluation(self) -> str: ...
    @property
    def status(self) -> str: ...


@dataclass(frozen=True)
class MaintenanceEffect:
    """What the active windows do to one observation; ``indexes`` point into the input list."""

    kind: EffectKind
    indexes: tuple[int, ...]


def _require_aware(now: datetime) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("the clock must be timezone-aware")


def window_phase(window: WindowLike, now: datetime) -> WindowPhase:
    _require_aware(now)
    if window.status == "cancelled":
        return "cancelled"
    if now < window.starts_at:
        return "upcoming"
    if now < window.ends_at:
        return "active"
    return "expired"


def effect_of_windows(
    windows: Sequence[WindowLike],
    scopes: AbstractSet[tuple[str, str]],
    now: datetime,
) -> MaintenanceEffect:
    """Union of the windows that are active at ``now`` and cover one of ``scopes``."""
    active = tuple(
        index
        for index, window in enumerate(windows)
        if window_phase(window, now) == "active" and (window.scope.kind, window.scope.ref) in scopes
    )
    if not active:
        return MaintenanceEffect("none", ())
    disabling = any(windows[index].evaluation == "disable" for index in active)
    return MaintenanceEffect("disable" if disabling else "suppress", active)
