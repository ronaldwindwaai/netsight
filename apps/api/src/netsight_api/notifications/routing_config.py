"""Where notifications go: the routing table, from the environment (fail closed).

* ``NETSIGHT_NOTIFY_EMAIL_TO``: comma-separated recipient addresses (at most 50).
* ``NETSIGHT_NOTIFY_PUSH_DEVICES``: comma-separated push device references (at most 50; they
  are :class:`Secret` values, never shown in a repr, log or error).
* ``NETSIGHT_NOTIFY_MIN_SEVERITY``: ``info|low|medium|high|critical`` (default ``high``): an
  alert below it is not sent to these destinations.

Unset means nobody is notified. An invalid value raises ``ValueError`` (the message never echoes
the value) so a typo fails start-up instead of silently dropping pages. Per-team and per-site
routing by label is supported by ``RoutingRule`` itself; this table is the single, flat default
until destinations are managed in the database (a follow-up).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Final, get_args

from netsight_api.notifications.dispatcher import RoutingRule
from netsight_api.notifications.models import Destination, EmailDestination, PushDestination
from netsight_api.notifications.secret import Secret
from netsight_api.schemas import AlertSeverity

MAX_DESTINATIONS_PER_CHANNEL: Final = 50
_SEVERITIES: Final = frozenset(get_args(AlertSeverity))


def _items(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def _bounded(items: list[str], name: str) -> list[str]:
    unique = list(dict.fromkeys(items))
    if len(unique) > MAX_DESTINATIONS_PER_CHANNEL:
        raise ValueError(f"{name} has too many entries")
    return unique


def _emails(raw: str) -> list[Destination]:
    destinations: list[Destination] = []
    seen: set[str] = set()
    for address in _items(raw):
        try:
            destination = EmailDestination(address)
        except ValueError:
            raise ValueError("NETSIGHT_NOTIFY_EMAIL_TO holds an invalid address") from None
        if destination.address.lower() not in seen:
            seen.add(destination.address.lower())
            destinations.append(destination)
    _bounded([d.label for d in destinations], "NETSIGHT_NOTIFY_EMAIL_TO")
    return destinations


def _devices(raw: str) -> list[Destination]:
    destinations: list[Destination] = []
    for reference in _bounded(_items(raw), "NETSIGHT_NOTIFY_PUSH_DEVICES"):
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in reference):
            raise ValueError("NETSIGHT_NOTIFY_PUSH_DEVICES holds an invalid device reference")
        try:
            destinations.append(PushDestination(Secret(reference)))
        except ValueError:
            raise ValueError(
                "NETSIGHT_NOTIFY_PUSH_DEVICES holds an invalid device reference"
            ) from None
    return destinations


def routing_rules_from_env(env: Mapping[str, str] | None = None) -> tuple[RoutingRule, ...]:
    source = os.environ if env is None else env
    severity = source.get("NETSIGHT_NOTIFY_MIN_SEVERITY", "").strip().lower() or "high"
    if severity not in _SEVERITIES:
        raise ValueError("NETSIGHT_NOTIFY_MIN_SEVERITY must be info, low, medium, high or critical")
    rules: list[RoutingRule] = []
    for destinations in (
        _emails(source.get("NETSIGHT_NOTIFY_EMAIL_TO", "")),
        _devices(source.get("NETSIGHT_NOTIFY_PUSH_DEVICES", "")),
    ):
        if destinations:
            rules.append(RoutingRule(severity, tuple(destinations)))  # type: ignore[arg-type]
    return tuple(rules)
