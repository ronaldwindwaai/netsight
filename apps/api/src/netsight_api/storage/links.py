"""Alert -> incident links: the durable memory that makes incident creation idempotent.

Two namespaces share one table (``alert_incident_links``):

* ``alert``: the alert fingerprint -> the incident that carries that alert;
* ``group``: the group key -> the current incident of that group (incident policy ``group``).

A link says only which incident a key currently points at; whether that incident is still open
is judged from the incident itself, so a human resolving an incident is what frees the key (the
evaluator never resolves anything). ``claim`` is compare-and-set, which is what keeps the
number of incidents per key at one even when two evaluators race: exactly one claim wins.
A loser holds an incident nobody links to; the caller notes that on the loser's timeline
(there is no delete, by design). Running a single evaluator avoids the race altogether.

Each link also records whether the alert was seen to *recover* since it was claimed
(``mark_recovered``; ``claim`` clears it). That is what lets a restarted evaluator behave like a
running one: an alert that is still firing after a human resolved its incident gets no new
incident until it has recovered at least once.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable
from typing import Final, Literal, Protocol

from netsight_api.storage import lifecycle
from netsight_api.storage.errors import NotFoundError

LinkKind = Literal["alert", "group"]
LINK_KEY: Final = re.compile(r"^[0-9a-f]{32}$")
_KINDS: Final = ("alert", "group")


class AlertIncidentLinkRepository(Protocol):
    def get(self, kind: LinkKind, key: str) -> str | None:
        """The incident id the key points at, or None."""
        ...

    def claim(self, kind: LinkKind, key: str, *, incident_id: str, replacing: str | None) -> bool:
        """Point ``key`` at ``incident_id`` if it currently points at ``replacing`` (None: at
        nothing). True when the key now points at ``incident_id``; False when another writer got
        there first (nothing changed). ``NotFoundError`` when the incident does not exist.
        A successful claim, including one that re-claims the same incident, clears the
        recovered mark."""
        ...

    def mark_recovered(self, kind: LinkKind, key: str) -> bool:
        """Record that the alert recovered. True when a link existed and was not yet marked."""
        ...

    def is_recovered(self, kind: LinkKind, key: str) -> bool:
        """True when a link exists and carries the recovered mark."""
        ...


def check_link_args(
    kind: str, key: str, incident_id: str | None = None, replacing: str | None = None
) -> None:
    if kind not in _KINDS:
        raise ValueError("kind must be 'alert' or 'group'")
    if not isinstance(key, str) or LINK_KEY.fullmatch(key) is None:
        raise ValueError("key must be 32 lowercase hexadecimal characters")
    for value in (incident_id, replacing):
        if value is not None and lifecycle.parse_id("incident", value) is None:
            raise ValueError("incident id is malformed")
    if incident_id is None and replacing is not None:
        raise ValueError("incident id is required")


class InMemoryAlertIncidentLinkRepository:
    """Unit-test implementation; ``incident_exists`` stands in for the foreign key."""

    def __init__(self, *, incident_exists: Callable[[str], bool]) -> None:
        self._incident_exists = incident_exists
        self._lock = threading.Lock()
        self._links: dict[tuple[str, str], str] = {}
        self._recovered: set[tuple[str, str]] = set()

    def get(self, kind: LinkKind, key: str) -> str | None:
        check_link_args(kind, key)
        with self._lock:
            return self._links.get((kind, key))

    def claim(self, kind: LinkKind, key: str, *, incident_id: str, replacing: str | None) -> bool:
        check_link_args(kind, key, incident_id, replacing)
        if not self._incident_exists(incident_id):
            raise NotFoundError("incident not found")
        with self._lock:
            if self._links.get((kind, key)) != replacing:
                return False
            self._links[(kind, key)] = incident_id
            self._recovered.discard((kind, key))
            return True

    def mark_recovered(self, kind: LinkKind, key: str) -> bool:
        check_link_args(kind, key)
        with self._lock:
            if (kind, key) not in self._links or (kind, key) in self._recovered:
                return False
            self._recovered.add((kind, key))
            return True

    def is_recovered(self, kind: LinkKind, key: str) -> bool:
        check_link_args(kind, key)
        with self._lock:
            return (kind, key) in self._recovered
