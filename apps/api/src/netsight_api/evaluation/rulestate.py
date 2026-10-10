"""Per (rule, version, entity) engine state, bounded and replaced rather than mutated.

State lives in memory: the engine is deterministic, so after a restart it simply re-derives the
phase from fresh observations (incident creation is protected by the durable links, repeat
pages by the delivery ledger). The store is bounded: an ``inactive`` entry carries no
information and is evicted first; an entry that is pending or firing is never evicted (losing it
would re-notify or restart a debounce), so when the store is full of those, new entities are
simply not tracked and the cycle reports itself truncated.
"""

from __future__ import annotations

from collections.abc import Set as AbstractSet
from dataclasses import replace
from typing import Final

from netsight_api.alerting.engine import RuleState

StateKey = tuple[str, int, str]  # (rule id, rule version, entity)
DEFAULT_MAX_ENTRIES: Final = 50_000


class RuleStateStore:
    def __init__(self, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        self._max = max_entries
        self._states: dict[StateKey, RuleState] = {}

    def __len__(self) -> int:
        return len(self._states)

    def get(self, key: StateKey) -> RuleState:
        return self._states.get(key, RuleState())

    def put(self, key: StateKey, state: RuleState) -> bool:
        """Store ``state``; False when the store is full of live entries and ``key`` is new."""
        if key not in self._states and len(self._states) >= self._max:
            self._evict_inactive()
            if len(self._states) >= self._max:
                return False
        self._states[key] = state
        return True

    def gap(self, rule_id: str, version: int, *, seen: AbstractSet[str] | None = None) -> None:
        """A data gap for the rule's entities (all of them, or those not in ``seen``): a pending
        debounce restarts, a firing alert is kept (a gap is not a recovery)."""
        for key, state in list(self._states.items()):
            if key[0] != rule_id or key[1] != version:
                continue
            if seen is not None and key[2] in seen:
                continue
            if state.phase == "pending":
                self._states[key] = replace(state, phase="inactive", since=None)

    def retain_rules(self, live: AbstractSet[tuple[str, int]]) -> None:
        """Forget the state of every rule version that is no longer active."""
        for key in [k for k in self._states if (k[0], k[1]) not in live]:
            del self._states[key]

    def _evict_inactive(self) -> None:
        for key in [k for k, s in self._states.items() if s.phase == "inactive"]:
            del self._states[key]
