"""The append-only, hash-chained history of an action request (Step 12).

Each event's ``hash`` covers the request id, its own fields and the previous event's hash, so editing
an event, dropping one, reordering them, truncating the start or moving them to another request all
fail ``verify_chain``. This makes tampering *detectable*; it is not tamper-proof storage (the store is
in memory today), and the audit log remains the independent record of who did what.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from netsight_api.actions.model import canonical, sha256_hex
from netsight_api.schemas_actions import ZERO_HASH, ActionHistoryEvent, EventType, RequestState

__all__ = ["ZERO_HASH", "next_event", "verify_chain"]


def _hash(action_id: str, event: ActionHistoryEvent) -> str:
    body = event.model_dump(mode="json", exclude={"hash"})
    return sha256_hex(canonical({"action": action_id, **body}))


def next_event(
    action_id: str,
    previous: ActionHistoryEvent | None,
    *,
    at: datetime,
    type: EventType,
    actor_id: str | None,
    from_state: RequestState | None,
    to_state: RequestState,
    code: str,
    note: str | None = None,
) -> ActionHistoryEvent:
    draft = ActionHistoryEvent(
        seq=1 if previous is None else previous.seq + 1,
        at=at,
        type=type,
        actor_id=actor_id,
        from_state=from_state,
        to_state=to_state,
        code=code,
        note=note,
        prev_hash=ZERO_HASH if previous is None else previous.hash,
        hash=ZERO_HASH,
    )
    return draft.model_copy(update={"hash": _hash(action_id, draft)})


def verify_chain(action_id: str, events: Sequence[ActionHistoryEvent]) -> bool:
    previous: ActionHistoryEvent | None = None
    for event in events:
        expected_seq = 1 if previous is None else previous.seq + 1
        expected_prev = ZERO_HASH if previous is None else previous.hash
        if event.seq != expected_seq or event.prev_hash != expected_prev:
            return False
        if event.hash != _hash(action_id, event):
            return False
        previous = event
    return previous is not None
