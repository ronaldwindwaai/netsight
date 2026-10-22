"""The append-only, hash-chained history of an action request (Step 12).

Each event's ``hash`` covers the request id, its own fields and the previous event's hash, so editing
an event, dropping one, reordering them, truncating the start or moving them to another request all
fail ``verify_chain``. This makes tampering *detectable*; the chain alone is not tamper-proof storage
(the PostgreSQL store adds triggers that refuse edits, but its owner role can still disable them), and
the audit log remains the independent record of who did what.
"""

from __future__ import annotations

import itertools
from collections.abc import Sequence
from datetime import datetime

from netsight_api.actions.model import canonical, sha256_hex
from netsight_api.schemas_actions import (
    ZERO_HASH,
    ActionHistoryEvent,
    ActionRequest,
    EventType,
    RequestState,
)

__all__ = ["ZERO_HASH", "history_matches", "next_event", "verify_chain"]


def _hash(action_id: str, digest: str, event: ActionHistoryEvent) -> str:
    """Covers the request id, the request digest (so the content an approver saw) and the event."""
    body = event.model_dump(mode="json", exclude={"hash"})
    return sha256_hex(canonical({"action": action_id, "digest": digest, **body}))


def next_event(
    action_id: str,
    digest: str,
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
    return draft.model_copy(update={"hash": _hash(action_id, digest, draft)})


def verify_chain(action_id: str, events: Sequence[ActionHistoryEvent], digest: str) -> bool:
    previous: ActionHistoryEvent | None = None
    for event in events:
        expected_seq = 1 if previous is None else previous.seq + 1
        expected_prev = ZERO_HASH if previous is None else previous.hash
        if event.seq != expected_seq or event.prev_hash != expected_prev:
            return False
        if event.hash != _hash(action_id, digest, event):
            return False
        previous = event
    return previous is not None


def history_matches(request: ActionRequest, events: Sequence[ActionHistoryEvent]) -> bool:
    """The chain verifies *and* the history agrees with the request it belongs to.

    A chain alone cannot see its own tail being cut off; the last event must also be the request's
    current version and state, the approvers on the request must be those the history recorded, and
    every step must start where the previous one ended. The chain is bound to the request's digest, which
    a store recomputes from the content it holds, so the content is bound to the history too.
    """
    if not verify_chain(request.id, events, request.digest):
        return False
    last = events[-1]
    if last.seq != request.version or last.to_state != request.state:
        return False
    # Who approved, and when, is what the history recorded when each approval happened.
    approved = [(x.actor_id, x.at) for x in events if x.type == "approved"]
    if [(a.approver_id, a.approved_at) for a in request.approvals] != approved:
        return False
    return all(
        later.from_state in (None, earlier.to_state)
        for earlier, later in itertools.pairwise(events)
    )
