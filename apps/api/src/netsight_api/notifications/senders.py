"""The sender contract and the test fake. No production email or push sender exists yet.

Production email (SMTP relay) and push (provider) senders need infrastructure decisions that
are still open; the dispatcher only depends on this Protocol. The webhook sender lives in
``webhook.py``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from netsight_api.notifications.models import (
    ChannelKind,
    Destination,
    NotificationPayload,
    SendResult,
)


class NotificationSender(Protocol):
    """Delivers one payload to one destination of its channel.

    Expected failures are *returned* as a ``SendResult`` with a static code; implementations
    must not put provider messages, credentials or payload text in the code.
    """

    channel: ChannelKind

    def send(self, destination: Destination, payload: NotificationPayload) -> SendResult: ...


class FakeSender:
    """Records what would have been sent; scripted results (or exceptions) in order, then OK."""

    def __init__(self, channel: ChannelKind, script: Sequence[SendResult | Exception] = ()) -> None:
        self.channel = channel
        self._script = list(script)
        self.calls: list[tuple[str, NotificationPayload]] = []

    def send(self, destination: Destination, payload: NotificationPayload) -> SendResult:
        if destination.kind != self.channel:
            return SendResult("permanent", "DESTINATION_MISMATCH")
        self.calls.append((destination.label, payload))
        if not self._script:
            return SendResult("sent", "OK")
        outcome = self._script.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome
