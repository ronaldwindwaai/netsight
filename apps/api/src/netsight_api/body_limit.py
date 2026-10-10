"""Request body size cap for state-changing API requests.

Field limits alone let a client make the server buffer an arbitrarily large body before
validation runs. This pure-ASGI middleware rejects a write whose declared
``Content-Length`` exceeds the cap, and buffers (at most the cap of) every other body
before the application runs, so a chunked overflow is answered 413 without the handler
ever seeing a truncated body. Malformed lengths fall back to the counted bytes. Reads are
not capped.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from starlette.types import ASGIApp, Message, Receive, Scope, Send

MAX_REQUEST_BODY_BYTES = 1024 * 1024
_CAPPED_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_CORRELATION_HEADER = b"x-correlation-id"


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int = MAX_REQUEST_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in _CAPPED_METHODS:
            await self.app(scope, receive, send)
            return
        if self._declared_length(scope) > self.max_bytes:
            await self._reject(scope, send)
            return

        # Buffer up to the cap before the application runs. The handler therefore never sees
        # a truncated body and cannot act on one: an overflow is answered 413 with the app
        # untouched, and a disconnect mid-body abandons the request.
        chunks: list[bytes] = []
        received = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return
            chunk = message.get("body", b"")
            received += len(chunk)
            if received > self.max_bytes:
                await self._reject(scope, send)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        replayed = False

        async def replay_receive() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)

    @staticmethod
    def _declared_length(scope: Scope) -> int:
        for name, value in scope["headers"]:
            if name == b"content-length":
                try:
                    return int(value)
                except ValueError:
                    return 0
        return 0

    @staticmethod
    def _correlation_id(scope: Scope) -> str:
        state = scope.get("state") or {}
        value = state.get("correlation_id")
        return value if isinstance(value, str) else str(uuid4())

    async def _reject(self, scope: Scope, send: Send) -> None:
        correlation_id = self._correlation_id(scope)
        body: dict[str, Any] = {
            "error": {
                "code": "PAYLOAD_TOO_LARGE",
                "message": "Request body is too large",
                "correlation_id": correlation_id,
            }
        }
        payload = json.dumps(body).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode("ascii")),
                    (_CORRELATION_HEADER, correlation_id.encode("ascii", "replace")),
                    (b"connection", b"close"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": payload})
