"""BodySizeLimitMiddleware: an over-cap body never reaches the handler, even when chunked."""

from __future__ import annotations

import json
from typing import Annotated, Any

import pytest
from fastapi import Body, FastAPI
from starlette.types import Message, Receive, Scope, Send

from netsight_api.body_limit import BodySizeLimitMiddleware

CAP = 100


def _scope(method: str, headers: list[tuple[bytes, bytes]] | None = None) -> Scope:
    return {
        "type": "http",
        "method": method,
        "path": "/act",
        "raw_path": b"/act",
        "root_path": "",
        "query_string": b"",
        "scheme": "http",
        "server": ("test", 80),
        "client": ("test", 1),
        "headers": headers or [],
        "state": {},
    }


class _Driver:
    """Feeds scripted ASGI messages and records what the client would see."""

    def __init__(self, messages: list[Message]) -> None:
        self._messages = list(messages)
        self.sent: list[Message] = []

    async def receive(self) -> Message:
        if self._messages:
            return self._messages.pop(0)
        return {"type": "http.disconnect"}

    async def send(self, message: Message) -> None:
        self.sent.append(message)

    @property
    def status(self) -> int | None:
        for message in self.sent:
            if message["type"] == "http.response.start":
                return int(message["status"])
        return None

    @property
    def body(self) -> bytes:
        return b"".join(m.get("body", b"") for m in self.sent if m["type"] == "http.response.body")


def _chunks(*parts: bytes) -> list[Message]:
    return [
        {"type": "http.request", "body": part, "more_body": index < len(parts) - 1}
        for index, part in enumerate(parts)
    ]


class _RecordingApp:
    """Reads the whole body, then 'commits' (records) and answers 200."""

    def __init__(self) -> None:
        self.commits: list[bytes] = []
        self.called = False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.called = True
        body = b""
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break
        self.commits.append(body)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


async def _run(
    app: Any,
    method: str,
    messages: list[Message],
    headers: list[tuple[bytes, bytes]] | None = None,
) -> _Driver:
    driver = _Driver(messages)
    middleware = BodySizeLimitMiddleware(app, max_bytes=CAP)
    await middleware(_scope(method, headers), driver.receive, driver.send)
    return driver


@pytest.mark.asyncio
async def test_valid_json_split_across_chunks_then_overflow_has_no_side_effect() -> None:
    app = _RecordingApp()
    valid = json.dumps({"body": "x" * 20}).encode()
    messages = _chunks(valid[:10], valid[10:], b"a" * (CAP + 1))
    driver = await _run(app, "POST", messages)
    assert driver.status == 413
    assert json.loads(driver.body)["error"]["code"] == "PAYLOAD_TOO_LARGE"
    assert app.commits == []
    assert app.called is False


@pytest.mark.asyncio
async def test_chunked_body_within_cap_is_delivered_intact() -> None:
    app = _RecordingApp()
    driver = await _run(app, "POST", _chunks(b"a" * 40, b"b" * 40, b"c" * 20))
    assert driver.status == 200
    assert app.commits == [b"a" * 40 + b"b" * 40 + b"c" * 20]


@pytest.mark.asyncio
async def test_body_exactly_at_cap_is_allowed() -> None:
    app = _RecordingApp()
    driver = await _run(app, "POST", _chunks(b"a" * CAP))
    assert driver.status == 200
    assert app.commits == [b"a" * CAP]


@pytest.mark.asyncio
async def test_delete_with_oversized_chunked_body_is_rejected() -> None:
    app = _RecordingApp()
    driver = await _run(app, "DELETE", _chunks(b"a" * 60, b"b" * 60))
    assert driver.status == 413
    assert app.called is False


@pytest.mark.asyncio
async def test_declared_oversize_is_rejected_before_reading() -> None:
    app = _RecordingApp()
    driver = await _run(app, "POST", [], headers=[(b"content-length", str(CAP + 1).encode())])
    assert driver.status == 413
    assert app.called is False


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [b"abc", b"-5", b"", b"1e9", b"\xff"])
async def test_malformed_content_length_does_not_bypass_the_cap(value: bytes) -> None:
    app = _RecordingApp()
    driver = await _run(
        app, "POST", _chunks(b"a" * (CAP + 1)), headers=[(b"content-length", value)]
    )
    assert driver.status == 413
    assert app.called is False


@pytest.mark.asyncio
async def test_malformed_content_length_with_small_body_still_works() -> None:
    app = _RecordingApp()
    driver = await _run(app, "POST", _chunks(b"hi"), headers=[(b"content-length", b"abc")])
    assert driver.status == 200
    assert app.commits == [b"hi"]


@pytest.mark.asyncio
async def test_client_disconnect_mid_body_never_reaches_the_app() -> None:
    app = _RecordingApp()
    messages: list[Message] = [
        {"type": "http.request", "body": b"abc", "more_body": True},
        {"type": "http.disconnect"},
    ]
    driver = await _run(app, "POST", messages)
    assert app.called is False
    assert driver.status is None


@pytest.mark.asyncio
async def test_get_is_passed_through_untouched() -> None:
    app = _RecordingApp()
    driver = await _run(app, "GET", _chunks(b"a" * (CAP * 5)))
    assert driver.status == 200


@pytest.mark.asyncio
async def test_optional_body_action_is_not_executed_on_overflow() -> None:
    api = FastAPI()
    executed: list[str | None] = []

    @api.post("/act")
    async def act(payload: Annotated[dict[str, Any] | None, Body()] = None) -> dict[str, bool]:
        executed.append("done")
        return {"ok": True}

    overflow = await _run(api, "POST", _chunks(b'{"note":"', b"a" * (CAP + 1), b'"}'))
    assert overflow.status == 413
    assert executed == []

    fine = await _run(
        api, "POST", _chunks(b'{"note":"x"}'), headers=[(b"content-type", b"application/json")]
    )
    assert fine.status == 200
    assert executed == ["done"]
