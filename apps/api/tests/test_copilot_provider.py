"""The model provider interface: not-connected unless configured via the environment (Step 10)."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from netsight_api.copilot import provider
from netsight_api.copilot.provider import ModelMessage, ProviderError

KEY = "k-test-0123456789abcdef"
MESSAGES = [ModelMessage("system", "rules"), ModelMessage("user", "question")]


def env(monkeypatch: pytest.MonkeyPatch, **values: str) -> None:
    for name in (
        "NETSIGHT_AI_BASE_URL",
        "NETSIGHT_AI_MODEL",
        "NETSIGHT_AI_API_KEY",
        "NETSIGHT_AI_ALLOW_EXTERNAL",
        "NETSIGHT_AI_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_without_configuration_there_is_no_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    env(monkeypatch)
    assert provider.configured_provider() is None
    env(monkeypatch, NETSIGHT_AI_BASE_URL="http://127.0.0.1:11434/v1")
    assert provider.configured_provider() is None, "a model name is required"
    env(monkeypatch, NETSIGHT_AI_MODEL="local-model")
    assert provider.configured_provider() is None, "a base URL is required"


@pytest.mark.parametrize(
    "url",
    [
        "ftp://127.0.0.1/v1",
        "file:///etc/passwd",
        "http://user:pw@127.0.0.1/v1",
        "http://127.0.0.1/v1?x=1",
        "http://127.0.0.1/v1#frag",
        "http:///v1",
        "not a url",
    ],
)
def test_unusable_urls_are_treated_as_not_configured(
    monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    env(monkeypatch, NETSIGHT_AI_BASE_URL=url, NETSIGHT_AI_MODEL="m")
    assert provider.configured_provider() is None


def test_a_non_loopback_endpoint_needs_an_explicit_external_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env(monkeypatch, NETSIGHT_AI_BASE_URL="https://models.example.net/v1", NETSIGHT_AI_MODEL="m")
    assert provider.configured_provider() is None, "evidence must not leave the host by accident"
    env(
        monkeypatch,
        NETSIGHT_AI_BASE_URL="https://models.example.net/v1",
        NETSIGHT_AI_MODEL="m",
        NETSIGHT_AI_ALLOW_EXTERNAL="true",
    )
    assert provider.configured_provider() is not None


def test_a_key_is_never_sent_over_cleartext_to_another_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env(
        monkeypatch,
        NETSIGHT_AI_BASE_URL="http://models.example.net/v1",
        NETSIGHT_AI_MODEL="m",
        NETSIGHT_AI_ALLOW_EXTERNAL="true",
        NETSIGHT_AI_API_KEY=KEY,
    )
    assert provider.configured_provider() is None


def make(handler, **kwargs) -> provider.OpenAICompatibleProvider:  # type: ignore[no-untyped-def]
    return provider.OpenAICompatibleProvider(
        base_url="http://127.0.0.1:11434/v1",
        model="local-model",
        api_key=kwargs.pop("api_key", None),
        timeout=5.0,
        transport=httpx.MockTransport(handler),
        **kwargs,
    )


@pytest.mark.asyncio
async def test_a_request_is_a_post_with_the_messages_and_no_sampling_freedom() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "hello"}}]})

    reply = await make(handler, api_key=KEY).complete(MESSAGES)
    assert reply == "hello"
    request = seen[0]
    assert request.method == "POST"
    assert str(request.url) == "http://127.0.0.1:11434/v1/chat/completions"
    assert request.headers["authorization"] == f"Bearer {KEY}"
    body = json.loads(request.content)
    assert body["model"] == "local-model"
    assert body["temperature"] == 0
    assert body["stream"] is False
    assert body["max_tokens"] <= 2048
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    assert "tools" not in body and "functions" not in body and "tool_choice" not in body


@pytest.mark.asyncio
async def test_no_key_means_no_authorization_header() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "x"}}]})

    await make(handler).complete(MESSAGES)
    assert "authorization" not in seen[0].headers


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500, text=f"boom {KEY}"),
        httpx.Response(401, text="no"),
        httpx.Response(302, headers={"location": "http://evil.example/"}),
        httpx.Response(200, text="not json"),
        httpx.Response(200, json={"choices": []}),
        httpx.Response(200, json={"choices": [{"message": {"content": 5}}]}),
        httpx.Response(200, json={"choices": [{"message": {"content": ""}}]}),
        httpx.Response(200, content=b"x" * (provider.MAX_RESPONSE_BYTES + 10)),
    ],
)
@pytest.mark.asyncio
async def test_every_failure_is_a_provider_error_that_never_carries_the_key_or_body(
    response: httpx.Response,
) -> None:
    provider_ = make(lambda _request: response, api_key=KEY)
    with pytest.raises(ProviderError) as caught:
        await provider_.complete(MESSAGES)
    assert KEY not in str(caught.value) and KEY not in repr(provider_)
    assert "boom" not in str(caught.value)


@pytest.mark.asyncio
async def test_a_timeout_is_a_provider_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    with pytest.raises(ProviderError):
        await make(handler).complete(MESSAGES)


@pytest.mark.asyncio
async def test_a_reply_over_the_content_cap_is_a_provider_error() -> None:
    big = "y" * (provider.MAX_REPLY_CHARS + 1)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": big}}]})

    with pytest.raises(ProviderError):
        await make(handler).complete(MESSAGES)


def test_the_environment_proxy_is_never_used(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    real = httpx.AsyncClient

    class Recorder(real):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            captured.update(kwargs)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(provider.httpx, "AsyncClient", Recorder)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": "x"}}]})

    import asyncio

    asyncio.run(make(handler).complete(MESSAGES))
    assert captured["trust_env"] is False
    assert captured["follow_redirects"] is False


@pytest.mark.parametrize(
    "host",
    ["169.254.169.254", "169.254.0.1", "0.0.0.0", "[fe80::1]", "224.0.0.1", "[::]"],
)
def test_link_local_metadata_and_unspecified_addresses_are_refused_even_when_external_is_allowed(
    monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    env(
        monkeypatch,
        NETSIGHT_AI_BASE_URL=f"https://{host}/v1",
        NETSIGHT_AI_MODEL="m",
        NETSIGHT_AI_ALLOW_EXTERNAL="true",
    )
    assert provider.configured_provider() is None
