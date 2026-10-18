"""The model provider interface (Step 10, AI-ARCHITECTURE "Model gateway").

Domain code never speaks to a vendor: it asks a ``ModelProvider`` to ``complete`` a list of messages
and gets text back or a ``ProviderError``. Whether any model exists is decided by the environment
only, and **no key or model name is in the source**:

* ``NETSIGHT_AI_BASE_URL``  an OpenAI-compatible base URL (a local server or a gateway);
* ``NETSIGHT_AI_MODEL``     the model name;
* ``NETSIGHT_AI_API_KEY``   optional bearer key (never logged, never in an error, never in a repr);
* ``NETSIGHT_AI_ALLOW_EXTERNAL``  ``true`` to allow a non-loopback endpoint. Evidence is sent to the
  model, so leaving the host is an explicit decision, not a default;
* ``NETSIGHT_AI_TIMEOUT_SECONDS``  per-request budget (default 30).

Anything unusable (missing, malformed, credentials in the URL, a key over cleartext to another host,
external without opt-in) is **not configured**: the copilot reports ``not-connected``. The request
carries no tools or functions: the model can only return text. Redirects are not followed and the
response is size-capped.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
from dataclasses import dataclass
from functools import cache
from typing import Final, Literal, Protocol
from urllib.parse import urlsplit

import httpx

_LOGGER: Final = logging.getLogger("netsight_api")
BASE_URL_ENV: Final = "NETSIGHT_AI_BASE_URL"
MODEL_ENV: Final = "NETSIGHT_AI_MODEL"
KEY_ENV: Final = "NETSIGHT_AI_API_KEY"
EXTERNAL_ENV: Final = "NETSIGHT_AI_ALLOW_EXTERNAL"
TIMEOUT_ENV: Final = "NETSIGHT_AI_TIMEOUT_SECONDS"
DEFAULT_TIMEOUT: Final = 30.0
MAX_TIMEOUT: Final = 120.0
MAX_TOKENS: Final = 1_024
MAX_RESPONSE_BYTES: Final = 256 * 1024
MAX_REPLY_CHARS: Final = 16_000
_LOOPBACK: Final = frozenset({"localhost", "127.0.0.1", "::1"})


@dataclass(frozen=True)
class ModelMessage:
    role: Literal["system", "user"]
    content: str


class ProviderError(Exception):
    """The model could not be used. The message is fixed text: never a body, URL or key."""


class ModelProvider(Protocol):
    async def complete(self, messages: list[ModelMessage]) -> str: ...


class OpenAICompatibleProvider:
    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str | None,
        timeout: float,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._model = model
        self._key = api_key
        self._timeout = timeout
        self._transport = transport

    def __repr__(self) -> str:
        return "OpenAICompatibleProvider(<configured>)"

    async def complete(self, messages: list[ModelMessage]) -> str:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._key:
            headers["Authorization"] = f"Bearer {self._key}"
        body = {
            "model": self._model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": 0,
            "max_tokens": MAX_TOKENS,
            "stream": False,
        }
        try:
            async with (
                httpx.AsyncClient(
                    timeout=self._timeout,
                    follow_redirects=False,
                    trust_env=False,  # no HTTP(S)_PROXY: evidence goes only where configured
                    transport=self._transport,
                ) as client,
                client.stream("POST", self._url, json=body, headers=headers) as response,
            ):
                if response.status_code != 200:
                    raise ProviderError("the model endpoint refused the request")
                raw = await _capped(response)
        except httpx.HTTPError:
            raise ProviderError("the model endpoint could not be reached") from None
        return _content(raw)


async def _capped(response: httpx.Response) -> bytes:
    chunks: list[bytes] = []
    size = 0
    async for part in response.aiter_bytes():
        size += len(part)
        if size > MAX_RESPONSE_BYTES:
            raise ProviderError("the model response is too large")
        chunks.append(part)
    return b"".join(chunks)


def _content(raw: bytes) -> str:
    try:
        payload = json.loads(raw)
        content = payload["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError):
        raise ProviderError("the model response was not understood") from None
    if not isinstance(content, str) or not content.strip():
        raise ProviderError("the model returned no text")
    if len(content) > MAX_REPLY_CHARS:
        raise ProviderError("the model reply is too large")
    return content


def _valid_url(value: str) -> bool:
    try:
        parts = urlsplit(value)
        return (
            parts.scheme in {"http", "https"}
            and parts.hostname is not None
            and parts.username is None
            and parts.password is None
            and not parts.query
            and not parts.fragment
        )
    except ValueError:
        return False


def _never_a_model_host(host: str) -> bool:
    """Link-local (cloud metadata), multicast and unspecified literals are never a model endpoint."""
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return address.is_link_local or address.is_multicast or address.is_unspecified


def _timeout() -> float:
    raw = os.environ.get(TIMEOUT_ENV, "").strip()
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_TIMEOUT
    return value if 1.0 <= value <= MAX_TIMEOUT else DEFAULT_TIMEOUT


def configured_provider() -> ModelProvider | None:
    """The provider the environment describes, or ``None`` (not-connected). Never raises."""
    base_url = os.environ.get(BASE_URL_ENV, "").strip()
    model = os.environ.get(MODEL_ENV, "").strip()
    if not base_url or not model:
        return None
    if not _valid_url(base_url):
        _warn("the model URL is not a usable http(s) URL")
        return None
    parts = urlsplit(base_url)
    if parts.hostname is not None and _never_a_model_host(parts.hostname):
        _warn("the model endpoint address is not allowed")
        return None
    local = parts.hostname in _LOOPBACK
    if not local and os.environ.get(EXTERNAL_ENV, "").strip().lower() != "true":
        _warn("the model endpoint is not on this host and external use is not enabled")
        return None
    key = os.environ.get(KEY_ENV, "").strip() or None
    if key and parts.scheme != "https" and not local:
        _warn("a model key is set but the endpoint is not https")
        return None
    return OpenAICompatibleProvider(base_url=base_url, model=model, api_key=key, timeout=_timeout())


@cache
def _warn(reason: str) -> None:
    _LOGGER.warning("the copilot model is not connected: %s", reason)
