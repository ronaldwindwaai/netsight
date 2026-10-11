"""Strict parsing of a read route's query string (Step 8).

The route, not the framework, decides what a query may contain, so that a refusal can be audited and
a hostile value is never echoed: an unknown name, a repeated name, a malformed or out-of-range value
is a ``QueryError`` and the route answers 422 with a fixed message. Values are validated against the
exact grammar of their parameter (digits only for numbers, ``true``/``false`` for booleans, an
allow-list for words, bounded text without control characters for free text).
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from typing import Final, Literal, TypeVar, cast

from fastapi import Request

_DIGITS: Final = re.compile(r"^[0-9]{1,9}$")
_CONTROL: Final = re.compile(r"[\x00-\x1f\x7f-\x9f]")
T = TypeVar("T", bound=str)


class QueryError(ValueError):
    """The query string is not acceptable; the message is static and never echoes input."""


def single_values(request: Request, allowed: Collection[str]) -> dict[str, str]:
    """The query as name -> value; unknown or repeated names are refused."""
    values: dict[str, str] = {}
    for name, value in request.query_params.multi_items():
        if name not in allowed:
            raise QueryError("unknown parameter")
        if name in values:
            raise QueryError("repeated parameter")
        values[name] = value
    return values


def integer(values: Mapping[str, str], name: str, default: int, low: int, high: int) -> int:
    raw = values.get(name)
    if raw is None:
        return default
    if _DIGITS.fullmatch(raw) is None or not low <= int(raw) <= high:
        raise QueryError("invalid number")
    return int(raw)


def word[T: str](values: Mapping[str, str], name: str, allowed: Collection[T]) -> T | None:
    raw = values.get(name)
    if raw is None:
        return None
    if raw not in allowed:
        raise QueryError("invalid choice")
    return cast(T, raw)


def boolean(values: Mapping[str, str], name: str) -> bool | None:
    raw = values.get(name)
    if raw is None:
        return None
    if raw not in ("true", "false"):
        raise QueryError("invalid flag")
    return raw == "true"


def text(values: Mapping[str, str], name: str, maximum: int) -> str | None:
    raw = values.get(name)
    if raw is None:
        return None
    if not 1 <= len(raw) <= maximum or _CONTROL.search(raw) or not raw.strip():
        raise QueryError("invalid text")
    return raw


Page = Literal["page", "page_size"]
