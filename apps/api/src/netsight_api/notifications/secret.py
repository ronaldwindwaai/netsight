"""A value that must never reach a log line, a repr or a traceback."""

from __future__ import annotations

import hmac
from typing import Any, NoReturn


class Secret:
    """Wraps a credential (webhook URL, header value, push token).

    ``repr`` and ``str`` never show the value; it is unhashable and cannot be pickled, so it
    cannot leak through a cache key or a serialised queue. ``reveal`` is called only at the
    moment the value is put on the wire.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret(***)"

    def __str__(self) -> str:
        return "***"

    def __format__(self, spec: str) -> str:
        return format("***", spec)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secret):
            return NotImplemented
        return hmac.compare_digest(self._value.encode("utf-8"), other._value.encode("utf-8"))

    __hash__ = None  # type: ignore[assignment]

    def __reduce__(self) -> NoReturn:
        raise TypeError("a Secret cannot be serialised")

    def __copy__(self) -> Secret:
        return self

    def __deepcopy__(self, memo: Any) -> Secret:
        return self
