"""Shared API error type.

Kept in a leaf module so authentication and route code can raise the
same intentional failure that ``main.py`` renders as a JSON envelope.
"""

from __future__ import annotations

from collections.abc import Mapping


class ApiError(Exception):
    """An intentional, non-sensitive API failure."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.headers = dict(headers) if headers else None
