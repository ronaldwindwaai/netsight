"""Shared cleaning of untrusted device-configuration text (Step 9)."""

from __future__ import annotations

import unicodedata
from typing import Final

MAX_LINE: Final = 400
# No rule or redaction pattern ever sees more than this many characters of one line, so a hostile
# line cannot make a pattern backtrack for long. A change beyond this column is not visible.
MAX_RAW_LINE: Final = 2_000
_DROPPED_CATEGORIES: Final = frozenset({"Cc", "Cf", "Zl", "Zp"})


def clean_line(raw: str) -> str:
    """Strip control and format characters (tabs become spaces) and trailing whitespace."""
    kept = [
        " " if ch == "\t" else ch
        for ch in raw
        if ch == "\t" or unicodedata.category(ch) not in _DROPPED_CATEGORIES
    ]
    return "".join(kept)[:MAX_RAW_LINE].rstrip()


def split_lines(text: str) -> list[str]:
    return [clean_line(line) for line in text.splitlines()]


def bounded(line: str) -> str:
    return line[:MAX_LINE]
