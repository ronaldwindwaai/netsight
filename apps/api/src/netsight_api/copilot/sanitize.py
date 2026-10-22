"""Cleaning of untrusted text before it reaches a model or a browser (Step 10).

Everything the copilot reads (document chunks, device names, commit messages, incident titles, the
question itself) is data from outside the trust boundary. Before it is placed in an evidence item it
is: cut to a bounded line length (so no pattern backtracks on a hostile line), stripped of control,
format and bidirectional characters, secret-redacted (the configuration redactor plus well-known
token shapes), collapsed to one line and bounded. A piece of text that *reads like an instruction to
a model* is flagged, never trusted and never dropped: it is still data, shown with its flag.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Final

from netsight_api.configuration.redact import REDACTED, redact_lines
from netsight_api.configuration.text import MAX_RAW_LINE

ELLIPSIS: Final = "…"
MAX_LINES: Final = 400
_DROPPED: Final = frozenset({"Cc", "Cf", "Zl", "Zp"})
_SPACES: Final = re.compile(r"\s+")
_TOKEN_SHAPES: Final = re.compile(
    r"AKIA[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|sk-[A-Za-z0-9_-]{16,}"
    r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|glpat-[A-Za-z0-9_-]{16,}"
    r"|AIza[0-9A-Za-z_-]{30,}"
    r"|sk_(?:live|test)_[A-Za-z0-9]{16,}"
    r"|(?i:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"
    r"|(?<=://)[^/\s:@]{1,64}:[^/\s@]{1,128}@"
    r"|(?<![\w/])[A-Za-z0-9_.-]{1,32}:[^\s:@/]{4,64}@(?=[A-Za-z0-9.-])"
)
# Look-alike letters (Cyrillic and Greek) folded to ASCII so a homoglyph cannot hide an instruction.
_CONFUSABLES: Final = {
    ord(look): ascii_
    for look, ascii_ in zip(
        (
            chr(c)
            for c in (0x430, 0x435, 0x43E, 0x440, 0x441, 0x443, 0x445, 0x456, 0x3BF, 0x3B1, 0x3BD)
        ),
        "aeopcyxioav",
        strict=True,
    )
}
_INSTRUCTION_LIKE: Final = re.compile(
    r"ignore\s{1,5}(?:all\s{1,5}|any\s{1,5}|the\s{1,5})?(?:previous|prior|above|earlier)\s{1,5}"
    r"(?:instructions?|rules|prompts?)"
    r"|disregard\s{1,5}(?:the\s{1,5}|all\s{1,5})?(?:above|previous|prior|instructions?)"
    r"|(?:forget|override|bypass)\s{1,5}(?:your|the|all|any)\s{1,5}"
    r"(?:rules|instructions|guidelines|polic(?:y|ies)|restrictions)"
    r"|you\s{1,5}are\s{1,5}now\b"
    r"|new\s{1,5}instructions?\s{0,3}:"
    r"|system\s{1,5}prompt"
    r"|^\s{0,8}system\s{0,3}:"
    r"|<\|im_(?:start|end)\|>"
    r"|\[/?inst\]"
    r"|#{1,6}\s{0,5}instruction"
    r"|as\s{1,5}the\s{1,5}(?:admin|administrator|root|owner)\b.{0,80}\b(?:authori[sz]e|approve|permit)",
    re.IGNORECASE | re.MULTILINE,
)


def _strip(raw: str) -> str:
    spaced = _SPACES.sub(" ", raw)
    kept = "".join(ch for ch in spaced if unicodedata.category(ch) not in _DROPPED)
    return _SPACES.sub(" ", kept).strip()


def clean_text(raw: str, limit: int) -> str:
    """One line, no control/format characters, at most ``limit`` characters (ellipsis when cut)."""
    text = _strip(raw)
    if len(text) <= limit:
        return text
    return text[: max(limit - 1, 0)].rstrip() + ELLIPSIS


def clean_question(raw: str) -> str:
    return _strip(raw)


def _folded(text: str) -> str:
    """Zero-width and control characters removed, compatibility forms and look-alikes folded."""
    stripped = "".join(
        ch for ch in text[:20_000] if ch.isspace() or unicodedata.category(ch) not in _DROPPED
    )
    return unicodedata.normalize("NFKC", stripped).translate(_CONFUSABLES)


def is_instruction_like(text: str) -> bool:
    return _INSTRUCTION_LIKE.search(_folded(text)) is not None


def redact_secrets(text: str) -> str:
    """Withhold secrets: configuration-style keywords per line, then well-known token shapes."""
    lines = [_strip(line)[:MAX_RAW_LINE] for line in text.splitlines()[:MAX_LINES]]
    redacted = redact_lines(lines).lines
    return "\n".join(_TOKEN_SHAPES.sub(REDACTED, line) for line in redacted)


def safe_excerpt(raw: str, limit: int) -> tuple[str, bool]:
    """The redacted, one-line, bounded text and whether the original read like an instruction."""
    flagged = is_instruction_like(raw)
    return clean_text(redact_secrets(raw), limit), flagged
