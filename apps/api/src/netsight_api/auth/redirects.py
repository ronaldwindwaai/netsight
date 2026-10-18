"""Where a completed sign-in may send the browser.

The destination arrives from a query string, so it is attacker-influenced. It is accepted only
when it is a same-origin absolute path into the Netsight UI; anything else becomes the default.
The rules mirror the web application's ``safeNextPath`` (``apps/web/src/lib/sign-in-redirect.ts``)
and add an allow-list of UI areas, so a redirect can never land on ``/api`` or ``/auth``.
"""

from __future__ import annotations

from typing import Final
from urllib.parse import unquote

DEFAULT_REDIRECT: Final = "/overview"
MAX_REDIRECT_LENGTH: Final = 512

# The first path segment of every dashboard area (keep in step with apps/web/src/app/(dashboard)).
UI_AREAS: Final = frozenset(
    {
        "overview",
        "network",
        "devices",
        "traffic",
        "security",
        "diagnostics",
        "incidents",
        "alerts",
        "inventory",
        "ipam",
        "unknown-devices",
        "copilot",
    }
)

# C0/C1 controls, then zero-width formatting characters, bidi overrides and bidi isolates.
_FORBIDDEN_RANGES: Final = (
    (0x0000, 0x001F),
    (0x007F, 0x009F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2066, 0x2069),
)


def _has_forbidden_character(value: str) -> bool:
    return any(low <= ord(char) <= high for char in value for low, high in _FORBIDDEN_RANGES)


def _first_segment(path: str) -> str:
    return path.split("?", 1)[0].split("#", 1)[0].split("/")[1]


def _acceptable(value: str) -> bool:
    if not value.startswith("/") or value.startswith("//"):
        return False
    if "\\" in value or _has_forbidden_character(value):
        return False
    return _first_segment(value) in UI_AREAS


def safe_ui_redirect(target: object) -> str:
    """``target`` when it is a safe same-origin UI path (as written and as percent-decoded)."""
    if not isinstance(target, str) or not 0 < len(target) <= MAX_REDIRECT_LENGTH:
        return DEFAULT_REDIRECT
    if not _acceptable(target) or not _acceptable(unquote(target)):
        return DEFAULT_REDIRECT
    return target
