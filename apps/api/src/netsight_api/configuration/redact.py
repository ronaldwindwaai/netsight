"""Secret redaction for device configuration text (Step 9; kept on integration because the copilot sanitiser uses it).

A device configuration is full of secrets (enable secrets, SNMP communities, pre-shared keys,
private keys). Nothing here is shown to a person until it has been through ``redact_lines``. The
rule is deliberately over-eager and fail closed: from the first token that names a secret, the rest
of the line is replaced; PEM blocks lose every inner line. Over-redaction loses a little context;
under-redaction leaks a credential. The function is pure and idempotent.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

REDACTED: Final = "[REDACTED]"
_TOKEN: Final = re.compile(r"\S+")
_PEM_BEGIN: Final = re.compile(r"^\s*-----BEGIN [^-]+-----\s*$")
_PEM_END: Final = re.compile(r"^\s*-----END [^-]+-----\s*$")
_SECRET_PARTS: Final = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "pw",
        "pass",
        "secret",
        "community",
        "token",
        "psk",
        "psksecret",
        "key",
        "passphrase",
        "credential",
        "credentials",
        "md5",
        "apikey",
        "authkey",
        "bearer",
        "hash",
        "encrypted",
        "authorization",
    }
)
# A compound spelled without a separator (passwordhash, sharedsecret, privatekey).
_SECRET_SUFFIXES: Final = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "authkey",
    "key",
    "hash",
)
# These name their secret in a position a keyword scan cannot see (the trap community follows the
# host; SNMPv3 passphrases follow the user), so everything after the pair is withheld.
_SECRET_COMMANDS: Final = frozenset(
    {("snmp-server", "host"), ("snmp-server", "user"), ("authentication", "text")}
)
_QUOTES: Final = "\"'`;,"


@dataclass(frozen=True)
class Redacted:
    lines: list[str]
    redacted: int


_CAMEL: Final = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_ALNUM: Final = re.compile(r"[^a-z0-9]+")
# An open tag and the text after it up to the next "<": bounded, with no nested quantifiers.
_TAG_VALUE: Final = re.compile(r"<([A-Za-z_][\w:.-]{0,63})(?:\s[^<>]{0,200})?>([^<]+)")
_OPEN_TAG_ENDING: Final = re.compile(r"<([A-Za-z_][\w:.-]{0,63})(?:\s[^<>]{0,200})?>\s*$")


def _names_a_secret(token: str) -> bool:
    """True when a token (before any ``=`` or ``:``) is, or is built from, a secret word.

    The token is split into words on camelCase boundaries and on every non-alphanumeric
    character, so ``apiKey``, ``api_key``, ``"api-key"`` and ``<snmp-community>`` all qualify.
    """
    words = _NON_ALNUM.split(_CAMEL.sub("-", token).lower())
    parts = [part for part in words if part]
    return any(part in _SECRET_PARTS for part in parts) or any(
        part.endswith(_SECRET_SUFFIXES) for part in parts
    )


def _redact_tags(line: str) -> str:
    """Withhold the text after a secret-named open tag (``<password>x</password>``)."""

    def replace(match: re.Match[str]) -> str:
        value = match.group(2)
        if value.strip() in ("", REDACTED) or not _names_a_secret(match.group(1)):
            return match.group(0)
        return match.group(0)[: match.start(2) - match.start()] + REDACTED

    return _TAG_VALUE.sub(replace, line)


_SEPARATORS: Final = "=:"


def _cut_after(line: str) -> tuple[int, str] | None:
    """Where the secret starts: (offset just past the keyword, glue before the marker), or None.

    ``password=x`` and ``key: x`` put the keyword and the value in one token or leave a dangling
    separator, so the keyword is the part of a token before its first ``=`` or ``:``.
    """
    tokens = list(_TOKEN.finditer(line))
    for index, match in enumerate(tokens):
        if index + 1 < len(tokens):
            pair = (match.group().lower(), tokens[index + 1].group().lower())
            if pair in _SECRET_COMMANDS:
                return tokens[index + 1].end(), " "
        token = match.group()
        if token.startswith("<"):
            continue  # markup is handled by _redact_tags, which keeps the surrounding tags
        split = next((i for i, ch in enumerate(token) if ch in _SEPARATORS), None)
        if split is not None and _names_a_secret(token[:split]):
            after = match.start() + split + 1
            return (after, "") if after < match.end() else (after, " ")
        if split is None and _names_a_secret(token):
            return match.end(), " "
    return None


def redact_line(line: str) -> str | None:
    """The line with its secret withheld, or ``None`` when the line holds none."""
    tagged = _redact_tags(line)
    changed = None if tagged == line else tagged
    found = _cut_after(tagged)
    if found is None:
        return changed
    cut, glue = found
    rest = tagged[cut:].strip()
    if not rest or rest == REDACTED:
        return changed
    return f"{tagged[:cut]}{glue}{REDACTED}"


def _dangling(line: str) -> bool:
    """A secret keyword ending the line with a separator: its value is on a later line."""
    stripped = line.rstrip()
    tag = _OPEN_TAG_ENDING.search(stripped)
    if tag is not None:
        return _names_a_secret(tag.group(1))
    if not stripped or stripped[-1] not in _SEPARATORS:
        return False
    tokens = [t.rstrip(_SEPARATORS) for t in stripped.split()]
    named = tokens[-1] or (tokens[-2] if len(tokens) > 1 else "")
    return bool(named) and _names_a_secret(named)


def redact_lines(lines: Sequence[str]) -> Redacted:
    out: list[str] = []
    count = 0
    in_pem = False
    value_next = False
    for line in lines:
        blank = not line.strip()
        if value_next and not blank:
            value_next = False
            if line.strip() != REDACTED:
                count += 1
            out.append(REDACTED)
            continue
        if in_pem:
            if _PEM_END.match(line):
                in_pem = False
                out.append(line)
            else:
                count += line.strip() not in ("", REDACTED)
                out.append(REDACTED)
            continue
        if _PEM_BEGIN.match(line):
            in_pem = True
            out.append(line)
            continue
        if not blank:
            value_next = _dangling(line)
        replaced = redact_line(line)
        if replaced is None:
            out.append(line)
        else:
            count += 1
            out.append(replaced)
    return Redacted(out, count)
