"""Reading an operator-owned JSON document from a file or an environment variable (Step 8).

Netsight does not decide what a NetBox role means or how serious an unknown device is: the operator
says so in a small JSON document and every classification traces to an entry in it. This module is
the one safe reader both documents share:

* the document comes from exactly one place: a file (``<NAME>_FILE``) or inline JSON (``<NAME>``);
  naming both is ambiguous and invalid, naming neither is *not configured*;
* nesting deep enough to exhaust the parser's recursion is invalid, not a crash;
* a file is opened once and measured with ``fstat`` on that handle, so a swap between a size check
  and the read cannot slip past the limit; only a regular file is read;
* duplicate keys are refused (a later key must not silently override an earlier one);
* any failure is ``invalid`` with a static log reason (never the content), and the caller treats
  invalid exactly like "nothing is configured" (fail closed: half a document is never applied).
"""

from __future__ import annotations

import json
import logging
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal

_LOGGER: Final = logging.getLogger("netsight_api")

MAX_DOCUMENT_BYTES: Final = 64 * 1024
DocumentState = Literal["not-configured", "configured", "invalid"]


@dataclass(frozen=True)
class OperatorDocument:
    state: DocumentState
    data: object = None


_NOT_CONFIGURED: Final = OperatorDocument("not-configured")


class _DuplicateKeyError(ValueError):
    pass


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError("duplicate key")
        result[key] = value
    return result


def _invalid(name: str, reason: str) -> OperatorDocument:
    _LOGGER.warning("operator document is invalid", extra={"setting": name, "reason": reason})
    return OperatorDocument("invalid")


def _parse(raw: bytes, name: str) -> OperatorDocument:
    if len(raw) > MAX_DOCUMENT_BYTES:
        return _invalid(name, "too-large")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except _DuplicateKeyError:
        return _invalid(name, "duplicate-key")
    except RecursionError:  # 64 kB of "[" is under the size limit and over the parser's depth
        return _invalid(name, "too-deep")
    except (UnicodeDecodeError, ValueError):
        return _invalid(name, "not-json")
    return OperatorDocument("configured", data)


def _read_file(path: str, name: str) -> OperatorDocument:
    try:
        with open(path, "rb") as handle:  # measured with fstat on this very handle
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                return _invalid(name, "not-a-file")
            if info.st_size > MAX_DOCUMENT_BYTES:
                return _invalid(name, "too-large")
            return _parse(handle.read(MAX_DOCUMENT_BYTES + 1), name)
    except OSError:
        return _invalid(name, "unreadable")


def read_operator_document(
    env: Mapping[str, str], inline_name: str, file_name: str
) -> OperatorDocument:
    """The document named by ``inline_name`` (JSON) or ``file_name`` (a path), validated as JSON only."""
    inline = env.get(inline_name, "").strip()
    path = env.get(file_name, "").strip()
    if inline and path:
        return _invalid(inline_name, "file-and-inline")
    if path:
        return _read_file(path, file_name)
    if inline:
        return _parse(inline.encode("utf-8"), inline_name)
    return _NOT_CONFIGURED
