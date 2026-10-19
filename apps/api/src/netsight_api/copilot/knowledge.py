"""Retrieval over Netsight's own documents (Step 10, RAG-KNOWLEDGE.md).

A small lexical index (term frequency x inverse document frequency) over the Markdown files below
one operator-configured directory. No embedding service is involved, so nothing leaves the host to
index or search. The index keeps provenance (relative path, heading, content version, modified time)
and flags old documents as stale. A retrieved chunk is **data**: it is cleaned, secret-redacted and
bounded again where it becomes evidence, and never interpreted.

Bounds: only ``*.md`` regular files under the root (symlinks, hidden and vendored directories are
skipped; a file whose real path leaves the root is skipped), 512 KiB per file, ``MAX_DOCUMENTS``
documents, ``MAX_CHUNKS`` chunks, 1 500 characters per chunk. The corpus is read at most once per
``RELOAD_SECONDS``. Without ``NETSIGHT_KNOWLEDGE_DIR`` the corpus is ``not-connected``; a directory
that cannot be read is ``unknown``: neither is an empty corpus.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import re
import stat
import threading
import time
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, Literal

from netsight_api.rbac import Role

_LOGGER: Final = logging.getLogger("netsight_api")
ROOT_ENV: Final = "NETSIGHT_KNOWLEDGE_DIR"
MAX_DOCUMENTS: Final = 2_000
MAX_CHUNKS: Final = 20_000
MAX_FILE_BYTES: Final = 512 * 1024
MAX_CHUNK_CHARS: Final = 1_500
STALE_AFTER_DAYS: Final = 365
RELOAD_SECONDS: Final = 300.0
# A failed read is retried soon: a transient filesystem error must not hide the corpus for minutes.
FAILURE_RELOAD_SECONDS: Final = 30.0
_ROLE_NAMES: Final = frozenset(role.value for role in Role)
_SKIPPED_DIRS: Final = frozenset({"node_modules", "__pycache__"})
_HEADING: Final = re.compile(r"^(#{1,4})\s+(.{1,120})$")
_WORD: Final = re.compile(r"[a-z0-9]{2,}")
_STOPWORDS: Final = frozenset(
    [
        "the",
        "and",
        "for",
        "are",
        "but",
        "not",
        "you",
        "all",
        "any",
        "can",
        "had",
        "her",
        "was",
        "one",
        "our",
        "out",
        "has",
        "have",
        "how",
        "what",
        "why",
        "who",
        "when",
        "where",
        "which",
        "with",
        "that",
        "this",
        "from",
        "into",
        "than",
        "then",
        "they",
        "them",
        "their",
        "there",
        "been",
        "being",
        "does",
        "did",
        "its",
        "his",
        "she",
        "him",
        "too",
        "use",
        "used",
        "using",
        "about",
        "after",
        "before",
        "over",
        "under",
        "again",
        "once",
        "only",
        "own",
        "same",
        "should",
        "would",
        "could",
        "will",
        "shall",
        "may",
        "might",
        "must",
        "is",
        "it",
        "as",
        "at",
        "be",
        "by",
        "do",
        "if",
        "in",
        "no",
        "of",
        "on",
        "or",
        "to",
        "up",
        "we",
    ]
)


@dataclass(frozen=True)
class Chunk:
    document: str
    heading: str
    text: str
    version: str
    modified: datetime
    stale: bool
    terms: tuple[tuple[str, int], ...]
    # None: every asker. A set: only these roles (empty: nobody, e.g. a restriction naming no known role).
    roles: frozenset[str] | None = None


@dataclass(frozen=True)
class Hit:
    document: str
    heading: str
    text: str
    version: str
    modified: datetime
    stale: bool
    score: float


def terms_of(text: str) -> list[str]:
    return [w for w in _WORD.findall(text.lower()) if w not in _STOPWORDS]


class KnowledgeIndex:
    def __init__(self, chunks: list[Chunk], documents: int) -> None:
        self._chunks = chunks
        self.documents = documents
        self.chunks = len(chunks)
        frequency: Counter[str] = Counter()
        for chunk in chunks:
            frequency.update(term for term, _ in chunk.terms)
        self._idf = {term: math.log(1 + len(chunks) / count) for term, count in frequency.items()}

    def search(self, query: str, *, roles: frozenset[str], limit: int = 5) -> list[Hit]:
        """Hits for ``query`` among the chunks ``roles`` may read (filtered here, per asker)."""
        wanted = {t for t in terms_of(query) if t in self._idf}
        if not wanted or limit < 1:
            return []
        scored: list[tuple[float, Chunk]] = []
        for chunk in self._chunks:
            if chunk.roles is not None and not chunk.roles & roles:
                continue
            weights = dict(chunk.terms)
            score = sum(math.log(1 + weights[t]) * self._idf[t] for t in wanted if t in weights)
            if score > 0:
                scored.append((score, chunk))
        scored.sort(key=lambda pair: (-pair[0], pair[1].document, pair[1].heading))
        return [
            Hit(c.document, c.heading, c.text, c.version, c.modified, c.stale, round(score, 4))
            for score, c in scored[:limit]
        ]


def _sections(text: str, title: str) -> list[tuple[str, str]]:
    sections: list[tuple[str, list[str]]] = [(title, [])]
    for line in text.splitlines():
        match = _HEADING.match(line)
        if match:
            sections.append((match.group(2).strip(), []))
        else:
            sections[-1][1].append(line)
    out: list[tuple[str, str]] = []
    for heading, lines in sections:
        body = "\n".join(lines).strip()
        for start in range(0, len(body), MAX_CHUNK_CHARS):
            piece = body[start : start + MAX_CHUNK_CHARS].strip()
            if piece:
                out.append((heading, piece))
    return out


def _front_matter(raw: str) -> tuple[frozenset[str] | None, str]:
    """An optional ``---`` header with ``roles: a, b``; the text without it. No header: open to all.

    A ``roles`` entry that names no known role restricts the document to nobody (fail closed).
    """
    if not raw.startswith(("---\n", "---\r\n")):
        return None, raw
    end = raw.find("\n---", 3)
    if end == -1 or end > 2_000:
        return None, raw
    roles: frozenset[str] | None = None
    for line in raw[3:end].splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() == "roles":
            named = {name.strip().lower() for name in value.split(",")}
            roles = frozenset(named & _ROLE_NAMES)
    return roles, raw[end + 4 :]


def _candidates(root: Path) -> list[Path]:
    found: list[Path] = []
    for directory, subdirs, files in os.walk(root, followlinks=False):
        subdirs[:] = sorted(d for d in subdirs if not d.startswith(".") and d not in _SKIPPED_DIRS)
        for name in sorted(files):
            if name.endswith(".md") and not name.startswith("."):
                found.append(Path(directory) / name)
    return found


def _read(path: Path, real_root: Path) -> tuple[str, datetime] | None:
    try:
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(real_root):
            return None
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
            return None
        raw = path.read_bytes().decode("utf-8", errors="replace")
    except OSError:
        return None
    return raw, datetime.fromtimestamp(info.st_mtime, UTC)


def build_index(root: Path, *, now: datetime) -> KnowledgeIndex | None:
    """The index of ``root``, or ``None`` when the directory cannot be read."""
    try:
        real_root = root.resolve(strict=True)
        if not real_root.is_dir():
            return None
        paths = _candidates(real_root)
    except OSError:
        return None
    chunks: list[Chunk] = []
    documents = 0
    stale_before = now - timedelta(days=STALE_AFTER_DAYS)
    for path in paths:
        if documents >= MAX_DOCUMENTS or len(chunks) >= MAX_CHUNKS:
            break
        read = _read(path, real_root)
        if read is None:
            continue
        raw, modified = read
        version = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
        roles, raw = _front_matter(raw)
        relative = path.relative_to(real_root).as_posix()
        before = len(chunks)
        for heading, piece in _sections(raw, path.stem):
            if len(chunks) >= MAX_CHUNKS:
                break
            counts = Counter(terms_of(f"{heading} {piece}"))
            if counts:
                stale = modified < stale_before
                chunks.append(
                    Chunk(
                        relative,
                        heading,
                        piece,
                        version,
                        modified,
                        stale,
                        tuple(counts.items()),
                        roles,
                    )
                )
        documents += 1 if len(chunks) > before else 0
    return KnowledgeIndex(chunks, documents)


@dataclass(frozen=True)
class Loaded:
    state: Literal["ok", "not-connected", "unknown"]
    index: KnowledgeIndex | None


_cache: tuple[float, str, Loaded, float] | None = None
_lock = threading.Lock()


def load_index(*, now: datetime) -> Loaded:
    """The configured corpus (cached; a failure is retried sooner); never raises.

    Blocking file work: call it off the event loop. One build at a time; concurrent callers wait for
    it and share the result.
    """
    global _cache
    configured = os.environ.get(ROOT_ENV, "").strip()
    if not configured:
        return Loaded("not-connected", None)
    with _lock:
        if _cache is not None and _cache[1] == configured:
            taken, _, cached, ttl = _cache
            if 0 <= time.monotonic() - taken < ttl:
                return cached
        index = build_index(Path(configured), now=now)
        if index is None:
            _LOGGER.warning("the copilot knowledge directory is not readable")
        loaded = Loaded("ok", index) if index is not None else Loaded("unknown", None)
        ttl = RELOAD_SECONDS if index is not None else FAILURE_RELOAD_SECONDS
        _cache = (time.monotonic(), configured, loaded, ttl)
        return loaded


def reset_for_tests() -> None:
    global _cache
    with _lock:
        _cache = None
