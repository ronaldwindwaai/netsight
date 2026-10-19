"""Retrieval over Netsight's own documents: lexical, bounded, provenance-carrying, data not instructions."""

from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

import pytest
from copilot_support import DOCS, NOW, write_docs

from netsight_api.copilot import knowledge

TECH = frozenset({"technician"})
ADMIN = frozenset({"administrator"})


def build(root: Path) -> knowledge.KnowledgeIndex:
    return knowledge.build_index(root, now=NOW)


def test_a_question_finds_the_section_that_answers_it_with_provenance(tmp_path: Path) -> None:
    index = build(write_docs(tmp_path))
    hits = index.search("what do I check first for a dns outage", roles=TECH, limit=3)
    assert hits, "expected a hit"
    top = hits[0]
    assert top.document == "08-operations/RUNBOOK.md"
    assert top.heading == "DNS outage"
    assert "resolver" in top.text
    assert len(top.version) == 12
    assert top.modified.tzinfo is not None


def test_nothing_matching_returns_nothing_never_a_guess(tmp_path: Path) -> None:
    index = build(write_docs(tmp_path))
    assert index.search("quantum entanglement of the espresso machine", roles=TECH, limit=5) == []
    assert index.search("the and of", roles=TECH, limit=5) == []


def test_counts_describe_the_corpus(tmp_path: Path) -> None:
    index = build(write_docs(tmp_path))
    assert index.documents == len(DOCS)
    assert index.chunks >= len(DOCS)


def test_only_markdown_inside_the_root_is_indexed(tmp_path: Path) -> None:
    root = write_docs(tmp_path / "docs")
    (root / "notes.txt").write_text("# Secret\nresolver", encoding="utf-8")
    (root / ".hidden").mkdir()
    (root / ".hidden" / "x.md").write_text("# Hidden\nresolver", encoding="utf-8")
    outside = tmp_path / "outside.md"
    outside.write_text("# Outside\nresolver outside", encoding="utf-8")
    try:
        os.symlink(outside, root / "link.md")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    index = build(root)
    assert index.documents == len(DOCS)
    assert all(
        "outside" not in hit.text.lower() for hit in index.search("resolver", roles=TECH, limit=10)
    )


def test_oversized_files_and_corpora_are_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = write_docs(tmp_path)
    (root / "huge.md").write_text("# Huge\n" + "resolver " * 200_000, encoding="utf-8")
    monkeypatch.setattr(knowledge, "MAX_DOCUMENTS", 2)
    index = build(root)
    assert index.documents <= 2
    assert all(hit.document != "huge.md" for hit in index.search("resolver", roles=TECH, limit=10))


def test_old_documents_are_marked_stale(tmp_path: Path) -> None:
    root = write_docs(tmp_path)
    old = (NOW - timedelta(days=knowledge.STALE_AFTER_DAYS + 5)).timestamp()
    now = NOW.timestamp()
    for other in root.rglob("*.md"):
        os.utime(other, (now, now))
    os.utime(root / "08-operations" / "RUNBOOK.md", (old, old))
    index = build(root)
    top = index.search("dns outage resolver", roles=TECH, limit=1)[0]
    assert top.stale is True
    fresh = index.search("remote access vpn", roles=TECH, limit=1)[0]
    assert fresh.stale is False


def test_a_missing_or_unreadable_root_is_not_an_empty_corpus(tmp_path: Path) -> None:
    assert knowledge.build_index(tmp_path / "nope", now=NOW) is None


def test_load_index_reads_the_environment_and_is_not_connected_without_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(knowledge.ROOT_ENV, raising=False)
    knowledge.reset_for_tests()
    assert knowledge.load_index(now=NOW).state == "not-connected"
    monkeypatch.setenv(knowledge.ROOT_ENV, str(tmp_path / "nope"))
    knowledge.reset_for_tests()
    assert knowledge.load_index(now=NOW).state == "unknown"
    monkeypatch.setenv(knowledge.ROOT_ENV, str(write_docs(tmp_path / "docs")))
    knowledge.reset_for_tests()
    loaded = knowledge.load_index(now=NOW)
    assert loaded.state == "ok" and loaded.index is not None and loaded.index.documents == 3


def restricted(root: Path, header: str) -> knowledge.KnowledgeIndex:
    write_docs(root)
    (root / "09-private").mkdir()
    (root / "09-private" / "PLAN.md").write_text(
        "---\n" + header + "\n---\n# Plan\n## Core\n"
        "The core switch password rotation plan mentions sentinelterm.\n",
        encoding="utf-8",
    )
    index = build(root)
    assert index is not None
    return index


def test_a_document_can_limit_which_roles_may_retrieve_it(tmp_path: Path) -> None:
    index = restricted(tmp_path, "roles: administrator, network_engineer")
    assert index.search("sentinelterm", roles=TECH, limit=5) == []
    hits = index.search("sentinelterm", roles=ADMIN, limit=5)
    assert [h.document for h in hits] == ["09-private/PLAN.md"]
    assert "---" not in hits[0].text and "roles:" not in hits[0].text
    assert index.documents == len(DOCS) + 1, "the corpus size is not role specific"


def test_a_restriction_naming_no_known_role_fails_closed(tmp_path: Path) -> None:
    index = restricted(tmp_path, "roles: superuser, , root")
    assert index.search("sentinelterm", roles=ADMIN | TECH, limit=5) == []
    empty = restricted(tmp_path / "again", "roles:")
    assert empty.search("sentinelterm", roles=ADMIN, limit=5) == []


def test_front_matter_without_roles_is_open_and_is_not_indexed_as_text(tmp_path: Path) -> None:
    index = restricted(tmp_path, "title: Plan")
    hit = index.search("sentinelterm", roles=TECH, limit=5)[0]
    assert "title: Plan" not in hit.text


def test_a_user_with_several_roles_needs_only_one_of_them(tmp_path: Path) -> None:
    index = restricted(tmp_path, "roles: auditor")
    assert index.search("sentinelterm", roles=frozenset({"technician", "auditor"}), limit=5)
    assert not index.search("sentinelterm", roles=frozenset({"technician", "bogus"}), limit=5)


def test_a_failed_read_is_retried_soon_not_after_the_full_reload_interval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [1000.0]
    monkeypatch.setattr(knowledge.time, "monotonic", lambda: clock[0])
    monkeypatch.setenv(knowledge.ROOT_ENV, str(tmp_path / "later"))
    knowledge.reset_for_tests()
    assert knowledge.load_index(now=NOW).state == "unknown"
    write_docs(tmp_path / "later")
    clock[0] += 5
    assert knowledge.load_index(now=NOW).state == "unknown"
    clock[0] += knowledge.FAILURE_RELOAD_SECONDS + 1
    assert knowledge.load_index(now=NOW).state == "ok"


def test_concurrent_first_use_builds_the_index_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import threading
    import time as real_time

    calls = []
    real = knowledge.build_index

    def slow(root: Path, *, now):  # type: ignore[no-untyped-def]
        calls.append(1)
        real_time.sleep(0.2)
        return real(root, now=now)

    monkeypatch.setattr(knowledge, "build_index", slow)
    monkeypatch.setenv(knowledge.ROOT_ENV, str(write_docs(tmp_path / "docs")))
    knowledge.reset_for_tests()
    threads = [threading.Thread(target=lambda: knowledge.load_index(now=NOW)) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(calls) == 1
