"""Tests for indexed structured subtree tag projections."""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import CStatements

from inertia.structuring.tagged_subtree_projection import (
    StructuredSubtreeEntryTagIndex8616,
    StructuredSubtreeEntryTagQuerySession8616,
    collect_structured_subtree_entry_tags_8616,
)


class _Codegen:
    """Minimal structured-codegen identity provider for C test nodes."""

    def __init__(self) -> None:
        self._next_index = 0

    def next_idx(self, _name: str) -> int:
        """Return one deterministic node identity."""
        self._next_index += 1
        return self._next_index

    def next_ident(self, name: str) -> str:
        """Return the stable display identity requested by angr nodes."""
        return name

    def next_node_idx(self) -> int:
        """Return the next unique node identity."""
        return self.next_idx("")


def _tagged_tree() -> tuple[CStatements, CStatements, CStatements]:
    """Return a small tagged tree with two sibling statement subtrees."""

    codegen = _Codegen()
    first = CStatements([], codegen=codegen)
    first.tags = {"ins_addr": 0x1020, "vex_block_addr": 0x1020}
    second = CStatements([], codegen=codegen)
    second.tags = {"ins_addr": 0x1010, "vex_block_addr": 0x1010}
    root = CStatements([first, second], codegen=codegen)
    root.tags = {"ins_addr": 0x1000, "vex_block_addr": 0x1000}
    return root, first, second


def test_subtree_tag_index_matches_exact_collector_for_every_node() -> None:
    """Bottom-up projections preserve the exact legacy collector result."""

    root, first, second = _tagged_tree()
    index = StructuredSubtreeEntryTagIndex8616.build(root)

    assert index.stats.complete
    for node in (root, first, second):
        assert index.for_node(node) == collect_structured_subtree_entry_tags_8616(node)


def test_subtree_tag_query_session_rebuilds_after_reported_mutation() -> None:
    """A caller-reported tag mutation invalidates the complete bottom-up index."""

    root, first, _second = _tagged_tree()
    session = StructuredSubtreeEntryTagQuerySession8616(root)
    before = session.current(first)
    first.tags = {"ins_addr": 0x1040, "vex_block_addr": 0x1040}
    session.record_mutation()
    after = session.current(first)
    stats = session.stats()

    assert before.first_instruction_addr == 0x1020
    assert after.first_instruction_addr == 0x1040
    assert stats.closed
    assert stats.request_count == stats.indexed_hit_count == 2
    assert stats.index_build_count == 2
    assert stats.fallback_count == 0
    assert stats.invalidation_count == 1
