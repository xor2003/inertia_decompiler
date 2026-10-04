"""Regression tests for high-byte cleanup traversal context."""

from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16 import decompiler_postprocess_calls as calls


def test_conditional_child_receives_high_byte_cleanup_context(monkeypatch) -> None:
    """Every conditional branch must retain the owning cleanup context."""
    child = SimpleNamespace()
    parent = SimpleNamespace(condition_and_nodes=((object(), child),))
    codegen = object()
    seen = object()
    summary_map = object()
    visited: list[object] = []

    def record_visit(node: object, *, codegen: object, seen: object, summary_map: object) -> bool:
        assert codegen is expected_codegen
        assert seen is expected_seen
        assert summary_map is expected_summary_map
        visited.append(node)
        return False

    expected_codegen = codegen
    expected_seen = seen
    expected_summary_map = summary_map
    monkeypatch.setattr(calls, "_hb_prune_statement_owner", record_visit)

    assert calls._hb_walk_statement(parent, codegen=codegen, seen=seen, summary_map=summary_map) is False
    assert visited == [parent, child]
