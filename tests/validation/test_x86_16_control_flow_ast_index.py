"""Tests for request-owned control-flow validation AST indexes."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CFunctionCall,
    CIfBreak,
    CStatements,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.lowering.indexed_global_evidence import (
    IndexedSegmentedGlobalEvidence8616,
)
from inertia.lowering.segmented_global_loads import (
    DirectGlobalSymbolRef8616,
    materialize_direct_global_symbol_stores_from_evidence_8616,
    materialize_indexed_segmented_global_loads_from_evidence_8616,
)
from inertia.pipeline.structured_ast_query_index import (
    StructuredAstQueryIndex8616,
    StructuredAstQuerySession8616,
)
from archinfo import ArchX86

from inertia.validation.control_flow_ast_index import ControlFlowAstIndex8616


class _Project:
    """Minimal project boundary carrying the target architecture."""

    def __init__(self) -> None:
        self.arch = ArchX86()


class _Codegen:
    """Minimal dynamic angr constructor boundary for C-AST fixtures."""

    def __init__(self) -> None:
        self._next_index = 0
        self.project = _Project()

    def next_idx(self, _kind: str) -> int:
        """Return one deterministic C-AST identity."""
        index = self._next_index
        self._next_index += 1
        return index

    def next_node_idx(self) -> int:
        """Return one deterministic C-AST node identity."""
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        """Return the class display identity expected by angr constructors."""
        return name


def test_indexes_guard_and_subtree_surfaces_once() -> None:
    codegen = _Codegen()
    short = SimTypeShort(False)
    local = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2"),
        variable_type=short,
        codegen=codegen,
    )
    condition = CConstant(1, short, codegen=codegen, tags={"ins_addr": 0x4005})
    guard = CIfBreak(condition, codegen=codegen)
    target = CAssignment(
        local,
        CConstant(2, short, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    body = CStatements([guard, target], codegen=codegen)
    loop = CWhileLoop(condition, body, codegen=codegen)
    root = CStatements([loop], codegen=codegen)

    root_index = StructuredAstQueryIndex8616.build(root)
    index = ControlFlowAstIndex8616.build(root, root_index=root_index)

    assert index.loops == (loop,)
    assert index.tagged_conditions(0x4005) == (condition,)
    assert index.break_guards(0x4005) == (guard,)
    assert index.loop_guards(0x4005) == (loop,)
    assert index.subtree_contains_node(body, guard)
    assert index.subtree_contains_instruction(body, 0x4010)
    assert target in index.subtree_nodes(body)
    stats = index.stats()
    assert stats.subtree_query_count == 3
    assert stats.subtree_materialized_count == 1
    assert stats.subtree_hit_count == 2
    assert stats.is_closed


def test_refuses_query_index_from_another_root() -> None:
    codegen = _Codegen()
    short = SimTypeShort(False)
    first = CStatements([CConstant(1, short, codegen=codegen)], codegen=codegen)
    second = CStatements([CConstant(2, short, codegen=codegen)], codegen=codegen)
    root_index = StructuredAstQueryIndex8616.build(first)

    with pytest.raises(ValueError, match="different root"):
        ControlFlowAstIndex8616.build(second, root_index=root_index)


def test_query_index_builds_typed_projections_in_walker_order() -> None:
    codegen = _Codegen()
    short = SimTypeShort(False)
    local = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2"),
        variable_type=short,
        codegen=codegen,
    )
    assignment = CAssignment(
        local,
        CConstant(2, short, codegen=codegen),
        codegen=codegen,
    )
    call = CFunctionCall("tick", None, [], codegen=codegen)
    root = CStatements([assignment, call], codegen=codegen)

    index = StructuredAstQueryIndex8616.build(root)

    assert index.statement_blocks == (root,)
    assert index.assignments == (assignment,)
    assert index.calls == (call,)
    assert index.variables == (local,)


def test_query_session_rebuilds_only_after_reported_mutation() -> None:
    codegen = _Codegen()
    short = SimTypeShort(False)
    root = CStatements([CConstant(1, short, codegen=codegen)], codegen=codegen)
    session = StructuredAstQuerySession8616(root)

    first = session.current()
    assert session.current() is first
    root.statements.append(CConstant(2, short, codegen=codegen))
    session.record_mutation(True)
    rebuilt = session.current()

    assert rebuilt is not first
    assert len(rebuilt.nodes) > len(first.nodes)
    stats = session.stats()
    assert stats.request_count == 3
    assert stats.build_count == 2
    assert stats.hit_count == 1
    assert stats.invalidation_count == 1
    assert stats.closed


def test_stable_indexed_global_subpasses_share_one_query_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codegen = _Codegen()
    short = SimTypeShort(False)
    root = CStatements([CConstant(1, short, codegen=codegen)], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4000, statements=root, body=root)
    original_build = StructuredAstQueryIndex8616.build
    built_roots: list[object] = []

    def counted_build(
        cls: type[StructuredAstQueryIndex8616],
        request_root: object,
    ) -> StructuredAstQueryIndex8616:
        del cls
        built_roots.append(request_root)
        return original_build(request_root)

    monkeypatch.setattr(
        StructuredAstQueryIndex8616,
        "build",
        classmethod(counted_build),
    )

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        codegen.project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x40, "g_values", 0, 2),),
    )

    assert changed is False
    assert built_roots == [root]


def test_stable_direct_global_subpasses_share_one_query_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codegen = _Codegen()
    short = SimTypeShort(False)
    root = CStatements([CConstant(1, short, codegen=codegen)], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4000, statements=root, body=root)
    original_build = StructuredAstQueryIndex8616.build
    built_roots: list[object] = []

    def counted_build(
        cls: type[StructuredAstQueryIndex8616],
        request_root: object,
    ) -> StructuredAstQueryIndex8616:
        del cls
        built_roots.append(request_root)
        return original_build(request_root)

    monkeypatch.setattr(
        StructuredAstQueryIndex8616,
        "build",
        classmethod(counted_build),
    )

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (DirectGlobalSymbolRef8616(0x40, "g_value", 0, 2, 0),),
    )

    assert changed is False
    assert built_roots == [root]
