"""Focused tests for the pre-mutation loop-break AST surface."""

from collections.abc import Iterator
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CBreak,
    CConstant,
    CIfBreak,
    CStatements,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
import inertia.structuring.loop_break_jcc as loop_break_jcc


class _Codegen:
    """Minimal structured-codegen boundary for the loop fixture."""

    def __init__(self) -> None:
        self._next_idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        """Return one deterministic node index."""
        self._next_idx += 1
        return self._next_idx

    def next_node_idx(self) -> int:
        """Return one deterministic AST node index."""
        return self.next_idx("")

    @staticmethod
    def next_ident(name: str) -> str:
        """Return the stable fixture identifier."""
        return name


def _condition(
    codegen: _Codegen,
    *,
    ins_addr: int,
    block_addr: int,
    typed_loop: bool = False,
) -> CBinaryOp:
    """Build one tagged condition expression."""
    return CBinaryOp(
        "CmpNE",
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={
            "ins_addr": ins_addr,
            "vex_block_addr": block_addr,
            "inertia_typed_loop_condition_bound_8616": typed_loop,
        },
    )


def test_loop_break_initial_surface_collects_all_projections_in_one_walk(
    monkeypatch,
) -> None:
    """One pre-mutation walk must publish every initial query projection."""
    codegen = _Codegen()
    loop_condition = _condition(
        codegen,
        ins_addr=0x1002,
        block_addr=0x1000,
        typed_loop=True,
    )
    guard_condition = _condition(
        codegen,
        ins_addr=0x1012,
        block_addr=0x1010,
    )
    guard = CIfBreak(guard_condition, codegen=codegen, cstyle_ifs=True)
    loop = CWhileLoop(
        loop_condition,
        CStatements([guard, CBreak(codegen=codegen)], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)
    original = loop_break_jcc._iter_c_nodes_deep_8616
    walk_count = 0

    def counted_walk(node: object) -> Iterator[object]:
        nonlocal walk_count
        walk_count += 1
        yield from original(node)

    monkeypatch.setattr(loop_break_jcc, "_iter_c_nodes_deep_8616", counted_walk)

    surface = loop_break_jcc._collect_loop_break_initial_surface_8616(root)

    assert walk_count == 1
    assert surface.condition_keys == frozenset({(0x1002, 0x1000), (0x1012, 0x1010)})
    assert surface.loop_header_jcc_addrs == frozenset({0x1002})
    assert surface.typed_loop_condition_jcc_addrs == frozenset({0x1002})
    assert dict(surface.break_nodes_by_key) == {(0x1012, 0x1010): (guard,)}


def test_loop_break_ast_query_session_reuses_only_unchanged_subtrees(
    monkeypatch,
) -> None:
    """Repeated membership queries share one walk and rebuild after mutation."""
    codegen = _Codegen()
    condition = _condition(codegen, ins_addr=0x1022, block_addr=0x1020)
    guard = CIfBreak(condition, codegen=codegen, cstyle_ifs=True)
    root = CStatements([guard], codegen=codegen)
    original = loop_break_jcc._iter_c_nodes_deep_8616
    walk_count = 0

    def counted_walk(node: object) -> Iterator[object]:
        nonlocal walk_count
        walk_count += 1
        yield from original(node)

    monkeypatch.setattr(loop_break_jcc, "_iter_c_nodes_deep_8616", counted_walk)
    session = loop_break_jcc._LoopBreakAstQuerySession8616()

    assert session.contains_instruction(root, 0x1022)
    assert session.contains_node(root, guard)
    assert walk_count == 1

    root.statements = [CBreak(codegen=codegen)]
    session.record_mutation()

    assert not session.contains_instruction(root, 0x1022)
    assert not session.contains_node(root, guard)
    assert walk_count == 2
    stats = loop_break_jcc.UnconsumedLoopBreakJccStats8616()
    session.record_stats(stats)
    assert stats.ast_query_count == 4
    assert stats.ast_query_build_count == 2
    assert stats.ast_query_hit_count == 2
    assert stats.ast_query_invalidation_count == 1
