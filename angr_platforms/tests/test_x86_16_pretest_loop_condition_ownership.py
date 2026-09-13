"""Regressions for exact pretest loop-condition ownership."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CBreak,
    CConstant,
    CForLoop,
    CIfBreak,
    CIfElse,
    CStatements,
    CUnaryOp,
)
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.structuring.loop_condition_materialization import (
    materialize_typed_loop_continuation_conditions_8616,
)


class _Codegen:
    """Minimal angr structured-C codegen fixture."""

    def __init__(self) -> None:
        self._next_idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        """Return one deterministic structured-C node index."""
        self._next_idx += 1
        return self._next_idx

    def next_node_idx(self) -> int:
        """Return one deterministic structured-C node index."""
        return self.next_idx("")

    @staticmethod
    def next_ident(name: str) -> str:
        """Return one deterministic identifier."""
        return name


def _pretest_fixture() -> tuple[_Codegen, CForLoop, CStatements, ConditionIR]:
    """Build a constant loop with one exact typed break guard in its body."""
    codegen = _Codegen()
    value_type = SimTypeShort(True).with_arch(codegen.project.arch)
    break_condition = CBinaryOp(
        "CmpLT",
        CConstant(1, value_type, codegen=codegen),
        CConstant(4, value_type, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10126, "vex_block_addr": 0x10120},
    )
    loop = CForLoop(
        None,
        CConstant(1, value_type, codegen=codegen),
        None,
        CStatements([CIfBreak(break_condition, codegen=codegen)], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)
    typed = ConditionIR(
        op="slt",
        lhs=1,
        rhs=4,
        src_insn=0x10126,
        block_addr=0x10120,
        taken_target=0x10128,
        fallthrough_target=0x1012B,
    )
    return codegen, loop, root, typed


def test_exact_pretest_break_owns_condition_before_header_materialization() -> None:
    """One JCC must not become both a loop header and an in-body break."""
    codegen, loop, root, typed = _pretest_fixture()
    replacement = CConstant(7, SimTypeShort(True), codegen=codegen)

    stats = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        (typed,),
        {
            0x10120: (0x10128, 0x1012B),
            0x10128: (0x10120,),
            0x1012B: (),
        },
        lambda _condition: replacement,
    )

    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert stats.composite_loop_exit_owned_count == 1
    assert stats.changed_count == 1
    assert loop.condition is replacement
    assert isinstance(loop.body.statements[0], CStatements)
    assert not loop.body.statements[0].statements


def test_pretest_break_refuses_when_both_jcc_edges_reenter_loop() -> None:
    """Ambiguous CFG ownership must preserve the original loop condition."""
    codegen, loop, root, typed = _pretest_fixture()
    original = loop.condition

    stats = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        (typed,),
        {
            0x10120: (0x10128, 0x1012B),
            0x10128: (0x10120,),
            0x1012B: (0x10120,),
        },
        lambda _condition: (_ for _ in ()).throw(
            AssertionError("ambiguous pretest condition was lowered")
        ),
    )

    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1
    assert stats.composite_loop_exit_owned_count == 0
    assert stats.changed_count == 0
    assert loop.condition is original


def test_expanded_pretest_break_owns_condition_before_header_materialization() -> None:
    """A one-arm if containing one break is the same exact exit carrier."""
    codegen, loop, root, typed = _pretest_fixture()
    break_condition = loop.body.statements[0].condition
    loop.body = CStatements(
        [
            CIfElse(
                [
                    (
                        break_condition,
                        CStatements([CBreak(codegen=codegen)], codegen=codegen),
                    )
                ],
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )
    replacement = CConstant(7, SimTypeShort(True), codegen=codegen)

    stats = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        (typed,),
        {
            0x10120: (0x10128, 0x1012B),
            0x10128: (0x10120,),
            0x1012B: (),
        },
        lambda _condition: replacement,
    )

    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert stats.composite_loop_exit_owned_count == 1
    assert stats.changed_count == 1
    assert loop.condition is replacement
    assert isinstance(loop.body.statements[0], CStatements)
    assert not loop.body.statements[0].statements


def test_structured_body_owner_cannot_override_unique_cfg_continuation() -> None:
    """Contradictory structured ownership must refuse the typed loop guard."""
    codegen = _Codegen()
    value_type = SimTypeShort(True).with_arch(codegen.project.arch)
    current = CBinaryOp(
        "CmpLT",
        CConstant(1, value_type, codegen=codegen),
        CConstant(4, value_type, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10126, "vex_block_addr": 0x10120},
    )
    body_marker = CConstant(
        1,
        value_type,
        codegen=codegen,
    )
    # Execution ownership belongs to the statement, not reused operand tags.
    body_guard = CIfBreak(body_marker, codegen=codegen, tags={"vex_block_addr": 0x1012B})
    loop = CForLoop(
        None,
        current,
        None,
        CStatements([body_guard], codegen=codegen),
        codegen=codegen,
    )
    typed = ConditionIR(
        op="slt",
        lhs=1,
        rhs=4,
        src_insn=0x10126,
        block_addr=0x10120,
        taken_target=0x10128,
        fallthrough_target=0x1012B,
    )

    stats = materialize_typed_loop_continuation_conditions_8616(
        CStatements([loop], codegen=codegen),
        codegen,
        (typed,),
        {
            0x10120: (0x10128, 0x1012B),
            0x10128: (0x10120,),
            0x1012B: (),
        },
        lambda _condition: (_ for _ in ()).throw(
            AssertionError("contradictory structured owner overrode unique CFG evidence")
        ),
    )

    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1
    assert stats.changed_count == 0
    assert loop.condition is current
    assert current.tags.get("inertia_typed_loop_condition_bound_8616") is not True


def test_cfg_selects_fresh_body_key_over_stale_rebuilt_header_key() -> None:
    """A rebuilt loop must bind the sole CFG-valid JCC from its body evidence."""
    codegen = _Codegen()
    value_type = SimTypeShort(True).with_arch(codegen.project.arch)
    stale_header = CConstant(
        1,
        value_type,
        codegen=codegen,
        tags={"ins_addr": 0x10126, "vex_block_addr": 0x10120},
    )
    fresh_guard = CConstant(
        1,
        value_type,
        codegen=codegen,
    )
    fresh_break = CIfBreak(CUnaryOp("Not", fresh_guard, codegen=codegen), codegen=codegen)
    fresh_break.tags = {"ins_addr": 0x10226, "vex_block_addr": 0x10220}
    loop = CForLoop(
        None,
        stale_header,
        None,
        CStatements([fresh_break], codegen=codegen),
        codegen=codegen,
    )
    stale = ConditionIR(
        op="slt",
        lhs=1,
        rhs=4,
        src_insn=0x10126,
        block_addr=0x10120,
        taken_target=0x10128,
        fallthrough_target=0x1012B,
    )
    fresh = ConditionIR(
        op="slt",
        lhs=2,
        rhs=5,
        src_insn=0x10226,
        block_addr=0x10220,
        taken_target=0x10228,
        fallthrough_target=0x1022B,
    )
    replacement = CConstant(7, value_type, codegen=codegen)

    stats = materialize_typed_loop_continuation_conditions_8616(
        CStatements([loop], codegen=codegen),
        codegen,
        (stale, fresh),
        {
            0x10120: (0x10128, 0x1012B),
            0x10128: (0x10120,),
            0x1012B: (),
            0x10220: (0x10228, 0x1022B),
            0x10228: (0x10220,),
            0x1022B: (),
        },
        lambda condition: replacement
        if condition is fresh
        else (_ for _ in ()).throw(AssertionError("stale header JCC was selected")),
    )

    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert stats.composite_loop_exit_owned_count == 1
    assert loop.condition is replacement
    assert replacement.tags["inertia_typed_loop_condition_key_8616"] == (0x10226, 0x10220)

    nested_guard = CConstant(
        1,
        value_type,
        codegen=codegen,
        tags={"ins_addr": 0x10226, "vex_block_addr": 0x10220},
    )
    exact_header = CConstant(
        1,
        value_type,
        codegen=codegen,
        tags={"ins_addr": 0x10126, "vex_block_addr": 0x10120},
    )
    header_loop = CForLoop(
        None,
        exact_header,
        None,
        CStatements(
                [
                    CIfBreak(CConstant(1, value_type, codegen=codegen), codegen=codegen),
                    CIfBreak(nested_guard, codegen=codegen),
                ],
            codegen=codegen,
        ),
        codegen=codegen,
    )
    header_replacement = CConstant(9, value_type, codegen=codegen)
    header_stats = materialize_typed_loop_continuation_conditions_8616(
        CStatements([header_loop], codegen=codegen),
        codegen,
        (stale, fresh),
        {
            0x10120: (0x10128, 0x1012B),
            0x10128: (0x10120,),
            0x1012B: (),
            0x10220: (0x10228, 0x1022B),
            0x10228: (0x10220,),
            0x1022B: (),
        },
        lambda condition: header_replacement
        if condition is stale
        else (_ for _ in ()).throw(AssertionError("nested body JCC was selected")),
    )

    assert header_stats.materialized_count == 1
    assert header_stats.failure_count == 0
    assert header_loop.condition is header_replacement
