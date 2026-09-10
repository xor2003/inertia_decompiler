"""Induction matching must preserve conversions in the loop condition."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CContinue,
    CExpression,
    CForLoop,
    CStatements,
    CSwitchCase,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616
from angr_platforms.X86_16.structuring.canonical_for_loops import (
    _contains_current_loop_continue_8616,
    recover_canonical_for_loops_8616,
)
from angr_platforms.X86_16.structuring.induction_comparisons import ordered_comparison_uses_induction_8616
from test_x86_16_canonical_for_loops import _Codegen as _BaseCodegen
from test_x86_16_canonical_for_loops import _local


class _Codegen(_BaseCodegen):
    cfunc: SimpleNamespace


@pytest.mark.parametrize("existing_for", [False, True])
@pytest.mark.parametrize("cast_depth", [1, 2])
def test_attach_initializer_without_removing_condition_conversion(existing_for, cast_depth):
    codegen = _Codegen()
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    signed = SimTypeShort(True).with_arch(codegen.project.arch)
    induction = _local(-4, codegen)
    initializer = CAssignment(induction, CConstant(0, word, codegen=codegen), codegen=codegen)
    converted: CExpression = induction
    for _ in range(cast_depth):
        converted = CSemanticCast8616(word, signed, converted, codegen=codegen)
    condition = CBinaryOp("CmpLT", converted, CConstant(10, signed, codegen=codegen), codegen=codegen)
    iterator = CAssignment(
        induction,
        CBinaryOp("Add", induction, CConstant(1, word, codegen=codegen), codegen=codegen),
        codegen=codegen,
    )
    if existing_for:
        loop = CForLoop(None, condition, iterator, CStatements([], codegen=codegen), codegen=codegen)
    else:
        loop = CWhileLoop(condition, CStatements([iterator], codegen=codegen), codegen=codegen)
    root = CStatements([initializer, loop], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)

    assert recover_canonical_for_loops_8616(codegen)

    assert len(root.statements) == 1
    recovered = root.statements[0]
    assert isinstance(recovered, CForLoop)
    assert recovered.initializer is initializer
    assert recovered.condition is condition
    assert recovered.condition.lhs is converted
    assert recovered.iterator is iterator


@pytest.mark.parametrize("both_operands", [False, True])
def test_cast_does_not_make_ambiguous_or_computed_induction_stable(both_operands):
    codegen = _Codegen()
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    induction = _local(-4, codegen)
    operand = induction if both_operands else CBinaryOp(
        "Add", induction, CConstant(1, word, codegen=codegen), codegen=codegen,
    )
    converted = CSemanticCast8616(word, SimTypeShort(True), operand, codegen=codegen)
    condition = CBinaryOp("CmpLT", converted, induction, codegen=codegen)

    assert not ordered_comparison_uses_induction_8616(condition, induction)


def test_switch_case_continue_still_targets_enclosing_loop():
    codegen = _Codegen()
    switch = CSwitchCase(
        _local(-8, codegen),
        [(1, CStatements([CContinue(codegen=codegen)], codegen=codegen))],
        None,
        codegen=codegen,
    )

    assert _contains_current_loop_continue_8616(switch)
