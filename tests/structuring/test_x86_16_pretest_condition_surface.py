"""Tests for typed structured pretest-condition projection."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBreak,
    CConstant,
    CIfBreak,
    CIfElse,
    CStatements,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from archinfo import ArchX86

from inertia.structuring.pretest_condition_surface import (
    pretest_condition_surface_8616,
)


def _codegen() -> SimpleNamespace:
    """Build the minimum structured-codegen boundary for C-AST fixtures."""
    return SimpleNamespace(
        cstyle_null_cmp=False,
        next_idx=lambda _name="": 1,
        next_ident=lambda name: f"{name}_0",
        next_node_idx=lambda: 1,
        project=SimpleNamespace(arch=ArchX86()),
    )


def _constant(value: int, codegen: object) -> CConstant:
    """Build one typed fixture constant."""
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def test_projects_header_and_unique_leading_ifbreak() -> None:
    """A pretest shell exposes both exact condition carriers in AST order."""
    codegen = _codegen()
    header = _constant(1, codegen)
    guard_condition = _constant(0, codegen)
    guard = CIfBreak(guard_condition, codegen=codegen)
    loop = CWhileLoop(header, CStatements([guard], codegen=codegen), codegen=codegen)

    surface = pretest_condition_surface_8616(loop)

    assert surface.conditions == (header, guard_condition)
    assert surface.leading_break_guard is guard


def test_projects_exact_single_arm_ifelse_break() -> None:
    """The equivalent one-arm if/break representation is an exact carrier."""
    codegen = _codegen()
    condition = _constant(0, codegen)
    guard = CIfElse(
        [(condition, CStatements([CBreak(codegen=codegen)], codegen=codegen))],
        codegen=codegen,
    )
    loop = CWhileLoop(
        _constant(1, codegen),
        CStatements([CStatements([], codegen=codegen), guard], codegen=codegen),
        codegen=codegen,
    )

    surface = pretest_condition_surface_8616(loop)

    assert surface.conditions[-1] is condition
    assert surface.leading_break_guard is guard


def test_deduplicates_shared_header_and_break_expression() -> None:
    """One expression object remains one evidence surface entry."""
    codegen = _codegen()
    condition = _constant(1, codegen)
    loop = CWhileLoop(
        condition,
        CStatements([CIfBreak(condition, codegen=codegen)], codegen=codegen),
        codegen=codegen,
    )

    assert pretest_condition_surface_8616(loop).conditions == (condition,)


def test_refuses_effectful_ifelse_break_branch() -> None:
    """A break mixed with another statement is not a pure loop-header guard."""
    codegen = _codegen()
    word = SimTypeShort(False)
    variable = CVariable(
        SimStackVariable(-2, 2, base="bp", name="value"),
        variable_type=word,
        codegen=codegen,
    )
    guard_condition = _constant(0, codegen)
    guard = CIfElse(
        [
            (
                guard_condition,
                CStatements(
                    [
                        CBreak(codegen=codegen),
                        CAssignment(variable, variable, codegen=codegen),
                    ],
                    codegen=codegen,
                ),
            )
        ],
        codegen=codegen,
    )
    header = _constant(1, codegen)
    loop = CWhileLoop(header, CStatements([guard], codegen=codegen), codegen=codegen)

    surface = pretest_condition_surface_8616(loop)

    assert surface.conditions == (header,)
    assert surface.leading_break_guard is None


def test_refuses_multi_arm_or_else_guard() -> None:
    """Ambiguous control-flow shapes never contribute a projected condition."""
    codegen = _codegen()
    first = _constant(0, codegen)
    second = _constant(1, codegen)
    break_body = CStatements([CBreak(codegen=codegen)], codegen=codegen)
    guards = (
        CIfElse([(first, break_body), (second, break_body)], codegen=codegen),
        CIfElse([(first, break_body)], else_node=break_body, codegen=codegen),
    )

    for guard in guards:
        header = _constant(1, codegen)
        loop = CWhileLoop(
            header,
            CStatements([guard], codegen=codegen),
            codegen=codegen,
        )
        surface = pretest_condition_surface_8616(loop)
        assert surface.conditions == (header,)
        assert surface.leading_break_guard is None
