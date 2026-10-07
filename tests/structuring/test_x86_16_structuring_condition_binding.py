from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from angr.analyses.decompiler.structured_codegen.c import CExpression
from inertia.ir.condition_ir import ConditionIR

from inertia.structuring.condition_binding import (
    select_unique_condition_by_expression_8616,
)


def _condition(op: str, src_insn: int) -> ConditionIR:
    return ConditionIR(op=op, lhs="left", rhs="right", src_insn=src_insn)


@dataclass(frozen=True)
class _Expression:
    op: str
    lhs: object
    rhs: object


def _expression(op: str) -> CExpression:
    return cast(CExpression, _Expression(op, "left", "right"))


def _materialize(condition: ConditionIR) -> CExpression:
    return cast(CExpression, _Expression(condition.op, condition.lhs, condition.rhs))


def _same(left: CExpression, right: CExpression) -> bool:
    return cast(_Expression, left) == cast(_Expression, right)


def test_structuring_condition_binding_accepts_unique_structural_match() -> None:
    selected = select_unique_condition_by_expression_8616(
        _expression("sle"),
        (_condition("sle", 0x1014), _condition("sge", 0x1019)),
        _materialize,
        _same,
    )

    assert selected == _condition("sle", 0x1014)


def test_structuring_condition_binding_refuses_ambiguous_structural_match() -> None:
    selected = select_unique_condition_by_expression_8616(
        _expression("sle"),
        (_condition("sle", 0x1014), _condition("sle", 0x1020)),
        _materialize,
        _same,
    )

    assert selected is None
