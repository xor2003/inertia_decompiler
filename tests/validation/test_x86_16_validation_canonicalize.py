from __future__ import annotations

from dataclasses import dataclass

from inertia.validation.canonicalize import (
    EquivalenceResult,
    canonicalize_expr_for_validation_8616,
    equivalent_expr_8616,
)


@dataclass(frozen=True, slots=True)
class DummyBinaryExpr:
    op: str
    lhs: object
    rhs: object
    codegen: object | None = None


def test_validation_canonicalize_simplifies_shaped_expression_add_zero():
    symbol = object()
    expr = DummyBinaryExpr("Add", symbol, 0)

    assert canonicalize_expr_for_validation_8616(expr) is symbol


def test_validation_canonicalize_simplifies_shaped_expression_sub_self():
    expr = DummyBinaryExpr("Sub", 7, 7)

    assert str(canonicalize_expr_for_validation_8616(expr)) == "0"


def test_validation_equivalence_uses_canonicalized_shaped_expressions():
    symbol = object()
    lhs = DummyBinaryExpr("Add", symbol, 0)

    assert equivalent_expr_8616(lhs, symbol) is EquivalenceResult.EQUIVALENT
