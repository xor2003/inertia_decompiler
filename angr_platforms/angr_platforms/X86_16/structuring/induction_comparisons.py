"""Match stable induction operands without changing their conversions.

Layer: Structuring.
Responsibility: inspect existing storage identities under pure casts when
joining an initializer and iterator to an ordered loop condition. The original
condition, including width/signedness conversions, must remain unchanged.
This proves neither monotonicity nor cast redundancy and performs no recovery.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CExpression,
    CTypeCast,
    CVariable,
)

from ..c_ast_utils import _same_c_expression_8616


def _stable_operand(expression: CExpression) -> CVariable | CConstant | None:
    """Inspect a pure conversion chain; refuse calls, loads and arithmetic."""
    while isinstance(expression, CTypeCast):
        expression = expression.expr
    return expression if isinstance(expression, (CVariable, CConstant)) else None


def ordered_comparison_uses_induction_8616(condition: CExpression, induction: CVariable) -> bool:
    """Require exactly one stable operand to refer to the induction storage."""
    if not isinstance(condition, CBinaryOp) or condition.op not in {"CmpLT", "CmpLE", "CmpGT", "CmpGE"}:
        return False
    lhs = _stable_operand(condition.lhs)
    rhs = _stable_operand(condition.rhs)
    if lhs is None or rhs is None:
        return False
    lhs_matches = isinstance(lhs, CVariable) and _same_c_expression_8616(lhs, induction)
    rhs_matches = isinstance(rhs, CVariable) and _same_c_expression_8616(rhs, induction)
    return lhs_matches != rhs_matches
