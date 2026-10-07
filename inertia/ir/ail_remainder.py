"""Preserve division semantics while normalizing native AIL remainders.

Layer: IR/native AIL adapter.
Responsibility: fold proven same-width integer remainder identities.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, Convert, Expression, Register, UnaryOp, VirtualVariable


def _pure_integer_8616(expression: Expression) -> bool:
    """Refuse loads, calls and dirty expressions whose repeated evaluation matters."""
    if isinstance(expression, (Const, Register, VirtualVariable)):
        return True
    if isinstance(expression, Convert):
        return _pure_integer_8616(expression.operand)
    if isinstance(expression, UnaryOp):
        return expression.op in {"Neg", "Not"} and _pure_integer_8616(expression.operand)
    if isinstance(expression, BinaryOp):
        scalar = not expression.floating_point and expression.vector_count is None and expression.vector_size is None
        total_operation = expression.op in {"Add", "Sub", "Mul", "And", "Or", "Xor", "Shl", "Shr", "Sar"}
        return scalar and total_operation and all(_pure_integer_8616(part) for part in expression.operands)
    return False


def fold_integer_remainder_8616(expression: BinaryOp) -> BinaryOp | None:
    """Fold a - (a / n) * n without changing width, signedness or fault behavior.

    Conversion-crossing forms remain intact: extending a wrapped product is
    not generally equivalent to extending the remainder. Signed division by
    minus one is retained because its minimum-value overflow may be observable.
    """
    if expression.op != "Sub":
        return None
    value, product = expression.operands
    if not isinstance(product, BinaryOp) or product.op != "Mul":
        return None
    quotient, multiplier = product.operands
    if not isinstance(quotient, BinaryOp) or quotient.op != "Div":
        return None
    dividend, divisor = quotient.operands
    if not isinstance(divisor, Const) or not isinstance(multiplier, Const):
        return None
    nodes = (expression, product, quotient, value, dividend, divisor, multiplier)
    if any(node.bits != expression.bits for node in nodes):
        return None
    if not value.likes(dividend) or not divisor.likes(multiplier) or not _pure_integer_8616(value):
        return None
    operations = (expression, product, quotient)
    if any(op.floating_point or op.vector_count is not None or op.vector_size is not None for op in operations):
        return None
    unsafe_divisors = {0, -1, (1 << expression.bits) - 1} if quotient.signed else {0}
    if divisor.value in unsafe_divisors:
        return None
    return BinaryOp(expression.idx, "Mod", [value, divisor], quotient.signed, bits=expression.bits, **expression.tags)
