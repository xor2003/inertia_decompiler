"""Small typed constant proofs shared by capture validation and fingerprints.

Layer: Tail validation.
Responsibility: evaluate bounded pure integer expressions only when C promotions
and the declared storage types preserve their mathematical values.
Layer: Validation
Owns canonical equivalence checking and validation diagnostics
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant
from angr.sim_type import SimTypeChar, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeShort


def constant_integer_value_8616(node: object) -> int | None:
    """Prove a typed constant expression with bounded work and no mutable reads."""
    return _constant_bitwise_value(node, [64])


def fold_typed_constant_binary_8616(node: CBinaryOp, lhs: object, rhs: object) -> CConstant | None:
    """Fold already simplified literal operands under the shared typed proof."""
    if not isinstance(lhs, CConstant) or not isinstance(rhs, CConstant):
        return None
    candidate = CBinaryOp(node.op, lhs, rhs, codegen=node.codegen)
    value = constant_integer_value_8616(candidate)
    bounds = integer_bounds_8616(node.type)
    if value is None or bounds is None or not bounds[0] <= value <= bounds[1]:
        return None
    return CConstant(value, node.type, codegen=node.codegen)


def integer_bounds_8616(type_: object, storage_bits: int = 64) -> tuple[int, int] | None:
    """Return a bounded ordinary C integer domain; unknown and oversized types refuse."""
    if not isinstance(type_, (SimTypeChar, SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong)):
        return None
    if not isinstance(type_.signed, bool) or not isinstance(type_.size, int):
        return None
    bits = min(type_.size, storage_bits)
    if not 0 < bits <= 64:
        return None
    minimum = -(1 << (bits - 1)) if type_.signed else 0
    return minimum, (1 << (bits - int(type_.signed))) - 1


def _constant_bitwise_value(node: object, budget: list[int]) -> int | None:
    """Evaluate only typed literals and nonnegative And/Or/Xor within a 64-node budget.

    Nonnegative representable operands make integer promotions and signedness
    conversions value-preserving for these bitwise operations. Arithmetic,
    undefined shifts, negative bitwise operands and all mutable/effectful values refuse.
    Every intermediate result must also fit its declared integer type.
    """
    budget[0] -= 1
    if budget[0] < 0 or not isinstance(node, (CConstant, CBinaryOp)):
        return None
    bounds = integer_bounds_8616(node.type)
    if bounds is None:
        return None
    if isinstance(node, CConstant):
        value = node.value
        if not isinstance(value, int) or isinstance(value, bool):
            return None
    else:
        value = _nonnegative_bitwise_value(node, budget)
        if value is None:
            return None
    return value if bounds[0] <= value <= bounds[1] else None


def _nonnegative_bitwise_value(node: CBinaryOp, budget: list[int]) -> int | None:
    """Keep the evaluator restricted to promotion-independent bitwise constants."""
    if node.op not in {"And", "Or", "Xor", "Shl"}:
        return None
    left = _constant_bitwise_value(node.lhs, budget)
    right = _constant_bitwise_value(node.rhs, budget)
    if left is None or right is None or left < 0 or right < 0:
        return None
    if node.op == "Shl":
        return _defined_unsigned_shift(node, left, right)
    if node.op == "And":
        return left & right
    if node.op == "Or":
        return left | right
    return left ^ right


def _defined_unsigned_shift(node: CBinaryOp, left: int, right: int) -> int | None:
    """Admit unsigned left shifts safe under both DOS16 and host32 promotions."""
    type_ = node.lhs.type
    if integer_bounds_8616(type_) is None or type_.signed is not False:
        return None
    bits = type_.size
    promoted_bits = max(16, bits)
    if not 0 <= right < promoted_bits:
        return None
    value = left << right
    # Narrow operands may promote to signed int. Avoid its sign bit even when
    # the DOS unsigned-short route would permit a larger unsigned result.
    maximum = (1 << 15) - 1 if bits <= 16 else (1 << bits) - 1
    return value if value <= maximum else None
