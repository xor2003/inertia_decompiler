"""Layer: IR.
Responsibility: admit only owned condition operands to private native fact copies.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations

from .condition_ir import ConditionFailure, ConditionIR, ConditionSource
from .condition_lift_capture import ConditionLiftCaptureSession8616
from .core import IRAddress, IRBinaryValue, IRValue

_MAX_OPERANDS = 16384


def _owned_operand(value: object, seen: set[int]) -> bool:
    """Reject opaque third-party values at the legacy Any-typed capture boundary."""
    if value is None or type(value) in (int, str, bool, bytes):
        return True
    if id(value) in seen:
        return True
    if len(seen) >= _MAX_OPERANDS:
        return False
    seen.add(id(value))
    if type(value) is tuple:
        return all(_owned_operand(item, seen) for item in value)
    if type(value) is IRValue:
        return (
            _owned_operand(value.index, seen) and _owned_operand(value.expr, seen)
            and (value.active_unary is None or _owned_operand(value.active_unary.operand, seen))
        )
    if type(value) is IRBinaryValue:
        return _owned_operand(value.lhs, seen) and _owned_operand(value.rhs, seen)
    if type(value) is IRAddress:
        return _owned_operand(value.base_values, seen) and _owned_operand(value.expr, seen)
    return False


def native_capture_copyable_8616(capture: ConditionLiftCaptureSession8616) -> bool:
    """Allow private copies only when every untyped condition payload is owned IR."""
    seen: set[int] = set()
    for rows in capture.condition_cache.values():
        for row in rows:
            if type(row) is ConditionFailure:
                continue
            if type(row) is not ConditionIR or not all(
                _owned_operand(value, seen)
                for value in (row.lhs, row.rhs, row.producer_semantics)
            ):
                return False
    for source in capture.pending_sources.values():
        if type(source) is not ConditionSource or not all(
            _owned_operand(value, seen) for value in (
                source.lhs, source.rhs, source.normalized_lhs,
                source.normalized_rhs, source.semantics,
            )
        ):
            return False
    return True
