"""Check the typed extent of a single machine-store projection.

Layer: Types/Lowering.
Responsibility: prevent a partial lvalue from consuming a complete store fact.
Instruction identity and equal immediate values do not prove byte coverage:
both bytes of a zero word store have the same value and source instruction.
Pair ownership and widening remain separate proof obligations. Unknown types
refuse single-store materialization; they do not justify deleting any effect.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import CExpression

_BITS_PER_BYTE = 8


def has_exact_store_projection_width_8616(lvalue: object, width_bytes: int) -> bool:
    """Require a known lvalue width equal to the consumed machine-store fact."""
    if not isinstance(lvalue, CExpression) or width_bytes <= 0:
        return False
    try:
        value_type = lvalue.type
        width_bits = value_type.size if value_type is not None else None
    except (AttributeError, TypeError, ValueError):
        # Native codegen types can be missing or not yet architecture-bound.
        return False
    return isinstance(width_bits, int) and width_bits == width_bytes * _BITS_PER_BYTE
