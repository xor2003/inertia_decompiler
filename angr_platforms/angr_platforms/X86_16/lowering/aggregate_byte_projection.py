"""Project exact scalar byte views of already-proven two-byte aggregates.

Layer: Types/Lowering.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Responsibility: preserve the original object and byte offset when scalar
consumers survive aggregate promotion. Consume layout proof; never infer it
from arithmetic expressions whose inherited type merely resembles a struct.
"""

from __future__ import annotations

from collections.abc import Callable

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CExpression,
    CFunctionCall,
    CIndexedVariable,
    CStructField,
    CUnaryOp,
    CVariable,
    CVariableField,
)
from angr.sim_type import SimStruct

_BYTE_BITS: int = 8
_BYTE_SHIFTS: tuple[int, ...] = (0, _BYTE_BITS)


def project_proven_aggregate_byte_8616(
    expression: CExpression,
    codegen: object,
    resolve_layout: Callable[[object], SimStruct | None],
) -> CVariableField | None:
    """Select a byte from an exact object or word-shift view, otherwise refuse.

    The resolver must prove the existing ordered two-byte-field layout. A
    shift selects a byte of its operand, not a field of the shift expression.
    Do not cross other arithmetic or casts even if angr inherits their type.
    """
    byte_offset = 0
    source = expression
    if isinstance(source, CBinaryOp):
        shift = source.rhs
        exact_byte_shift = (
            source.op == "Shr" and isinstance(shift, CConstant)
            and isinstance(shift.value, int) and shift.value in _BYTE_SHIFTS
        )
        if not exact_byte_shift:
            return None
        byte_offset = int(shift.value) // _BYTE_BITS
        source = source.lhs
    direct_object = isinstance(source, (CVariable, CIndexedVariable, CVariableField, CFunctionCall))
    indirect_object = isinstance(source, CUnaryOp) and source.op == "Dereference"
    if not direct_object and not indirect_object:
        return None
    layout = resolve_layout(source.type)
    if layout is None:
        return None
    field_name = tuple(layout.fields)[byte_offset]
    return CVariableField(
        source, CStructField(layout, byte_offset, field_name, codegen=codegen), codegen=codegen,
    )
