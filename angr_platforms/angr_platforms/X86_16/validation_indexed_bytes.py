"""Identify explicit byte views of addressed scalar storage in generated C.

Layer: Tail validation.
Responsibility: consume typed address-of, pointer-cast and constant-index nodes
without recovering storage from text or changing the AST. The caller must prove
the owner's storage identity and that the byte lies within that owner.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CIndexedVariable,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypePointer


def indexed_scalar_byte_view_8616(node: object) -> tuple[CVariable, int] | None:
    """Return a scalar owner and exact byte index, refusing indirect pointers."""
    if not isinstance(node, CIndexedVariable) or not isinstance(node.type, SimTypeChar):
        return None
    index = node.index
    if not isinstance(index, CConstant) or type(index.value) is not int or index.value < 0:
        return None
    pointer = node.variable
    if not isinstance(pointer, CTypeCast):
        return None
    pointer_type = pointer.dst_type
    if not isinstance(pointer_type, SimTypePointer) or not isinstance(pointer_type.pts_to, SimTypeChar):
        return None
    reference = pointer.expr
    if not isinstance(reference, CUnaryOp) or reference.op != "Reference":
        return None
    owner = reference.operand
    return (owner, index.value) if isinstance(owner, CVariable) else None
