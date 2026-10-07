"""Resolve typed aggregate fields to exact segmented storage locations.

Layer: Tail validation.
Responsibility: map non-pointer structured-C aggregate fields back to their
proven global byte ranges without mutating the final AST.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Forbidden: semantic recovery, AST mutation, or name-based storage inference.

Package ownership contract (canonical inertia/validation package):
Layer: Validation.
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.analyses.decompiler.structured_codegen.c import unpack_typeref
from angr.sim_type import SimType
from angr.sim_variable import SimMemoryVariable

from inertia.ir.core import MemSpace

__all__ = [
    "AggregateFieldStorage8616",
    "aggregate_field_storage_8616",
]


@dataclass(frozen=True, slots=True)
class AggregateFieldStorage8616:
    """Exact byte location and width of one final aggregate field."""

    space: MemSpace
    offset: int
    width: int


def _strip_casts_8616(node: object) -> object:
    """Return the structured expression beneath transparent C casts."""
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _field_width_8616(node: structured_c.CVariableField) -> int | None:
    """Return the architecture-bound byte width of the selected leaf field."""
    field_type = node.field.type
    if not isinstance(field_type, SimType):
        return None
    try:
        bits = unpack_typeref(field_type).size
    except (AttributeError, TypeError, ValueError):
        return None
    if not isinstance(bits, int) or bits <= 0 or bits % 8 != 0:
        return None
    return bits // 8


def aggregate_field_storage_8616(node: object) -> AggregateFieldStorage8616 | None:
    """Resolve one nested non-pointer global field from typed AST structure."""
    current = _strip_casts_8616(node)
    if not isinstance(current, structured_c.CVariableField):
        return None
    width = _field_width_8616(current)
    if width is None:
        return None
    relative_offset = 0
    while isinstance(current, structured_c.CVariableField):
        field_offset = current.field.offset
        if current.var_is_ptr or not isinstance(field_offset, int) or isinstance(field_offset, bool):
            return None
        if field_offset < 0:
            return None
        relative_offset += field_offset
        current = _strip_casts_8616(current.variable)
    if not isinstance(current, structured_c.CVariable):
        return None
    variable = current.variable
    if not isinstance(variable, SimMemoryVariable):
        return None
    base_offset = variable.addr
    if not isinstance(base_offset, int) or isinstance(base_offset, bool):
        return None
    if not 0 <= base_offset <= 0xFFFF:
        return None
    return AggregateFieldStorage8616(
        space=MemSpace.DS,
        offset=(base_offset + relative_offset) & 0xFFFF,
        width=width,
    )
