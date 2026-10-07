"""Match typed global projections of binary-proven segmented stack sources.

Layer: Types/Lowering.
Responsibility: prove that an indexed global C expression denotes the same
segmented source address consumed by a direct-stack move fact.
Consumes alias, widening, and typed facts: stack coordinates and structured
global storage identity.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CIndexedVariable,
    CTypeCast,
    CVariable,
    CVariableField,
)
from angr.sim_variable import SimMemoryVariable, SimStackVariable

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616

from .segment_access_policy import instruction_addrs_from_node_8616
from .stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616


@dataclass(frozen=True, slots=True)
class SegmentedStackSourceProjection8616:
    """Exact source and destination coordinates consumed by one stack move."""

    instruction_addr: int
    destination_machine_bp_offset: int
    destination_width: int
    source_displacement: int
    source_index_machine_bp_offset: int
    source_index_byte_scale: int
    source_access_width: int

    def __post_init__(self) -> None:
        """Reject malformed coordinates before matching structured C."""
        if self.instruction_addr < 0:
            raise ValueError("instruction address must be nonnegative")
        if self.destination_width <= 0 or self.source_access_width <= 0:
            raise ValueError("projection widths must be positive")
        if self.source_index_byte_scale <= 0:
            raise ValueError("source index byte scale must be positive")


def _strip_casts_8616(node: object) -> object:
    """Strip syntax-only casts from one structured expression."""
    while isinstance(node, CTypeCast):
        node = node.expr
    return node


def _constant_value_8616(node: object) -> int | None:
    """Return one exact structured integer constant."""
    node = _strip_casts_8616(node)
    return int(node.value) if isinstance(node, CConstant) and isinstance(node.value, int) else None


def _index_coordinate_8616(codegen: object, node: object) -> tuple[int, int] | None:
    """Return machine-BP stack identity and constant element adjustment."""
    node = _strip_casts_8616(node)
    if isinstance(node, CVariable) and isinstance(node.variable, SimStackVariable):
        offset = machine_bp_offset_for_stack_variable_8616(codegen, node.variable)
        return (offset, 0) if isinstance(offset, int) else None
    if not isinstance(node, CBinaryOp) or node.op not in {"Add", "Sub"}:
        return None
    base = _index_coordinate_8616(codegen, node.lhs)
    adjustment = _constant_value_8616(node.rhs)
    if base is None or adjustment is None:
        return None
    return base[0], base[1] + (adjustment if node.op == "Add" else -adjustment)


def _source_projection_matches_8616(
    codegen: object,
    node: object,
    projection: SegmentedStackSourceProjection8616,
) -> bool:
    """Match one indexed global expression by exact effective address."""
    node = _strip_casts_8616(node)
    field_offset = 0
    projected_access_width: int | None = None
    if isinstance(node, CVariableField):
        field_offset = node.field.offset
        node = node.variable
        projected_access_width = 1
        if not isinstance(field_offset, int):
            return False
    if not isinstance(node, CIndexedVariable):
        return False
    base = node.variable
    if not isinstance(base, CVariable) or not isinstance(base.variable, SimMemoryVariable):
        return False
    base_addr = base.variable.addr
    element_width = base.variable.size
    index_coordinate = _index_coordinate_8616(codegen, node.index)
    if (
        not isinstance(base_addr, int)
        or not isinstance(element_width, int)
        or index_coordinate is None
        or element_width != projection.source_index_byte_scale
        or index_coordinate[0] != projection.source_index_machine_bp_offset
    ):
        return False
    if projected_access_width is None:
        projected_access_width = element_width
    if (
        projected_access_width != projection.source_access_width
        or field_offset < 0
        or field_offset + projected_access_width > element_width
    ):
        return False
    effective_base = (base_addr + index_coordinate[1] * element_width + field_offset) & 0xFFFF
    return effective_base == (projection.source_displacement & 0xFFFF)


def projected_segmented_stack_assignment_present_8616(
    codegen: object,
    root: object,
    projection: SegmentedStackSourceProjection8616,
) -> bool:
    """Return whether exact instruction, destination, and source storage agree."""
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CAssignment):
            continue
        if projection.instruction_addr not in instruction_addrs_from_node_8616(node):
            continue
        lhs = _strip_casts_8616(node.lhs)
        if not isinstance(lhs, CVariable) or not isinstance(lhs.variable, SimStackVariable):
            continue
        destination_offset = machine_bp_offset_for_stack_variable_8616(codegen, lhs.variable)
        if (
            destination_offset == projection.destination_machine_bp_offset
            and lhs.variable.size == projection.destination_width
            and _source_projection_matches_8616(codegen, node.rhs, projection)
        ):
            return True
    return False


__all__ = [
    "SegmentedStackSourceProjection8616",
    "projected_segmented_stack_assignment_present_8616",
]
