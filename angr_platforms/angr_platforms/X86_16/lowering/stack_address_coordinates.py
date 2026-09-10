"""Resolve stack-address anchors across angr and machine coordinates.

Layer: Types/Lowering.
Responsibility: consume the proven BP-to-entry-SP frame coordinate when an
unprojected angr stack variable is used specifically as an address anchor.
This does not reinterpret ordinary stack variables or infer storage identity.
Consumes IR frame evidence and existing coordinate projections.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from ..analysis.stack_frame_ir import FrameAccessArtifact, FrameCoordinateStatus8616
from ..ir.native_stack_anchor import native_stack_anchor_8616
from .stack_variable_coordinates import stack_variable_coordinate_registry_8616


class _CodegenBoundary8616(Protocol):
    """Dynamic codegen boundary carrying the typed frame artifact."""

    _inertia_vex_ir_frame: object


def machine_bp_offset_for_native_anchor_8616(codegen: object, node: object) -> int | None:
    """Translate an explicitly published source anchor using complete frame proof."""
    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Reference":
        return None
    anchor = native_stack_anchor_8616(node.tags)
    if anchor is None:
        return None
    try:
        frame = cast(_CodegenBoundary8616, codegen)._inertia_vex_ir_frame
    except AttributeError:
        return None
    if (
        not isinstance(frame, FrameAccessArtifact)
        or not frame.bp_coordinate.complete
        or frame.bp_coordinate.status is not FrameCoordinateStatus8616.PROVEN
        or type(frame.bp_coordinate.bp_entry_sp_delta) is not int
    ):
        return None
    return anchor.entry_sp_offset - frame.bp_coordinate.bp_entry_sp_delta


def machine_bp_offset_for_entry_sp_anchor_8616(
    codegen: object,
    node: object,
) -> int | None:
    """Project one unbound ``&stack_var`` address anchor to machine BP.

    Already-projected variables are refused here because their authoritative
    machine coordinate is owned by ``stack_variable_coordinates``. The frame
    delta is used only for an otherwise-unbound address anchor, never as a
    global reinterpretation of legacy angr stack variables.
    """
    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Reference":
        return None
    operand = node.operand
    if not isinstance(operand, structured_c.CVariable):
        return None
    variable = operand.variable
    if (
        not isinstance(variable, SimStackVariable)
        or variable.base != "bp"
        or not isinstance(variable.offset, int)
        or not isinstance(variable.size, int)
    ):
        return None
    registry = stack_variable_coordinate_registry_8616(codegen)
    if (
        registry.for_variable(variable) is not None
        or registry.for_entry_sp_range(variable.offset, variable.size) is not None
        or registry.containing_entry_sp_range(variable.offset, variable.size) is not None
    ):
        return None
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        frame = boundary._inertia_vex_ir_frame
    except AttributeError:
        return None
    if (
        not isinstance(frame, FrameAccessArtifact)
        or not frame.bp_coordinate.complete
        or frame.bp_coordinate.status is not FrameCoordinateStatus8616.PROVEN
        or not isinstance(frame.bp_coordinate.bp_entry_sp_delta, int)
    ):
        return None
    return variable.offset - frame.bp_coordinate.bp_entry_sp_delta


def absolute_machine_bp_offset_from_wrapped_anchor_8616(
    node: object,
    encoded_offset: int,
    known_bp_offsets: set[int],
) -> int | None:
    """Return a wrapped direct BP displacement carried beside a frame anchor."""
    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Reference":
        return None
    operand = node.operand
    variable = operand.variable if isinstance(operand, structured_c.CVariable) else None
    if not isinstance(variable, SimStackVariable) or variable.base != "bp":
        return None
    if not 0x8000 <= encoded_offset <= 0xFFFF:
        return None
    displacement = encoded_offset - 0x10000
    return displacement if displacement in known_bp_offsets else None


def consume_indexed_stack_frame_terms_8616(
    codegen: object,
    terms: tuple[tuple[int, object], ...],
    *,
    segment_name: Callable[[object], str | None],
) -> tuple[tuple[int, object], ...] | None:
    """Remove one proven SS/BP-zero frame from an indexed linear address.

    A local C pointer already embodies its frame. Preserve index/lane terms,
    but refuse foreign segments and ambiguous or unproven frame anchors.
    Offset-only input remains owned by the caller's existing indexed proof.
    """
    segments = [(index, sign, segment_name(term)) for index, (sign, term) in enumerate(terms)]
    segments = [entry for entry in segments if entry[2] is not None]
    if not segments:
        return terms
    if len(segments) != 1 or segments[0][1:] != (1, "ss"):
        return None
    anchors: list[int] = []
    registry = stack_variable_coordinate_registry_8616(codegen)
    for index, (sign, term) in enumerate(terms):
        if not isinstance(term, structured_c.CUnaryOp) or term.op != "Reference":
            continue
        operand = term.operand
        if not isinstance(operand, structured_c.CVariable) or not isinstance(operand.variable, SimStackVariable):
            continue
        projection = registry.for_variable(operand.variable)
        offset = (
            projection.bp_offset if projection is not None
            else machine_bp_offset_for_entry_sp_anchor_8616(codegen, term)
        )
        if sign != 1 or offset != 0:
            return None
        anchors.append(index)
    if len(anchors) != 1:
        return None
    consumed = {segments[0][0], anchors[0]}
    return tuple(term for index, term in enumerate(terms) if index not in consumed)


__all__ = [
    "absolute_machine_bp_offset_from_wrapped_anchor_8616",
    "consume_indexed_stack_frame_terms_8616",
    "machine_bp_offset_for_entry_sp_anchor_8616",
]
