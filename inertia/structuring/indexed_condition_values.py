"""Materialize proven indexed segmented values in structured conditions.

Layer: Structuring.
Responsibility: lower typed affine index evidence into equivalent C AST nodes.
Forbidden: index recovery, alias inference, rendered-text parsing, or cleanup.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CFunctionCall
from angr.sim_type import SimTypeShort

from inertia.ir.core import IRBinaryValue, IRValue

if TYPE_CHECKING:
    from angr.analyses.decompiler.structured_codegen.c import CExpression

__all__ = ["materialize_indexed_segmented_condition_value_8616"]


def materialize_indexed_segmented_condition_value_8616(
    operand: IRValue,
    segment: CExpression,
    codegen: object,
    lower_index: Callable[[IRValue | IRBinaryValue], CExpression | None],
    build_tags: Callable[[IRValue, str], dict[str, object]],
) -> CFunctionCall | None:
    """Build a segmented load from an exact typed affine index."""
    if operand.index is None or operand.index_shift < 0:
        return None
    index = lower_index(operand.index)
    if index is None:
        return None
    if operand.index_shift:
        index = CBinaryOp(
            "Shl",
            index,
            CConstant(operand.index_shift, SimTypeShort(signed=False), codegen=codegen),
            codegen=codegen,
        )
    offset = CConstant(int(operand.offset) & 0xFFFF, SimTypeShort(signed=False), codegen=codegen)
    indexed_offset = CBinaryOp("Add", offset, index, codegen=codegen)
    access_size = max(1, int(operand.memory_access_size or operand.size or 2))
    helper = {1: "SEG_U8", 2: "SEG_U16", 4: "SEG_U32"}.get(access_size)
    if helper is None:
        return None
    return CFunctionCall(
        helper,
        None,
        [segment, indexed_offset],
        codegen=codegen,
        tags=build_tags(operand, helper),
    )
