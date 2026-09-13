"""Prove that typed stack words belong to one widened stack object.

Layer: Types/Lowering.
Responsibility: connect adjacent ``IRValue`` stack slices to the active C stack
object only when alias adjacency or an existing four-byte stack owner proves
that they are one logical value.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

This module does not infer widths from names, rendered C, or compiler-specific
instruction shapes.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable

from ..ir.core import IRValue, MemSpace
from .real_mode_linear import proven_wide_stack_pair_low_offset_8616
from .semantic_cast import CSemanticCast8616
from .stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616

_WORD_BYTES = 2
_DWORD_BYTES = 4
_WORD_BITS = 16
_WORD_MASK = 0xFFFF


def materialize_proven_wide_stack_pair_variable_8616(
    codegen: object,
    high_expression: object,
    low_expression: object,
    candidate_expression: object,
) -> CVariable | None:
    """Materialize a four-byte stack variable only from a widening proof."""
    low_offset = proven_wide_stack_pair_low_offset_8616(
        high_expression,
        low_expression,
    )
    if low_offset is None or not isinstance(candidate_expression, CVariable):
        return None
    candidate_variable = candidate_expression.variable
    if (
        not isinstance(candidate_variable, SimStackVariable)
        or candidate_variable.offset != low_offset
    ):
        return None
    if candidate_variable.size == _DWORD_BYTES:
        return candidate_expression
    if candidate_variable.size != _WORD_BYTES:
        return None
    return CVariable(
        SimStackVariable(
            low_offset,
            _DWORD_BYTES,
            base=candidate_variable.base,
            base_addr=candidate_variable.base_addr,
            ident=candidate_variable.ident,
            name=candidate_variable.name,
            region=candidate_variable.region,
            category=candidate_variable.category,
        ),
        codegen=codegen,
        tags=candidate_expression.tags,
    )


def _word_projection_source_8616(expression: object, shift: int) -> CVariable | None:
    """Recover one masked word projection of a proven wide stack C variable."""
    if not isinstance(expression, structured_c.CBinaryOp) or expression.op != "And":
        return None
    mask = expression.rhs
    if not isinstance(mask, structured_c.CConstant) or mask.value != _WORD_MASK:
        return None
    source = expression.lhs
    if shift:
        if not isinstance(source, structured_c.CBinaryOp) or source.op != "Shr":
            return None
        shift_node = source.rhs
        if not isinstance(shift_node, structured_c.CConstant) or shift_node.value != shift:
            return None
        source = source.lhs
    return source if isinstance(source, CVariable) else None


def _proven_projected_wide_pair_8616(
    high_expression: object,
    low_expression: object,
    low_offset: int,
) -> bool:
    """Join one four-byte owner to IR using its authoritative BP projection."""
    high_source = _word_projection_source_8616(high_expression, _WORD_BITS)
    low_source = _word_projection_source_8616(low_expression, 0)
    if high_source is None or low_source is None:
        return False
    high_variable = high_source.variable
    low_variable = low_source.variable
    if not isinstance(high_variable, SimStackVariable) or not isinstance(low_variable, SimStackVariable):
        return False
    if high_variable != low_variable or high_variable.size != _DWORD_BYTES or high_variable.base != "bp":
        return False
    # Rendered entry-SP offsets are not the machine-BP coordinates used by IR.
    return (
        machine_bp_offset_for_stack_variable_8616(high_source.codegen, high_variable) == low_offset
        and machine_bp_offset_for_stack_variable_8616(low_source.codegen, low_variable) == low_offset
    )


def _proven_low_owner_with_high_slice_8616(
    high_expression: object,
    low_expression: object,
) -> bool:
    """Accept a low-word projection whose four-byte owner covers the high slice."""
    low_source = _word_projection_source_8616(low_expression, 0)
    if (
        low_source is None
        and isinstance(low_expression, CSemanticCast8616)
        and isinstance(low_expression.dst_type, SimTypeShort)
        and isinstance(low_expression.expr, CVariable)
    ):
        low_source = low_expression.expr
    if low_source is None or not isinstance(high_expression, CVariable):
        return False
    high_variable = high_expression.variable
    low_variable = low_source.variable
    return (
        isinstance(high_variable, SimStackVariable)
        and isinstance(low_variable, SimStackVariable)
        and high_variable.size == _WORD_BYTES
        and low_variable.size == _DWORD_BYTES
        and high_variable.offset == low_variable.offset + _WORD_BYTES
        and high_variable.base == low_variable.base
        and high_variable.base_addr == low_variable.base_addr
        and high_variable.region == low_variable.region
    )


def proven_wide_stack_ir_pair_8616(
    high_value: IRValue,
    low_value: IRValue,
    high_expression: object,
    low_expression: object,
) -> bool:
    """Return whether typed IR slices and active stack objects prove a pair."""
    are_bp_words = all(
        value.space is MemSpace.SS and value.name == "bp" and value.size == _WORD_BYTES
        for value in (high_value, low_value)
    )
    if not are_bp_words or high_value.offset != low_value.offset + _WORD_BYTES:
        return False
    if proven_wide_stack_pair_low_offset_8616(high_expression, low_expression) == low_value.offset:
        return True
    if _proven_projected_wide_pair_8616(
        high_expression,
        low_expression,
        low_value.offset,
    ):
        return True
    if _proven_low_owner_with_high_slice_8616(high_expression, low_expression):
        return True
    if not isinstance(high_expression, CVariable) or not isinstance(low_expression, CVariable):
        return False
    high_variable = high_expression.variable
    low_variable = low_expression.variable
    return (
        isinstance(high_variable, SimStackVariable)
        and isinstance(low_variable, SimStackVariable)
        and high_variable.offset == high_value.offset
        and low_variable.offset == low_value.offset
        and isinstance(low_variable.size, int)
        and low_variable.size >= _DWORD_BYTES
    )
