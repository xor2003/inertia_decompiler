"""Compare explicit condition casts with equivalent typed memory views.

Layer: Tail validation.
Responsibility: prove equal storage, access width and integer interpretation
when a segmented load becomes a typed field. Never mutate or repair the AST.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeChar, SimTypeInt, SimTypeNum
from angr.sim_variable import SimMemoryVariable, SimStackVariable

from .ir.condition_ir import ConditionIR
from .ir.core import IRValue, MemSpace
from .lowering.semantic_cast import CSemanticCast8616
from .lowering.stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616
from .structuring.condition_materialization import materialize_condition_ir_expression_8616
from .tail_validation_fingerprint import _expr_fingerprint, _global_indexed_field_ds_deref_fingerprint_8616
from .widening.segmented_load_identity import segmented_load_identity_8616

_BITS_PER_BYTE = 8
_SEGMENT_LOAD_ARGUMENT_COUNT = 2
_INTEGER_TYPES = (SimTypeChar, SimTypeInt, SimTypeNum)
_INVERTED_COMPARISONS = {"CmpLT": "CmpGE", "CmpLE": "CmpGT", "CmpGT": "CmpLE", "CmpGE": "CmpLT"}
_LOAD_HELPERS = {1: "SEG_U8", 2: "SEG_U16", 4: "SEG_U32"}


def _memory_storage(expression: c.CExpression, width: int, project: object) -> str | None:
    """Return storage identity only for an exact-width physical memory read."""
    if isinstance(expression, c.CFunctionCall):
        identity = segmented_load_identity_8616(expression)
        valid_load = (
            identity is not None
            and identity.width == width
            and expression.callee_target == _LOAD_HELPERS.get(width)
            and len(expression.args) == _SEGMENT_LOAD_ARGUMENT_COUNT
        )
        return _expr_fingerprint(expression, project) if valid_load else None
    if isinstance(expression, c.CVariable):
        variable = expression.variable
        if isinstance(variable, SimStackVariable) and (
            variable.base != "bp"
            or machine_bp_offset_for_stack_variable_8616(expression.codegen, variable) is None
        ):
            return None
        if isinstance(variable, (SimStackVariable, SimMemoryVariable)) and variable.size == width:
            return _expr_fingerprint(expression, project)
    if isinstance(expression, c.CVariableField):
        type_ = expression.type
        if (
            isinstance(type_, _INTEGER_TYPES)
            and type_.with_arch(expression.codegen.project.arch).size == width * _BITS_PER_BYTE
        ):
            return _global_indexed_field_ds_deref_fingerprint_8616(expression, project, set())
    return None


def _interpreted_storage(
    expression: c.CExpression, width: int, signed: bool, project: object,
) -> str | None:
    """Require the current value view to implement the decoded interpretation."""
    view_type = expression.type
    if not isinstance(view_type, _INTEGER_TYPES):
        return None
    view_type = view_type.with_arch(expression.codegen.project.arch)
    if view_type.size != width * _BITS_PER_BYTE or view_type.signed is not signed:
        return None
    storage = expression.expr if isinstance(expression, CSemanticCast8616) else expression
    return _memory_storage(storage, width, project)


def condition_storage_views_match_8616(
    project: object, codegen: object, condition: ConditionIR, candidate: object, inverted: bool,
) -> bool:
    """Prove a typed memory comparison or its inverse without dropping casts blindly."""
    if not isinstance(candidate, c.CBinaryOp) or not (condition.is_signed or condition.is_unsigned):
        return False
    operands = (condition.lhs, condition.rhs)
    if not all(
        isinstance(operand, IRValue)
        and operand.space in {MemSpace.SS, MemSpace.DS, MemSpace.ES}
        and operand.size * _BITS_PER_BYTE == condition.width_bits
        for operand in operands
    ):
        return False
    expected = materialize_condition_ir_expression_8616(project, codegen, condition)
    if not isinstance(expected, c.CBinaryOp):
        return False
    expected_op = _INVERTED_COMPARISONS.get(expected.op) if inverted else expected.op
    if candidate.op != expected_op:
        return False
    width = condition.width_bits // _BITS_PER_BYTE
    for original, final in ((expected.lhs, candidate.lhs), (expected.rhs, candidate.rhs)):
        original_storage = _interpreted_storage(original, width, condition.is_signed, project)
        final_storage = _interpreted_storage(final, width, condition.is_signed, project)
        if original_storage is None or final_storage != original_storage:
            return False
    return True
