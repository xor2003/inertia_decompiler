"""Capture proven wide predicate call results without moving call execution.

Layer: Types/Lowering.
Responsibility: consume typed call-source and existing wide-storage evidence,
then capture an accepted predicate's call at its original statement position.
Consumes alias, widening, and typed facts. CFG polarity belongs to Structuring.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import replace
from typing import cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CExpression,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeLong
from angr.sim_variable import SimRegisterVariable, SimStackVariable, SimTemporaryVariable

from ..c_ast_utils import _iter_c_node_occurrences_8616, _iter_c_nodes_deep_8616
from ..ir.condition_ir import ConditionIR, ConditionOp, condition_sort_key_8616
from ..ir.core import IRValue
from ..pipeline.errors import PipelineHardError
from .call_output_stack_objects import _CallOutputCodegen8616, _wide_condition_call_8616
from .semantic_cast import CSemanticCast8616
from .stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616
from .wide_call_condition_binding import WIDE_CALL_BINDING_TAG_8616, WideCallBinding8616, wide_call_identity_8616

_PENDING_CAPTURE: str = "inertia_wide_condition_pending_call_capture_8616"
_CAPTURED_CALL: str = "inertia_wide_condition_captured_call_8616"
_WIDE_BYTES: int = 4
_CAPTURE_CALL_OCCURRENCES: int = 2
_OPERATORS: dict[ConditionOp, str] = {
    "eq": "CmpEQ", "ne": "CmpNE", "slt": "CmpLT", "sle": "CmpLE",
    "sgt": "CmpGT", "sge": "CmpGE",
}


def build_proven_wide_call_condition_8616(
    codegen: object,
    conditions: tuple[ConditionIR, ...],
    low_stack: IRValue,
    operator: ConditionOp,
) -> CExpression | None:
    """Build a deferred predicate over a proven call and one existing wide local.

    The caller must prove the entire CFG decision and commit captures after
    inserting accepted predicates. Speculative predicates do not move calls or
    create declarations. No scalar return-register placeholder is introduced.
    """
    c_operator = _OPERATORS.get(operator)
    if c_operator is None:
        return None
    boundary = cast(_CallOutputCodegen8616, codegen)
    candidates = {
        id(cvar): cvar
        for variable, cvar in boundary.cfunc.variables_in_use.items()
        if isinstance(variable, SimStackVariable)
        and variable.size == _WIDE_BYTES
        and machine_bp_offset_for_stack_variable_8616(codegen, variable) == low_stack.offset
        and isinstance(cvar, CVariable)
    }
    if len(candidates) != 1:
        return None
    selection = _wide_condition_call_8616(boundary, conditions)
    if selection is None:
        return None
    call, summary = selection
    wide = next(iter(candidates.values()))
    signed = SimTypeLong(True).with_arch(boundary.project.arch)
    captures = [
        node.lhs for node in _iter_c_nodes_deep_8616(boundary.cfunc.statements)
        if isinstance(node, CAssignment) and node.rhs is call
        and node.tags.get(_CAPTURED_CALL) == summary.callsite_addr
        and isinstance(node.lhs, CVariable)
    ]
    if len(captures) > 1:
        return None
    expression = CBinaryOp(
        c_operator,
        CSemanticCast8616(None, signed, captures[0] if captures else call, codegen=codegen),
        CSemanticCast8616(None, signed, wide, codegen=codegen),
        codegen=codegen,
    )
    if not captures:
        expression.tags[_PENDING_CAPTURE] = summary.callsite_addr
    callee_identity = wide_call_identity_8616(call)
    if callee_identity is not None and isinstance(low_stack.offset, int):
        variable = captures[0].variable if captures else None
        expression.tags[WIDE_CALL_BINDING_TAG_8616] = WideCallBinding8616(
            tuple(condition_sort_key_8616(condition) for condition in conditions),
            summary.callsite_addr, callee_identity, low_stack.offset,
            variable.tmp_id if isinstance(variable, SimTemporaryVariable) else None,
        )
    return expression


def _standalone_slots(root: object, call: CFunctionCall) -> tuple[tuple[CStatements, int], ...]:
    """Find exact standalone occurrences without moving across any effect."""
    slots: list[tuple[CStatements, int]] = []
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, CStatements):
            for index, statement in enumerate(node.statements):
                register_capture = (
                    isinstance(statement, CAssignment) and statement.rhs is call
                    and isinstance(statement.lhs, CVariable)
                    and isinstance(statement.lhs.variable, SimRegisterVariable)
                )
                if register_capture or statement is call or (
                    isinstance(statement, CExpressionStatement) and statement.expr is call
                ):
                    slots.append((node, index))
    return tuple(slots)


def commit_wide_call_condition_captures_8616(codegen: object) -> int:
    """Capture accepted calls once in place; fail on ambiguous AST ownership."""
    boundary = cast(_CallOutputCodegen8616, codegen)
    root = boundary.cfunc.statements
    committed = 0
    for node in tuple(_iter_c_nodes_deep_8616(root)):
        if not isinstance(node, CBinaryOp) or _PENDING_CAPTURE not in node.tags:
            continue
        callsite = node.tags[_PENDING_CAPTURE]
        if not isinstance(node.lhs, CSemanticCast8616) or not isinstance(node.lhs.expr, CFunctionCall):
            raise PipelineHardError(f"wide-call capture function={boundary.cfunc.addr:#x}: invalid pending predicate")
        call = node.lhs.expr
        slots = _standalone_slots(root, call)
        occurrences = sum(child is call for child in _iter_c_node_occurrences_8616(root))
        if len(slots) != 1 or occurrences != _CAPTURE_CALL_OCCURRENCES:
            raise PipelineHardError(
                f"wide-call capture function={boundary.cfunc.addr:#x} callsite={callsite!r}: "
                f"expected one standalone and one predicate use; slots={len(slots)} occurrences={occurrences}"
            )
        used_ids = {
            variable.tmp_id for variable in boundary.cfunc.variables_in_use
            if isinstance(variable, SimTemporaryVariable)
        }
        used_ids.update(
            child.variable.tmp_id for child in _iter_c_nodes_deep_8616(root)
            if isinstance(child, CVariable) and isinstance(child.variable, SimTemporaryVariable)
        )
        temporary_id = max(used_ids, default=-1) + 1
        temporary = SimTemporaryVariable(temporary_id, _WIDE_BYTES)
        value_type = SimTypeLong(True).with_arch(boundary.project.arch)
        value = CVariable(temporary, variable_type=value_type, codegen=codegen)
        group, index = slots[0]
        original = group.statements[index]
        capture = CAssignment(
            value, call, codegen=codegen,
            tags={"ins_addr": callsite, _CAPTURED_CALL: callsite},
        )
        if isinstance(original, CAssignment):
            # Preserve the register result and its truncation for remaining users.
            original.rhs = value
            group.statements[index] = CStatements([capture, original], codegen=codegen)
        else:
            group.statements[index] = capture
        node.lhs.expr = value
        binding = node.tags.get(WIDE_CALL_BINDING_TAG_8616)
        if isinstance(binding, WideCallBinding8616):
            node.tags[WIDE_CALL_BINDING_TAG_8616] = replace(binding, temporary_id=temporary_id)
        del node.tags[_PENDING_CAPTURE]
        boundary.cfunc.variables_in_use[temporary] = value
        # CFunction.refresh reads declaration types from the variable manager.
        boundary.cfunc.variable_manager.set_variable_type(temporary, value_type)
        committed += 1
    if committed:
        boundary.cfunc.refresh()
    return committed
