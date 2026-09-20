"""Publish exact Boolean projections of an already-proven call return.

Layer: Structuring.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Do not perform alias-state ownership, widening,
type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting
work here.
Responsibility: retain one bound call occurrence while canonicalizing its
Boolean control wrapper. The caller must first prove the exact callsite,
return register and ConditionIR relationship. This does not discover calls,
recover arguments or infer ownership from a callee name.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CBinaryOp,
    CConstant,
    CExpression,
    CFunctionCall,
    CUnaryOp,
)
from angr.sim_type import SimTypeShort

from ..ir.condition_ir import ConditionIR
from ..structured_tags import copy_structured_tags_8616
from .condition_replay import bind_condition_replay_identity_8616

_MAX_WRAPPER_DEPTH: int = 16
_OWNED_TAG: str = "inertia_structuring_condition_cfg_materialized_8616"


def _constant_8616(expression: object) -> int | None:
    """Read an exact integer constant without evaluating other expressions."""
    return expression.value if isinstance(expression, CConstant) and isinstance(expression.value, int) else None


def _negate_comparison_8616(
    predicate: tuple[str, CConstant] | None,
) -> tuple[str, CConstant] | None:
    """Invert a proven equality test without changing its operands."""
    if predicate is None:
        return None
    operator, constant = predicate
    return ("CmpEQ" if operator == "CmpNE" else "CmpNE"), constant


def _direct_call_comparison_8616(
    expression: CBinaryOp, call: CFunctionCall,
) -> tuple[str, CConstant] | None:
    """Recognize one existing call compared with one integer constant."""
    if expression.op not in {"CmpEQ", "CmpNE"}:
        return None
    for operand, other in ((expression.lhs, expression.rhs), (expression.rhs, expression.lhs)):
        if operand is call and isinstance(other, CConstant) and isinstance(other.value, int):
            return expression.op, other
    return None


def _call_predicate_8616(
    expression: CExpression, call: CFunctionCall, depth: int = 0,
) -> tuple[str, CConstant] | None:
    """Project Boolean wrappers onto one exact call comparison, or refuse."""
    if depth >= _MAX_WRAPPER_DEPTH:
        return None
    if expression is call:
        return "CmpNE", CConstant(0, SimTypeShort(False), codegen=call.codegen)
    if isinstance(expression, CUnaryOp) and expression.op == "Not":
        return _negate_comparison_8616(_call_predicate_8616(expression.operand, call, depth + 1))
    if isinstance(expression, CITE):
        outcomes = (_constant_8616(expression.iftrue), _constant_8616(expression.iffalse))
        if outcomes not in {(0, 1), (1, 0)}:
            return None
        inner = _call_predicate_8616(expression.cond, call, depth + 1)
        return inner if outcomes == (1, 0) else _negate_comparison_8616(inner)
    if isinstance(expression, CBinaryOp):
        return _direct_call_comparison_8616(expression, call)
    return None


def materialize_bound_call_condition_8616(
    expression: CExpression,
    call: CFunctionCall,
    condition: ConditionIR,
    codegen: object,
) -> CExpression:
    """Publish a proven call comparison while retaining its constant and arguments."""
    predicate = _call_predicate_8616(expression, call)
    if predicate is None:
        return expression
    tags = copy_structured_tags_8616(expression.tags) or {}
    operator, constant = predicate
    if isinstance(expression, CBinaryOp) and expression.op == operator:
        bind_condition_replay_identity_8616(expression, condition)
        expression.tags[_OWNED_TAG] = True
        return expression
    replacement = CBinaryOp(
        operator, call, constant,
        codegen=codegen, tags=tags,
    )
    bind_condition_replay_identity_8616(replacement, condition)
    replacement.tags[_OWNED_TAG] = True
    return replacement
