"""Publish exact Boolean projections of an already-proven call return.

Layer: Structuring.
Responsibility: retain one bound call occurrence while canonicalizing its
Boolean control wrapper. The caller must first prove the exact callsite,
return register and ConditionIR relationship. This does not discover calls,
recover arguments or infer ownership from a callee name.
"""

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


def _call_truth_8616(expression: CExpression, call: CFunctionCall, depth: int = 0) -> bool | None:
    """Return whether guard truth equals call nonzero, or refuse unknown form."""
    if depth >= _MAX_WRAPPER_DEPTH:
        return None
    if expression is call:
        return True
    if isinstance(expression, CUnaryOp) and expression.op == "Not":
        inner = _call_truth_8616(expression.operand, call, depth + 1)
        return None if inner is None else not inner
    if isinstance(expression, CITE):
        outcomes = (_constant_8616(expression.iftrue), _constant_8616(expression.iffalse))
        if outcomes not in {(0, 1), (1, 0)}:
            return None
        inner = _call_truth_8616(expression.cond, call, depth + 1)
        return None if inner is None else inner == (outcomes == (1, 0))
    if isinstance(expression, CBinaryOp) and expression.op in {"CmpEQ", "CmpNE"}:
        compares_call_to_zero = (expression.lhs is call and _constant_8616(expression.rhs) == 0) or (
            expression.rhs is call and _constant_8616(expression.lhs) == 0
        )
        if compares_call_to_zero:
            return bool(expression.op == "CmpNE")
    return None


def materialize_bound_call_condition_8616(
    expression: CExpression,
    call: CFunctionCall,
    condition: ConditionIR,
    codegen: object,
) -> CExpression:
    """Publish a proven call's exact zero-test while retaining its arguments."""
    truth = _call_truth_8616(expression, call)
    if truth is None:
        return expression
    tags = copy_structured_tags_8616(expression.tags) or {}
    operator = "CmpNE" if truth else "CmpEQ"
    if isinstance(expression, CBinaryOp) and expression.op == operator:
        bind_condition_replay_identity_8616(expression, condition)
        expression.tags[_OWNED_TAG] = True
        return expression
    replacement = CBinaryOp(
        operator, call, CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen, tags=tags,
    )
    bind_condition_replay_identity_8616(replacement, condition)
    replacement.tags[_OWNED_TAG] = True
    return replacement
