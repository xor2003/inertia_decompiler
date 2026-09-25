"""Deterministic semantic tokens for already-lowered call arguments.

Layer: Types/Lowering.
Responsibility: compare materialized C argument expressions without using
third-party object identity or rendered C text.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Unsupported expression shapes return ``None`` so callers refuse cache reuse.
"""

from __future__ import annotations

from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import (
    SimMemoryVariable,
    SimRegisterVariable,
    SimStackVariable,
)

from ..semantics.expression_analysis import describe_virtual_value_identity_8616

type CallArgumentSemanticToken8616 = tuple[object, ...]


class _ExternalCallee8616(Protocol):
    """Minimal third-party angr callee surface consumed by tokenization."""

    addr: int
    name: str


def _call_target_token_8616(call: structured_c.CFunctionCall) -> str | int | None:
    """Return a stable target identity across regenerated third-party call nodes."""
    target = call.callee_target
    if isinstance(target, (str, int)):
        return target
    callee = call.callee_func
    if callee is None:
        return None
    boundary = cast(_ExternalCallee8616, callee)
    try:
        addr = boundary.addr
    except AttributeError:
        addr = None
    if isinstance(addr, int):
        return addr
    try:
        name = boundary.name
    except AttributeError:
        return None
    return name if isinstance(name, str) and name else None


def _variable_token_8616(
    expression: structured_c.CVariable,
) -> CallArgumentSemanticToken8616 | None:
    """Return the storage-identity token for one proven variable reference."""
    variable = expression.variable
    if isinstance(variable, SimStackVariable):
        if not isinstance(variable.offset, int) or not isinstance(variable.size, int):
            return None
        return ("stack", variable.offset, variable.size, variable.base, variable.region)
    if isinstance(variable, SimRegisterVariable):
        if not isinstance(variable.reg, int) or not isinstance(variable.size, int):
            return None
        return ("register", variable.reg, variable.size)
    if isinstance(variable, SimMemoryVariable):
        if not isinstance(variable.addr, int) or not isinstance(variable.size, int):
            return None
        return ("memory", variable.addr, variable.size)
    return None


def _indexed_variable_token_8616(
    expression: structured_c.CIndexedVariable,
    seen: frozenset[int],
    depth: int,
) -> CallArgumentSemanticToken8616 | None:
    """Return the token for a proven indexed variable expression."""
    variable = call_argument_semantic_token_8616(
        expression.variable,
        _seen=seen,
        _depth=depth + 1,
    )
    index = call_argument_semantic_token_8616(
        expression.index,
        _seen=seen,
        _depth=depth + 1,
    )
    if variable is None or index is None:
        return None
    return ("index", variable, index)


def _unary_op_token_8616(
    expression: structured_c.CUnaryOp,
    seen: frozenset[int],
    depth: int,
) -> CallArgumentSemanticToken8616 | None:
    """Return the token for a proven unary operation."""
    operand = call_argument_semantic_token_8616(
        expression.operand,
        _seen=seen,
        _depth=depth + 1,
    )
    return ("unary", expression.op, operand) if operand is not None else None


def _binary_op_token_8616(
    expression: structured_c.CBinaryOp,
    seen: frozenset[int],
    depth: int,
) -> CallArgumentSemanticToken8616 | None:
    """Return the token for a proven binary operation."""
    lhs = call_argument_semantic_token_8616(
        expression.lhs,
        _seen=seen,
        _depth=depth + 1,
    )
    rhs = call_argument_semantic_token_8616(
        expression.rhs,
        _seen=seen,
        _depth=depth + 1,
    )
    if lhs is None or rhs is None:
        return None
    return ("binary", expression.op, lhs, rhs)


def _function_call_token_8616(
    expression: structured_c.CFunctionCall,
    seen: frozenset[int],
    depth: int,
) -> CallArgumentSemanticToken8616 | None:
    """Return the token for a proven call with stable callee identity."""
    target = _call_target_token_8616(expression)
    if target is None:
        return None
    arguments = tuple(
        call_argument_semantic_token_8616(argument, _seen=seen, _depth=depth + 1)
        for argument in expression.args or ()
    )
    if any(argument is None for argument in arguments):
        return None
    return ("call", target, arguments)


def _node_token_8616(
    expression: object,
    seen: frozenset[int],
    depth: int,
) -> CallArgumentSemanticToken8616 | None:
    """Dispatch one AST node kind to its typed token arm."""
    if isinstance(expression, structured_c.CConstant):
        value = expression.value
        return ("const", value) if isinstance(value, (str, int, bool)) else None
    if isinstance(expression, structured_c.CVariable):
        return _variable_token_8616(expression)
    if isinstance(expression, structured_c.CIndexedVariable):
        return _indexed_variable_token_8616(expression, seen, depth)
    if isinstance(expression, structured_c.CUnaryOp):
        return _unary_op_token_8616(expression, seen, depth)
    if isinstance(expression, structured_c.CBinaryOp):
        return _binary_op_token_8616(expression, seen, depth)
    if isinstance(expression, structured_c.CFunctionCall):
        return _function_call_token_8616(expression, seen, depth)
    return None


def call_argument_semantic_token_8616(
    expression: object,
    *,
    _seen: frozenset[int] = frozenset(),
    _depth: int = 0,
) -> CallArgumentSemanticToken8616 | None:
    """Return a deterministic token for one proven materialized argument.

    The token describes value and storage identity only. A cycle, excessive
    depth, or unsupported third-party AST node refuses comparison.
    """
    if _depth > 128:
        return None
    while isinstance(expression, structured_c.CTypeCast):
        expression = expression.expr

    marker = id(expression)
    if marker in _seen:
        return None
    seen = _seen | {marker}

    virtual_identity = describe_virtual_value_identity_8616(expression)
    if virtual_identity is not None:
        return ("virtual", virtual_identity.kind.value, virtual_identity.value)

    return _node_token_8616(expression, seen, _depth)


__all__ = [
    "CallArgumentSemanticToken8616",
    "call_argument_semantic_token_8616",
]
