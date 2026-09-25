"""Lower unusable return carriers only when closed caller evidence permits it.

Layer: Types/Lowering.
Responsibility: replace pure unresolved C return-value artifacts with a typed
zero when a complete binary caller census proves the scalar result unobserved.
Consumes alias, widening, and typed facts after structured C materialization.
Do not recover semantics from COD, source, assembly, or rendered C text.
Forbidden: infer a void ABI, discard side-effecting return expressions, or use
symbol names or function-specific addresses.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol, cast

from angr import ailment
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CFakeVariable,
    CIndexedVariable,
    CReturn,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import (
    SimType,
    SimTypeChar,
    SimTypeDouble,
    SimTypeFloat,
    SimTypeInt,
    SimTypeLong,
    SimTypePointer,
    SimTypeShort,
)
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..pipeline.errors import PipelineHardError
from .return_type_evidence import function_result_is_proven_unobserved_8616

__all__ = [
    "UnobservedReturnLoweringStats8616",
    "neutralize_unobserved_unresolved_returns_8616",
    "return_expr_is_unresolved_carrier_8616",
    "return_value_needs_neutralization_8616",
]

_SCALAR_RETURN_TYPES_8616 = (
    SimTypeChar,
    SimTypeShort,
    SimTypeInt,
    SimTypeLong,
    SimTypeFloat,
    SimTypeDouble,
    SimTypePointer,
)

_CarrierIdentity8616 = tuple[str, int | None, int | str | None, int, int]


class _ReturnPrototypeSurface8616(Protocol):
    """Typed view of the angr return type needed by this lowering pass."""

    returnty: SimType


class _ReturnCFunctionSurface8616(Protocol):
    """Typed view of the active angr C function needed by this pass."""

    addr: object
    arg_list: Iterable[object]
    statements: object
    functy: _ReturnPrototypeSurface8616 | None
    prototype: _ReturnPrototypeSurface8616 | None


class _ReturnCodegenSurface8616(Protocol):
    """Typed view of the mutable angr codegen boundary used by this pass."""

    cfunc: _ReturnCFunctionSurface8616
    _inertia_unobserved_return_lowering_stats_8616: UnobservedReturnLoweringStats8616


@dataclass(frozen=True, slots=True)
class UnobservedReturnLoweringStats8616:
    """Closed evidence counts for one unobserved-result lowering run."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


def _pure_return_expr_state_8616(expr: object, *, depth: int = 0) -> tuple[bool, bool]:
    """Return ``(pure, unresolved)`` for one bounded return expression tree."""
    if expr is None:
        return True, True
    if depth > 8:
        return False, False
    leaf = _leaf_expr_state_8616(expr)
    if leaf is not None:
        return leaf
    if isinstance(expr, CTypeCast):
        return _pure_return_expr_state_8616(expr.expr, depth=depth + 1)
    if isinstance(expr, CUnaryOp):
        return _pure_return_expr_state_8616(expr.operand, depth=depth + 1)
    if isinstance(expr, CIndexedVariable):
        return _combined_expr_state_8616((expr.variable, expr.index), depth=depth)
    if isinstance(expr, CBinaryOp):
        return _combined_expr_state_8616((expr.lhs, expr.rhs), depth=depth)
    return False, False


def _leaf_expr_state_8616(expr: object) -> tuple[bool, bool] | None:
    """Return the leaf-carrier state, or None for composite expressions."""
    if isinstance(expr, CConstant):
        return True, False
    if isinstance(expr, CFakeVariable):
        return True, True
    if isinstance(expr, CDirtyExpression):
        return _dirty_expr_state_8616(expr)
    if isinstance(expr, CVariable):
        return _variable_expr_state_8616(expr)
    return None


def _combined_expr_state_8616(
    items: tuple[object, ...],
    *,
    depth: int,
) -> tuple[bool, bool]:
    """Combine child states: pure only when all pure, unresolved when any."""
    states = tuple(
        _pure_return_expr_state_8616(item, depth=depth + 1) for item in items
    )
    return all(pure for pure, _unresolved in states), any(
        unresolved for _pure, unresolved in states
    )


def _dirty_expr_state_8616(expr: CDirtyExpression) -> tuple[bool, bool]:
    """Report an unresolved dirty carrier exactly once."""
    unresolved = isinstance(
        expr.dirty,
        (ailment.Expr.VirtualVariable, ailment.Expr.Register, ailment.Expr.Tmp),
    )
    return unresolved, unresolved


def _variable_expr_state_8616(expr: CVariable) -> tuple[bool, bool]:
    """Report register and stack carriers as pure; name the unresolved forms."""
    variable = expr.variable
    if isinstance(variable, SimRegisterVariable):
        return True, expr.unified_variable is None
    if isinstance(variable, SimStackVariable):
        return True, not isinstance(variable.name, str)
    return False, False


def return_expr_is_unresolved_carrier_8616(expr: object) -> bool:
    """Return whether an expression is pure and contains an unresolved carrier."""
    pure, unresolved = _pure_return_expr_state_8616(expr)
    return pure and unresolved


def return_value_needs_neutralization_8616(retval: object, return_type: object) -> bool:
    """Classify a pure unusable scalar result without inferring a void ABI."""
    if not isinstance(return_type, _SCALAR_RETURN_TYPES_8616):
        return False
    pure, unresolved = _pure_return_expr_state_8616(retval)
    if pure and unresolved:
        return True
    if not pure:
        return False
    try:
        retval_type = cast(Any, retval).type
    except (AttributeError, ValueError):
        return False
    return retval_type is not None and not isinstance(retval_type, _SCALAR_RETURN_TYPES_8616)


def _carrier_identity_8616(expr: object) -> _CarrierIdentity8616 | None:
    """Return exact structured storage identity for one register or stack carrier."""
    if not isinstance(expr, CVariable):
        return None
    candidates = (expr.unified_variable, expr.variable)
    variables = tuple(
        candidate for candidate in candidates if isinstance(candidate, (SimRegisterVariable, SimStackVariable))
    )
    if not variables:
        return None
    variable = next(
        (
            candidate
            for candidate in variables
            if isinstance(candidate.region, int) and isinstance(candidate.ident, (int, str))
        ),
        variables[0],
    )
    region = variable.region if isinstance(variable.region, int) else None
    ident = variable.ident if isinstance(variable.ident, (int, str)) else None
    if isinstance(variable, SimRegisterVariable):
        return "register", region, ident, variable.reg, variable.size
    return "stack", region, ident, variable.offset, variable.size


def _unassigned_return_carrier_8616(
    retval: object,
    assigned_carriers: frozenset[_CarrierIdentity8616],
) -> bool:
    """Return whether a direct pure carrier has no definition anywhere in the AST."""
    identity = _carrier_identity_8616(retval)
    return identity is not None and identity not in assigned_carriers


def neutralize_unobserved_unresolved_returns_8616(project: object, codegen: object) -> bool:
    """Materialize typed zeroes only for proven-unobserved unusable returns.

    Caller liveness may authorize replacing an unresolved or unassigned carrier,
    but it never authorizes deleting a value defined by the callee.
    """
    boundary = cast(_ReturnCodegenSurface8616, codegen)
    try:
        cfunc = boundary.cfunc
        function_addr = cfunc.addr
        root = cfunc.statements
        prototype = cfunc.functy or cfunc.prototype
        return_type = prototype.returnty if prototype is not None else None
    except AttributeError:
        function_addr = None
        root = None
        return_type = None
    return_nodes = tuple(node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CReturn))
    assigned_carriers = frozenset(
        identity
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CAssignment)
        if (identity := _carrier_identity_8616(node.lhs)) is not None
    )
    try:
        argument_carriers = frozenset(
            identity
            for argument in cfunc.arg_list
            if (identity := _carrier_identity_8616(argument)) is not None
        )
    except (AttributeError, TypeError):
        argument_carriers = frozenset()
    defined_carriers = assigned_carriers | argument_carriers
    raw_count = len(return_nodes)
    classified = 0
    materialized = 0
    unobserved = (
        isinstance(function_addr, int)
        and isinstance(return_type, _SCALAR_RETURN_TYPES_8616)
        and function_result_is_proven_unobserved_8616(project, function_addr)
    )
    if os.environ.get("INERTIA_DEBUG_UNOBSERVED_RETURN") == "1":
        logging.getLogger(__name__).warning(
            "unobserved-return lowering function=%r proof=%s returns=%r",
            function_addr,
            unobserved,
            tuple(
                (
                    type(node.retval).__name__,
                    _pure_return_expr_state_8616(node.retval),
                    repr(node.retval),
                )
                for node in return_nodes
            ),
        )
    if unobserved and isinstance(return_type, SimType):
        for return_node in return_nodes:
            if not (
                return_value_needs_neutralization_8616(return_node.retval, return_type)
                or _unassigned_return_carrier_8616(return_node.retval, defined_carriers)
            ):
                continue
            classified += 1
            return_node.retval = CConstant(0, return_type, codegen=cast(Any, codegen))
            materialized += 1
    stats = UnobservedReturnLoweringStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=raw_count,
        classified_fact_count=classified,
        materialized_count=materialized,
        failure_count=classified - materialized,
    )
    boundary._inertia_unobserved_return_lowering_stats_8616 = stats
    if classified > 0 and materialized == 0:
        raise PipelineHardError("classified unobserved return carriers were not materialized")
    return materialized > 0
