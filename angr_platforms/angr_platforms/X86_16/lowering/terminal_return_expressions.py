"""Resolve proven linear virtual carriers for terminal register returns.

Layer: Types/Lowering.
Responsibility: consume ordered structured definitions for generated AIL/C-AST
carriers before a proven terminal register value is materialized as C.
This module never infers values from names, rendered text, source sidecars, or
postprocess output. Unknown identity, cycles, and observable barriers refuse.
Consumes alias, widening, and typed facts from structured definitions.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import logging
import os
from typing import cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimStackVariable, SimTemporaryVariable

from ..c_ast_utils import _clone_c_ast_tree_8616, _iter_c_nodes_deep_8616, _replace_c_children_8616
from ..semantics.expression_analysis import (
    VirtualValueIdentity8616,
    describe_virtual_value_identity_8616,
)
from .physical_registers import physical_register_offset_8616, physical_register_view_8616
from .runtime_memory_helpers import memory_pointer_helper_8616, segmented_memory_read_helper_8616

__all__ = [
    "contains_effectful_call_8616",
    "resolve_linear_virtual_return_expression_8616",
    "return_expression_contains_dereference_8616",
    "return_expression_has_wide_word_composition_8616",
    "return_expression_requires_materialization_8616",
    "uncollapse_safe_scalar_expression_8616",
]

_LOGGER = logging.getLogger(__name__)


def _call_is_effectful_8616(call: structured_c.CFunctionCall) -> bool:
    """Refuse unclassified calls while accepting generated memory reads."""
    return memory_pointer_helper_8616(call) is None and segmented_memory_read_helper_8616(call) is None


def contains_effectful_call_8616(node: object) -> bool:
    """Return whether one structured subtree contains an effectful call."""
    nodes = (node, *_iter_c_nodes_deep_8616(node))
    return any(
        isinstance(candidate, structured_c.CFunctionCall) and _call_is_effectful_8616(candidate)
        for candidate in nodes
    )


def _first_unsafe_scalar_node_8616(
    expression: object,
    seen: frozenset[int] = frozenset(),
) -> object | None:
    """Return the first unsupported node on the current recursion path."""
    marker = id(expression)
    if marker in seen:
        return expression
    child_path = seen | {marker}
    if isinstance(expression, structured_c.CConstant):
        return None
    if isinstance(expression, structured_c.CVariable):
        return _unsafe_variable_8616(expression)
    if isinstance(expression, structured_c.CBinaryOp):
        unsafe_lhs = _first_unsafe_scalar_node_8616(expression.lhs, child_path)
        return unsafe_lhs or _first_unsafe_scalar_node_8616(expression.rhs, child_path)
    if isinstance(expression, structured_c.CTypeCast):
        return _first_unsafe_scalar_node_8616(expression.expr, child_path)
    if isinstance(expression, structured_c.CUnaryOp):
        if expression.op not in {"BitwiseNeg", "LogicalNot", "Neg"}:
            return cast(object, expression)
        return _first_unsafe_scalar_node_8616(expression.operand, child_path)
    if isinstance(expression, structured_c.CFunctionCall):
        return _unsafe_call_node_8616(expression, child_path)
    return expression


def _unsafe_variable_8616(expression: structured_c.CVariable) -> object | None:
    """Reject unresolved temporary or physical-register carriers."""
    if isinstance(expression.variable, SimTemporaryVariable) or physical_register_view_8616(expression) is not None:
        return cast(object, expression)
    return None


def _unsafe_call_node_8616(
    expression: structured_c.CFunctionCall,
    child_path: frozenset[int],
) -> object | None:
    """Reject effectful calls; recurse into pure call arguments."""
    if _call_is_effectful_8616(expression):
        return cast(object, expression)
    for argument in tuple(expression.args or ()):
        unsafe_argument = _first_unsafe_scalar_node_8616(argument, child_path)
        if unsafe_argument is not None:
            return unsafe_argument
    return None


def _safe_scalar_expression_8616(expression: object) -> bool:
    """Accept a resolved, side-effect-free scalar expression."""
    return _first_unsafe_scalar_node_8616(expression) is None


def uncollapse_safe_scalar_expression_8616(expression: object) -> bool:
    """Expose an already-proven scalar tree hidden by angr's depth cutoff."""
    if not _safe_scalar_expression_8616(expression):
        return False
    changed = False
    for node in (expression, *_iter_c_nodes_deep_8616(expression)):
        if isinstance(node, structured_c.CExpression) and node.collapsed:
            node.collapsed = False
            changed = True
    return changed


def _diagnostic_expression_shape_8616(expression: object) -> object:
    """Describe typed AST structure for opt-in lowering diagnostics."""
    identity = describe_virtual_value_identity_8616(expression)
    if isinstance(expression, structured_c.CConstant):
        return (type(expression).__name__, expression.value)
    if isinstance(expression, structured_c.CVariable):
        register_view = physical_register_view_8616(expression)
        return (
            type(expression).__name__,
            None if identity is None else (identity.kind.value, identity.value),
            type(expression.variable).__name__,
            None if register_view is None else (register_view.reg_offset, register_view.width),
        )
    if isinstance(expression, structured_c.CDirtyExpression):
        return (
            type(expression).__name__,
            None if identity is None else (identity.kind.value, identity.value),
            physical_register_offset_8616(expression),
        )
    if isinstance(expression, structured_c.CBinaryOp):
        return (
            type(expression).__name__,
            expression.op,
            _diagnostic_expression_shape_8616(expression.lhs),
            _diagnostic_expression_shape_8616(expression.rhs),
        )
    if isinstance(expression, structured_c.CTypeCast):
        return (type(expression).__name__, _diagnostic_expression_shape_8616(expression.expr))
    if isinstance(expression, structured_c.CUnaryOp):
        return (
            type(expression).__name__,
            expression.op,
            _diagnostic_expression_shape_8616(expression.operand),
        )
    if isinstance(expression, structured_c.CFunctionCall):
        helper = segmented_memory_read_helper_8616(expression)
        return (
            type(expression).__name__,
            None if helper is None else helper.helper_name,
            tuple(_diagnostic_expression_shape_8616(argument) for argument in tuple(expression.args or ())),
        )
    return type(expression).__name__


def _resolve_virtual_expression_8616(
    expression: object,
    definitions: dict[VirtualValueIdentity8616, object],
) -> object:
    """Clone once and substitute exact, already-resolved prior definitions."""
    identity = describe_virtual_value_identity_8616(expression)
    source = definitions[identity] if identity is not None and identity in definitions else expression
    clone = _clone_c_ast_tree_8616(source)

    def transform(child: object) -> object:
        """Substitute one generated child from the resolved definition map."""
        child_identity = describe_virtual_value_identity_8616(child)
        if child_identity is None or child_identity not in definitions:
            return child
        return _clone_c_ast_tree_8616(definitions[child_identity])

    _replace_c_children_8616(clone, transform)
    return clone


def _assignment_writes_observable_storage_8616(lhs: object) -> bool:
    """Conservatively classify writes that invalidate prior memory reads."""
    if describe_virtual_value_identity_8616(lhs) is not None:
        return False
    if isinstance(lhs, structured_c.CVariable):
        variable = lhs.unified_variable if lhs.unified_variable is not None else lhs.variable
        return isinstance(variable, (SimMemoryVariable, SimStackVariable))
    return True


def _linear_virtual_definitions_8616(
    statements: tuple[object, ...],
) -> dict[VirtualValueIdentity8616, object]:
    """Collect reusable generated definitions without crossing barriers."""
    definitions: dict[VirtualValueIdentity8616, object] = {}
    for statement in statements:
        if not isinstance(statement, structured_c.CAssignment):
            if contains_effectful_call_8616(statement):
                definitions.clear()
            continue
        if contains_effectful_call_8616(statement.rhs):
            definitions.clear()
            continue
        identity = describe_virtual_value_identity_8616(statement.lhs)
        resolved_rhs = _resolve_virtual_expression_8616(statement.rhs, definitions)
        if identity is None or _assignment_writes_observable_storage_8616(statement.lhs):
            definitions.clear()
            continue
        if _safe_scalar_expression_8616(resolved_rhs):
            definitions[identity] = resolved_rhs
        else:
            if os.environ.get("INERTIA_DEBUG_TERMINAL_RETURN_VALUES") == "1":
                _LOGGER.warning(
                    "terminal virtual definition refused: identity=%s rhs=%s unsafe=%s",
                    (identity.kind.value, identity.value),
                    _diagnostic_expression_shape_8616(resolved_rhs),
                    _diagnostic_expression_shape_8616(_first_unsafe_scalar_node_8616(resolved_rhs)),
                )
            definitions.pop(identity, None)
    return definitions


def _contains_unresolved_virtual_value_8616(expression: object) -> bool:
    """Return whether a resolved expression still exposes a generated carrier."""
    nodes = (expression, *_iter_c_nodes_deep_8616(expression))
    return any(
        isinstance(node, structured_c.CDirtyExpression)
        or (isinstance(node, structured_c.CVariable) and isinstance(node.variable, SimTemporaryVariable))
        for node in nodes
    )


def _uncollapse_materialized_expression_8616(expression: object) -> object:
    """Clear inherited display collapse state on a newly materialized expression."""
    for node in (expression, *_iter_c_nodes_deep_8616(expression)):
        if isinstance(node, structured_c.CExpression):
            node.collapsed = False
    return expression


def return_expression_has_wide_word_composition_8616(expression: object | None) -> bool:
    """Return whether a C expression structurally preserves a 32-bit word pair."""
    if not isinstance(expression, structured_c.CBinaryOp) or expression.op != "Or":
        return False

    def _is_high_word(node: object) -> bool:
        if not isinstance(node, structured_c.CBinaryOp) or node.op != "Shl":
            return False
        shift = node.rhs
        return isinstance(shift, structured_c.CConstant) and int(shift.value or 0) == 16

    return _is_high_word(expression.lhs) or _is_high_word(expression.rhs)


def return_expression_contains_dereference_8616(expression: object | None) -> bool:
    """Return whether one generated expression reads through a pointer."""
    return any(
        isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference"
        for node in _iter_c_nodes_deep_8616(expression)
    )


def return_expression_requires_materialization_8616(
    statements_before_return: tuple[object, ...],
    expression: object | None,
) -> bool:
    """Return whether a generated return expression must be made renderable."""
    if expression is None:
        return True
    if contains_effectful_call_8616(expression):
        return False
    del statements_before_return
    nodes = (expression, *_iter_c_nodes_deep_8616(expression))
    return any(
        isinstance(node, structured_c.CExpression) and node.collapsed
        for node in nodes
    ) or _contains_unresolved_virtual_value_8616(expression)


def resolve_linear_virtual_return_expression_8616(
    statements_before_definition: tuple[object, ...],
    expression: object,
) -> object | None:
    """Resolve one candidate terminal value or refuse incomplete evidence."""
    definitions = _linear_virtual_definitions_8616(statements_before_definition)
    resolved = _resolve_virtual_expression_8616(expression, definitions)
    unresolved = tuple(
        node
        for node in (resolved, *_iter_c_nodes_deep_8616(resolved))
        if isinstance(node, structured_c.CDirtyExpression)
        or (isinstance(node, structured_c.CVariable) and isinstance(node.variable, SimTemporaryVariable))
    )
    unsafe_node = _first_unsafe_scalar_node_8616(resolved)
    if os.environ.get("INERTIA_DEBUG_TERMINAL_RETURN_VALUES") == "1":
        _LOGGER.warning(
            "terminal virtual return resolution: definitions=%s unresolved=%s unsafe=%s nodes=%s",
            tuple(
                (identity.kind.value, identity.value, type(rhs).__name__)
                for identity, rhs in definitions.items()
            ),
            tuple(
                (
                    type(node).__name__,
                    identity.kind.value if (identity := describe_virtual_value_identity_8616(node)) is not None else None,
                    identity.value if identity is not None else None,
                )
                for node in unresolved
            ),
            type(unsafe_node).__name__ if unsafe_node is not None else None,
            tuple(type(node).__name__ for node in (resolved, *_iter_c_nodes_deep_8616(resolved))),
        )
    if unresolved or unsafe_node is not None:
        return None
    return _uncollapse_materialized_expression_8616(resolved)
