"""Materialize one proven terminal AX expression as a structured C return.

Layer: Types/Lowering.
Responsibility: consume complete terminal AX semantics and one linear structured
register definition before cleanup can discard the returned value.
Forbidden: source/COD/name evidence, rendered-text parsing, branch guessing, or
postprocess body repair. Ambiguous control flow or definitions are refused.
Consumes alias, widening, and typed facts from terminal-register semantics.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CReturn,
    CStatement,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeBottom, SimTypeFunction
from angr.sim_variable import SimMemoryVariable, SimStackVariable
from archinfo import Arch

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..semantics.terminal_return_storage import TerminalReturnStorage8616, terminal_return_storage_8616
from .physical_registers import physical_register_view_8616
from .terminal_return_expressions import (
    contains_effectful_call_8616,
    resolve_linear_virtual_return_expression_8616,
    return_expression_has_wide_word_composition_8616,
    return_expression_requires_materialization_8616,
)

__all__ = [
    "TerminalRegisterReturnValueEvidence8616",
    "TerminalRegisterReturnValueRefusal8616",
    "TerminalRegisterReturnValueResult8616",
    "TerminalRegisterReturnValueStatus8616",
    "materialize_terminal_register_return_value_8616",
]

_LOGGER = logging.getLogger(__name__)


class TerminalRegisterReturnValueStatus8616(Enum):
    """Typed outcome of one terminal register return-value decision."""

    NOT_APPLICABLE = "not_applicable"
    REFUSED = "refused"
    MATERIALIZED = "materialized"


class TerminalRegisterReturnValueRefusal8616(Enum):
    """Structured reason why return-value lowering did not materialize."""

    NONE = "none"
    NOT_APPLICABLE = "not_applicable"
    MISSING_FUNCTION = "missing_function"
    MISSING_AX_REGISTER = "missing_ax_register"
    INCOMPLETE_TERMINAL_SHAPE = "incomplete_terminal_shape"
    NONLINEAR_AX_DEFINITION = "nonlinear_ax_definition"
    OUT_OF_ORDER_DEFINITION = "out_of_order_definition"
    UNSAFE_EXPRESSION = "unsafe_expression"
    INTERVENING_CALL = "intervening_call"
    INTERVENING_DEFINITION = "intervening_definition"


@dataclass(frozen=True, slots=True)
class TerminalRegisterReturnValueEvidence8616:
    """Closed evidence accounting for terminal return-value lowering."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class TerminalRegisterReturnValueResult8616:
    """Result of materializing one structured terminal AX value."""

    changed: bool
    status: TerminalRegisterReturnValueStatus8616
    refusal: TerminalRegisterReturnValueRefusal8616
    evidence: TerminalRegisterReturnValueEvidence8616


class _FunctionSurface8616(Protocol):
    """angr function fields consumed by terminal semantics."""

    addr: int
    block_addrs_set: set[int]


class _FunctionManagerSurface8616(Protocol):
    """angr function-manager lookup used at the project boundary."""

    def function(self, *, addr: int, create: bool) -> _FunctionSurface8616 | None:
        """Return one existing function without creating it."""


class _KnowledgeBaseSurface8616(Protocol):
    """angr knowledge-base fields used by terminal return lowering."""

    functions: _FunctionManagerSurface8616


class _ProjectSurface8616(Protocol):
    """Project fields used by terminal return-value lowering."""

    arch: Arch
    kb: _KnowledgeBaseSurface8616


class _CFunctionSurface8616(Protocol):
    """Structured C function fields consumed by this lowering pass."""

    addr: int
    functy: object
    statements: object


class _CodegenSurface8616(Protocol):
    """Codegen fields consumed and updated by terminal return lowering."""

    cfunc: _CFunctionSurface8616
    _inertia_terminal_register_return_value_result_8616: TerminalRegisterReturnValueResult8616


def _result_8616(
    codegen: _CodegenSurface8616,
    status: TerminalRegisterReturnValueStatus8616,
    evidence: TerminalRegisterReturnValueEvidence8616,
    refusal: TerminalRegisterReturnValueRefusal8616 = TerminalRegisterReturnValueRefusal8616.NONE,
) -> TerminalRegisterReturnValueResult8616:
    """Store and return one typed lowering result."""
    result = TerminalRegisterReturnValueResult8616(
        status is TerminalRegisterReturnValueStatus8616.MATERIALIZED,
        status,
        refusal,
        evidence,
    )
    codegen._inertia_terminal_register_return_value_result_8616 = result
    if os.environ.get("INERTIA_DEBUG_TERMINAL_RETURN_VALUES") == "1":
        _LOGGER.warning(
            "terminal AX value result: status=%s refusal=%s evidence=%s",
            status.value,
            refusal.value,
            evidence,
        )
    return result


def _variable_storage_key_8616(node: CVariable) -> tuple[object, ...]:
    """Return one stable storage key at the third-party C-variable boundary."""
    variable = node.unified_variable if node.unified_variable is not None else node.variable
    if isinstance(variable, SimStackVariable):
        return ("stack", variable.base, variable.offset, variable.size, variable.region)
    if isinstance(variable, SimMemoryVariable):
        return ("memory", variable.addr, variable.size, variable.region)
    return ("identity", id(variable))


def _expression_variable_keys_8616(expression: object) -> frozenset[tuple[object, ...]]:
    """Collect exact C-variable storage read by one scalar expression."""
    nodes = (expression, *_iter_c_nodes_deep_8616(expression))
    return frozenset(
        _variable_storage_key_8616(node) for node in nodes if isinstance(node, CVariable)
    )


def _defines_any_variable_8616(
    node: object,
    variable_keys: frozenset[tuple[object, ...]],
) -> bool:
    """Return whether one subtree assigns any exact return-expression variable."""
    nodes = (node, *_iter_c_nodes_deep_8616(node))
    return any(
        isinstance(candidate, CAssignment)
        and isinstance(candidate.lhs, CVariable)
        and _variable_storage_key_8616(candidate.lhs) in variable_keys
        for candidate in nodes
    )


def _terminal_linear_suffix_8616(root: CStatements) -> tuple[object, ...]:
    """Return the linear statements after the final structured control-flow node.

    Earlier loops or branches cannot affect placement once a later unconditional
    AX definition overwrites the carrier. Control flow after that definition
    clears the candidate suffix and therefore still forces refusal.
    """
    suffix: list[object] = []

    def _append(statement: object) -> None:
        if isinstance(statement, CStatements):
            for nested in tuple(statement.statements or ()):
                _append(nested)
            return
        if isinstance(statement, (CAssignment, CExpressionStatement, CFunctionCall, CReturn)):
            suffix.append(statement)
            return
        suffix.clear()

    for statement in tuple(root.statements or ()):
        _append(statement)
    return tuple(suffix)


def _return_value_context_8616(
    project_surface: _ProjectSurface8616,
    codegen_surface: _CodegenSurface8616,
    function_addr: int,
) -> tuple[_FunctionSurface8616, int, int] | TerminalRegisterReturnValueResult8616:
    """Resolve the proven function and AX register geometry or refuse."""
    functions = project_surface.kb.functions
    function = functions.function(addr=function_addr, create=False)
    if function is None:
        return _result_8616(
            codegen_surface,
            TerminalRegisterReturnValueStatus8616.REFUSED,
            TerminalRegisterReturnValueEvidence8616(failure_count=1),
            TerminalRegisterReturnValueRefusal8616.MISSING_FUNCTION,
        )
    ax_register = project_surface.arch.registers.get("ax")
    if not isinstance(ax_register, tuple) or len(ax_register) < 2:
        return _result_8616(
            codegen_surface,
            TerminalRegisterReturnValueStatus8616.REFUSED,
            TerminalRegisterReturnValueEvidence8616(failure_count=1),
            TerminalRegisterReturnValueRefusal8616.MISSING_AX_REGISTER,
        )
    ax_offset, ax_width = ax_register[:2]
    if not isinstance(ax_offset, int) or not isinstance(ax_width, int):
        return _result_8616(
            codegen_surface,
            TerminalRegisterReturnValueStatus8616.REFUSED,
            TerminalRegisterReturnValueEvidence8616(failure_count=1),
            TerminalRegisterReturnValueRefusal8616.MISSING_AX_REGISTER,
        )
    return function, ax_offset, ax_width


def _debug_linear_order_8616(
    statements: tuple[CStatement, ...],
    assignment_index: int,
    return_index: int,
) -> None:
    """Emit the opt-in linear AX-definition ordering dump."""
    _LOGGER.warning(
        "terminal AX value linear order: assignment=%d return=%d statements=%s calls=%s",
        assignment_index,
        return_index,
        tuple(
            (index, type(statement).__name__, contains_effectful_call_8616(statement))
            for index, statement in enumerate(statements)
        ),
        tuple(
            (
                index,
                tuple(
                    (
                        call.callee_func.name if call.callee_func is not None else None,
                        type(call.callee_target).__name__,
                        (
                            call.callee_target.variable.name
                            if isinstance(call.callee_target, CVariable)
                            else call.callee_target.value
                            if isinstance(call.callee_target, CConstant)
                            else call.callee_target
                            if isinstance(call.callee_target, str)
                            else None
                        ),
                    )
                    for call in _iter_c_nodes_deep_8616(statement)
                    if isinstance(call, CFunctionCall)
                ),
            )
            for index, statement in enumerate(statements)
            if contains_effectful_call_8616(statement)
        ),
    )


def materialize_terminal_register_return_value_8616(
    project: object,
    codegen: object,
) -> TerminalRegisterReturnValueResult8616:
    """Materialize one linear full-AX definition into one bare scalar return."""
    project_surface = cast(_ProjectSurface8616, project)
    codegen_surface = cast(_CodegenSurface8616, codegen)
    cfunc = codegen_surface.cfunc
    prototype = cfunc.functy
    root = cfunc.statements
    if (
        project_surface.arch.name != "86_16"
        or not isinstance(prototype, SimTypeFunction)
        or isinstance(prototype.returnty, SimTypeBottom)
        or not isinstance(root, CStatements)
    ):
        return _result_8616(
            codegen_surface,
            TerminalRegisterReturnValueStatus8616.NOT_APPLICABLE,
            TerminalRegisterReturnValueEvidence8616(),
            TerminalRegisterReturnValueRefusal8616.NOT_APPLICABLE,
        )

    context = _return_value_context_8616(project_surface, codegen_surface, cfunc.addr)
    if isinstance(context, TerminalRegisterReturnValueResult8616):
        return context
    function, ax_offset, ax_width = context

    census = _ax_return_census_8616(project, function, root, ax_offset, ax_width)
    if not census.terminal_shape or not census.all_assignments:
        return _result_8616(
            codegen_surface,
            TerminalRegisterReturnValueStatus8616.REFUSED,
            TerminalRegisterReturnValueEvidence8616(
                census.raw_count, int(census.terminal_shape), 0, 0, 0
            ),
            TerminalRegisterReturnValueRefusal8616.INCOMPLETE_TERMINAL_SHAPE,
        )
    return _materialize_linear_ax_return_8616(codegen_surface, census)


@dataclass(slots=True)
class _AxReturnCensus8616:
    """Terminal AX-definition census for one structured function."""

    raw_count: int
    terminal_shape: bool
    statements: tuple[object, ...]
    all_assignments: tuple[CAssignment, ...]
    assignments: tuple[CAssignment, ...]
    returns: tuple[CReturn, ...]


def _ax_return_census_8616(
    project: object,
    function: _FunctionSurface8616,
    root: CStatements,
    ax_offset: int,
    ax_width: int,
) -> _AxReturnCensus8616:
    """Collect terminal AX assignments, returns, and the linear suffix."""
    nodes = tuple(_iter_c_nodes_deep_8616(root))
    all_assignments = tuple(
        node
        for node in nodes
        if isinstance(node, CAssignment)
        and (view := physical_register_view_8616(node.lhs)) is not None
        and view.reg_offset == ax_offset
        and view.width == ax_width
    )
    returns = tuple(node for node in nodes if isinstance(node, CReturn))
    statements = _terminal_linear_suffix_8616(root)
    assignments = tuple(
        statement
        for statement in statements
        if isinstance(statement, CAssignment)
        and any(statement is assignment for assignment in all_assignments)
    )
    return _AxReturnCensus8616(
        raw_count=len(all_assignments),
        terminal_shape=(
            terminal_return_storage_8616(project, function) is TerminalReturnStorage8616.AX
            and len(returns) == 1
        ),
        statements=statements,
        all_assignments=all_assignments,
        assignments=assignments,
        returns=returns,
    )


def _materialize_linear_ax_return_8616(
    codegen_surface: _CodegenSurface8616,
    census: _AxReturnCensus8616,
) -> TerminalRegisterReturnValueResult8616:
    """Prove linear AX-definition ordering and rewrite the sole return."""
    raw_count = census.raw_count
    statements = census.statements
    assignments = census.assignments
    if not assignments:
        return _result_8616(
            codegen_surface,
            TerminalRegisterReturnValueStatus8616.REFUSED,
            TerminalRegisterReturnValueEvidence8616(raw_count, 1, 0, 0, 0),
            TerminalRegisterReturnValueRefusal8616.NONLINEAR_AX_DEFINITION,
        )
    return_node = census.returns[0]
    if not any(statement is return_node for statement in statements):
        return _result_8616(
            codegen_surface,
            TerminalRegisterReturnValueStatus8616.REFUSED,
            TerminalRegisterReturnValueEvidence8616(raw_count, 1, 0, 0, 0),
            TerminalRegisterReturnValueRefusal8616.NONLINEAR_AX_DEFINITION,
        )
    assignment = assignments[-1]
    assignment_index = next(
        index for index, statement in enumerate(statements) if statement is assignment
    )
    return_index = next(
        index for index, statement in enumerate(statements) if statement is return_node
    )
    if return_expression_has_wide_word_composition_8616(return_node.retval) or not return_expression_requires_materialization_8616(
        statements[:return_index],
        return_node.retval,
    ):
        return _result_8616(
            codegen_surface,
            TerminalRegisterReturnValueStatus8616.REFUSED,
            TerminalRegisterReturnValueEvidence8616(raw_count, 0, 0, 0, 0),
            TerminalRegisterReturnValueRefusal8616.INCOMPLETE_TERMINAL_SHAPE,
        )
    intervening = statements[assignment_index + 1 : return_index]
    if assignment_index >= return_index:
        return _result_8616(
            codegen_surface,
            TerminalRegisterReturnValueStatus8616.REFUSED,
            TerminalRegisterReturnValueEvidence8616(raw_count, 1, 0, 0, 0),
            TerminalRegisterReturnValueRefusal8616.OUT_OF_ORDER_DEFINITION,
        )
    return_expression = resolve_linear_virtual_return_expression_8616(
        statements[:assignment_index],
        assignment.rhs,
    )
    if return_expression is None:
        return _result_8616(
            codegen_surface,
            TerminalRegisterReturnValueStatus8616.REFUSED,
            TerminalRegisterReturnValueEvidence8616(raw_count, 1, 0, 0, 0),
            TerminalRegisterReturnValueRefusal8616.UNSAFE_EXPRESSION,
        )
    return_variable_keys = _expression_variable_keys_8616(return_expression)
    if any(_defines_any_variable_8616(statement, return_variable_keys) for statement in intervening):
        return _result_8616(
            codegen_surface,
            TerminalRegisterReturnValueStatus8616.REFUSED,
            TerminalRegisterReturnValueEvidence8616(raw_count, 1, 0, 0, 0),
            TerminalRegisterReturnValueRefusal8616.INTERVENING_DEFINITION,
        )
    if any(contains_effectful_call_8616(statement) for statement in intervening):
        if os.environ.get("INERTIA_DEBUG_TERMINAL_RETURN_VALUES") == "1":
            _debug_linear_order_8616(statements, assignment_index, return_index)
        return _result_8616(
            codegen_surface,
            TerminalRegisterReturnValueStatus8616.REFUSED,
            TerminalRegisterReturnValueEvidence8616(raw_count, 1, 0, 0, 0),
            TerminalRegisterReturnValueRefusal8616.INTERVENING_CALL,
        )

    return_node.retval = return_expression
    evidence = TerminalRegisterReturnValueEvidence8616(raw_count, 1, 1, 1, 0)
    if evidence.classified_fact_count > 0 and evidence.materialized_count == 0:
        raise RuntimeError("terminal AX return-value evidence was classified but not materialized")
    return _result_8616(
        codegen_surface,
        TerminalRegisterReturnValueStatus8616.MATERIALIZED,
        evidence,
    )
