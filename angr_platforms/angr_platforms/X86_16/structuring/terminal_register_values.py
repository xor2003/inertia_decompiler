"""Materialize proven terminal register-lane values as structured C.

Layer: Structuring.
Responsibility: shape semantic register-lane effects into typed return expressions.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CExpression, CReturn, CVariable
from angr.sim_type import SimTypeBottom, SimTypeShort
from angr.sim_variable import SimStackVariable

from ..c_ast_utils import _clone_c_ast_tree_8616, _iter_c_nodes_deep_8616
from ..lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    stack_variable_coordinate_registry_8616,
)

__all__ = [
    "TerminalReturnValueMaterializationRefusal8616",
    "TerminalReturnValueMaterializationResult8616",
    "TerminalReturnValueMaterializationStatus8616",
    "compose_ax_byte_lanes_8616",
    "materialize_linear_terminal_return_value_8616",
    "materialize_proven_terminal_return_value_8616",
    "proven_terminal_value_extends_existing_8616",
    "terminal_ax_value_supports_widths_8616",
]


class _TerminalReturnCodegenSurface8616(Protocol):
    """Third-party codegen fields consumed by terminal return Structuring."""

    cfunc: object | None
    _inertia_missing_terminal_ax_return_terminal_value_block_count_8616: int


class _TerminalReturnCFunctionSurface8616(Protocol):
    """Third-party C function fields consumed by terminal return Structuring."""

    statements: object | None
    body: object | None
    functy: object | None
    prototype: object | None


class _TerminalReturnFunctionSurface8616(Protocol):
    """Third-party function fields consumed by terminal return Structuring."""

    prototype: object | None


class _TerminalReturnPrototypeSurface8616(Protocol):
    """Third-party prototype field consumed by terminal return Structuring."""

    returnty: object | None


class _TerminalReturnTypeSurface8616(Protocol):
    """Third-party return-type fields consumed by terminal return Structuring."""

    size: int | None
    label: str | None


class TerminalReturnValueMaterializationStatus8616(Enum):
    """Outcome of consuming one proven terminal register-value lineage."""

    MATERIALIZED = "materialized"
    ALREADY_MATERIALIZED = "already_materialized"
    REFUSED = "refused"


class TerminalReturnValueMaterializationRefusal8616(Enum):
    """Typed reason why a terminal register value was not consumed."""

    NONE = "none"
    MISSING_CFUNCTION = "missing_cfunction"
    MISSING_ROOT = "missing_root"
    MISSING_FUNCTION = "missing_function"
    RETURN_WIDTH = "return_width"
    MISSING_PROVEN_VALUE = "missing_proven_value"
    PROVEN_VALUE_NOT_EXTENSION = "proven_value_not_extension"
    TERMINAL_BLOCK_COUNT = "terminal_block_count"
    RETURN_COUNT = "return_count"


@dataclass(frozen=True)
class TerminalReturnValueMaterializationResult8616:
    """Closed evidence result for one terminal return-value materialization."""

    status: TerminalReturnValueMaterializationStatus8616
    refusal: TerminalReturnValueMaterializationRefusal8616
    changed: bool
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    replaced_return_value: CExpression | None = None
    materialized_return_value: CExpression | None = None

    @property
    def accepted(self) -> bool:
        """Return whether the proven value is present in the structured return."""
        return self.status is not TerminalReturnValueMaterializationStatus8616.REFUSED


def _refused_result_8616(
    refusal: TerminalReturnValueMaterializationRefusal8616,
    *,
    raw_fact_count: int = 0,
    normalized_fact_count: int = 0,
) -> TerminalReturnValueMaterializationResult8616:
    """Build one typed refusal without claiming classified or consumed evidence."""
    return TerminalReturnValueMaterializationResult8616(
        TerminalReturnValueMaterializationStatus8616.REFUSED,
        refusal,
        False,
        raw_fact_count,
        normalized_fact_count,
        0,
        0,
        0,
    )


def terminal_ax_value_supports_widths_8616(return_widths: Iterable[int | None]) -> bool:
    """Return whether AX alone satisfies every owned return-width projection."""
    widths = tuple(return_widths)
    return bool(widths) and all(isinstance(bits, int) and 0 < bits <= 16 for bits in widths)


def _prototype_return_type_8616(prototype: object | None) -> object | None:
    """Read one return type through the explicit third-party prototype surface."""
    if prototype is None:
        return None
    try:
        return cast(_TerminalReturnPrototypeSurface8616, prototype).returnty
    except AttributeError:
        return None


def _return_type_width_8616(return_type: object) -> int | None:
    """Read one return width through the explicit third-party type surface."""
    try:
        return cast(_TerminalReturnTypeSurface8616, return_type).size
    except (AttributeError, ValueError):
        return None


def _is_explicit_void_return_type_8616(return_type: object) -> bool:
    """Recognize an explicit third-party void type without text-based inference."""
    if type(return_type) is not SimTypeBottom:
        return False
    try:
        return cast(_TerminalReturnTypeSurface8616, return_type).label == "void"
    except AttributeError:
        return False


def proven_terminal_value_extends_existing_8616(
    existing_value: object,
    proven_value: CExpression,
    expressions_equivalent: Callable[[object, object], bool],
) -> bool:
    """Require a proven AX read-modify-write lineage to extend the existing value."""
    candidate: object = proven_value
    while isinstance(candidate, CBinaryOp):
        if expressions_equivalent(existing_value, candidate.lhs):
            return True
        candidate = candidate.lhs
    return False


def _proven_terminal_stack_value_replaces_stale_carrier_8616(
    codegen: object,
    existing_value: object,
    proven_value: CExpression,
    return_widths: Sequence[int | None],
) -> bool:
    """Accept an exact projected stack owner over a narrower stale carrier."""
    if not isinstance(existing_value, CVariable) or not isinstance(proven_value, CVariable):
        return False
    existing_variable = existing_value.variable
    proven_variable = proven_value.variable
    if not isinstance(existing_variable, SimStackVariable) or not isinstance(proven_variable, SimStackVariable):
        return False
    if existing_variable.base != "bp" or proven_variable.base != "bp":
        return False
    if not isinstance(existing_variable.size, int) or not isinstance(proven_variable.size, int):
        return False
    if existing_variable.size >= proven_variable.size:
        return False
    if not return_widths or any(width != proven_variable.size * 8 for width in return_widths):
        return False
    registry = stack_variable_coordinate_registry_8616(codegen)
    projection = registry.for_entry_sp_range(proven_variable.offset, proven_variable.size)
    if projection is None or projection.size != proven_variable.size:
        return False
    existing_bp_offset = machine_bp_offset_for_stack_variable_8616(codegen, existing_variable)
    proven_bp_offset = machine_bp_offset_for_stack_variable_8616(codegen, proven_variable)
    return bool(existing_bp_offset == proven_bp_offset == projection.bp_offset)


def materialize_proven_terminal_return_value_8616(
    return_nodes: Sequence[CReturn],
    proven_value: CExpression,
    *,
    terminal_value_block_count: int,
    expressions_equivalent: Callable[[object, object], bool],
) -> TerminalReturnValueMaterializationResult8616:
    """Install one fully proven terminal register value into one C return node."""
    raw_fact_count = max(1, terminal_value_block_count)
    if terminal_value_block_count != 1:
        return _refused_result_8616(
            TerminalReturnValueMaterializationRefusal8616.TERMINAL_BLOCK_COUNT,
            raw_fact_count=raw_fact_count,
            normalized_fact_count=max(0, terminal_value_block_count),
        )
    if len(return_nodes) != 1:
        return _refused_result_8616(
            TerminalReturnValueMaterializationRefusal8616.RETURN_COUNT,
            raw_fact_count=raw_fact_count,
            normalized_fact_count=1,
        )
    return_node = return_nodes[0]
    if expressions_equivalent(return_node.retval, proven_value):
        return TerminalReturnValueMaterializationResult8616(
            TerminalReturnValueMaterializationStatus8616.ALREADY_MATERIALIZED,
            TerminalReturnValueMaterializationRefusal8616.NONE,
            False,
            raw_fact_count,
            1,
            1,
            1,
            0,
        )
    replaced_return_value = return_node.retval if isinstance(return_node.retval, CExpression) else None
    return_node.retval = proven_value
    result = TerminalReturnValueMaterializationResult8616(
        TerminalReturnValueMaterializationStatus8616.MATERIALIZED,
        TerminalReturnValueMaterializationRefusal8616.NONE,
        True,
        raw_fact_count,
        1,
        1,
        1,
        0,
        replaced_return_value,
        proven_value,
    )
    if result.classified_fact_count > 0 and result.materialized_count == 0:
        raise RuntimeError("terminal register return value was classified but not materialized")
    return result


def _materialization_context_8616(
    codegen_surface: _TerminalReturnCodegenSurface8616,
    function: object | None,
) -> (
    tuple[_TerminalReturnCFunctionSurface8616, object, tuple[CReturn, ...]]
    | TerminalReturnValueMaterializationResult8616
):
    """Resolve cfunc, AST root, and return nodes or produce the refusal."""
    try:
        cfunc_value = codegen_surface.cfunc
    except AttributeError:
        cfunc_value = None
    if cfunc_value is None:
        return _refused_result_8616(TerminalReturnValueMaterializationRefusal8616.MISSING_CFUNCTION)
    cfunc = cast(_TerminalReturnCFunctionSurface8616, cfunc_value)
    try:
        root = cfunc.statements
    except AttributeError:
        root = None
    if root is None:
        try:
            root = cfunc.body
        except AttributeError:
            root = None
    if root is None:
        return _refused_result_8616(TerminalReturnValueMaterializationRefusal8616.MISSING_ROOT)
    if function is None:
        return _refused_result_8616(TerminalReturnValueMaterializationRefusal8616.MISSING_FUNCTION)
    return_nodes = tuple(node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CReturn))
    if len(return_nodes) != 1:
        return _refused_result_8616(
            TerminalReturnValueMaterializationRefusal8616.RETURN_COUNT,
            raw_fact_count=len(return_nodes),
        )
    return cfunc, root, return_nodes


def _return_widths_8616(
    function_surface: _TerminalReturnFunctionSurface8616,
    cfunc: _TerminalReturnCFunctionSurface8616,
) -> tuple[int | None, ...] | TerminalReturnValueMaterializationResult8616:
    """Collect concrete return widths or produce the width refusal."""
    try:
        function_prototype = function_surface.prototype
    except AttributeError:
        function_prototype = None
    try:
        cfunc_functy = cfunc.functy
    except AttributeError:
        cfunc_functy = None
    try:
        cfunc_prototype = cfunc.prototype
    except AttributeError:
        cfunc_prototype = None
    return_types = tuple(
        return_type
        for candidate in (function_prototype, cfunc_functy, cfunc_prototype)
        if (return_type := _prototype_return_type_8616(candidate)) is not None
    )
    concrete_return_types = tuple(return_type for return_type in return_types if type(return_type) is not SimTypeBottom)
    return_widths = tuple(_return_type_width_8616(return_type) for return_type in concrete_return_types)
    explicit_void = any(_is_explicit_void_return_type_8616(return_type) for return_type in return_types)
    if explicit_void or not terminal_ax_value_supports_widths_8616(return_widths):
        return _refused_result_8616(
            TerminalReturnValueMaterializationRefusal8616.RETURN_WIDTH,
            raw_fact_count=1,
            normalized_fact_count=1,
        )
    return return_widths


def materialize_linear_terminal_return_value_8616(
    project: object,
    codegen: object,
    function: object | None,
    *,
    recover_proven_value: Callable[[object, object, object], object | None],
    expressions_equivalent: Callable[[object, object], bool],
) -> TerminalReturnValueMaterializationResult8616:
    """Consume one linear terminal-register proof at the Structuring boundary."""
    codegen_surface = cast(_TerminalReturnCodegenSurface8616, codegen)
    context = _materialization_context_8616(codegen_surface, function)
    if isinstance(context, TerminalReturnValueMaterializationResult8616):
        return context
    cfunc, root, return_nodes = context
    widths = _return_widths_8616(
        cast(_TerminalReturnFunctionSurface8616, function),
        cfunc,
    )
    if isinstance(widths, TerminalReturnValueMaterializationResult8616):
        return widths
    return_widths = widths
    proven_value = recover_proven_value(project, codegen, function)
    if not isinstance(proven_value, CExpression):
        return _refused_result_8616(
            TerminalReturnValueMaterializationRefusal8616.MISSING_PROVEN_VALUE,
            raw_fact_count=1,
            normalized_fact_count=1,
        )
    existing_return_value = return_nodes[0].retval
    if (
        not expressions_equivalent(existing_return_value, proven_value)
        and not proven_terminal_value_extends_existing_8616(
            existing_return_value,
            proven_value,
            expressions_equivalent,
        )
        and not _proven_terminal_stack_value_replaces_stale_carrier_8616(
            codegen,
            existing_return_value,
            proven_value,
            return_widths,
        )
    ):
        return _refused_result_8616(
            TerminalReturnValueMaterializationRefusal8616.PROVEN_VALUE_NOT_EXTENSION,
            raw_fact_count=1,
            normalized_fact_count=1,
        )
    try:
        terminal_value_block_count = int(
            codegen_surface._inertia_missing_terminal_ax_return_terminal_value_block_count_8616 or 0
        )
    except AttributeError:
        terminal_value_block_count = 0
    result = materialize_proven_terminal_return_value_8616(
        return_nodes,
        proven_value,
        terminal_value_block_count=terminal_value_block_count,
        expressions_equivalent=expressions_equivalent,
    )
    if result.changed:
        cfunc.statements = root
        with contextlib.suppress(AttributeError):
            cfunc.body = root
    return result


def compose_ax_byte_lanes_8616(
    codegen: object,
    low_value: CExpression,
    high_value: CExpression,
) -> CBinaryOp:
    """Build AX from independently proven AL and AH values."""
    word_type = SimTypeShort(False)
    low_lane = CBinaryOp(
        "And",
        cast(CExpression, _clone_c_ast_tree_8616(low_value)),
        CConstant(0xFF, word_type, codegen=codegen),
        codegen=codegen,
    )
    high_lane = CBinaryOp(
        "And",
        cast(CExpression, _clone_c_ast_tree_8616(high_value)),
        CConstant(0xFF, word_type, codegen=codegen),
        codegen=codegen,
    )
    shifted_high_lane = CBinaryOp(
        "Shl",
        high_lane,
        CConstant(8, word_type, codegen=codegen),
        codegen=codegen,
    )
    return CBinaryOp("Or", low_lane, shifted_high_lane, codegen=codegen)
