"""Lower unresolved direction-step inputs to explicit runtime state.

Layer: Types/Lowering.
Responsibility: preserve the architectural DF-derived string direction when
angr cannot render the artificial VEX ``d`` register's incoming expression.

Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeLong
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616

from .global_declarations import GlobalDeclarationCType8616, record_global_declaration_spec_8616

__all__ = ["DirectionFlagStateStats8616", "lower_direction_flag_state_8616"]

_RUNTIME_DIRECTION_ADDRESS_8616 = 0x1_001C
_RUNTIME_DIRECTION_NAME_8616 = "inertia_direction"


class _DirectionArch8616(Protocol):
    """Architecture register map consumed at the third-party boundary."""

    registers: Mapping[str, tuple[int, int]]


class _DirectionProject8616(Protocol):
    """Project architecture consumed by direction-state lowering."""

    arch: _DirectionArch8616


class _DirectionCFunction8616(Protocol):
    """Structured function surface mutated by direction-state lowering."""

    addr: int
    statements: object


class _DirectionCodegen8616(Protocol):
    """Dynamic codegen boundary consumed by direction-state lowering."""

    project: _DirectionProject8616 | None
    cfunc: _DirectionCFunction8616 | None
    _inertia_direction_flag_state_stats_8616: DirectionFlagStateStats8616


@dataclass(frozen=True, slots=True)
class DirectionFlagStateStats8616:
    """Closed evidence counters for direction-state materialization."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


def _register_shape_8616(node: object) -> tuple[int, int] | None:
    """Return one exact structured register view."""
    if not isinstance(node, structured_c.CVariable):
        return None
    for variable in (node.unified_variable, node.variable):
        if isinstance(variable, SimRegisterVariable) and isinstance(variable.reg, int) and isinstance(variable.size, int):
            return variable.reg, variable.size
    return None


def _contains_unrenderable_input_8616(node: object) -> bool:
    """Return whether one expression contains angr's opaque dirty placeholder."""
    return any(isinstance(item, structured_c.CDirtyExpression) for item in _iter_c_nodes_deep_8616(node))


def _runtime_direction_cvar_8616(codegen: object, function_addr: int) -> structured_c.CVariable:
    """Build the explicit signed direction-step runtime variable."""
    return structured_c.CVariable(
        SimMemoryVariable(
            _RUNTIME_DIRECTION_ADDRESS_8616,
            4,
            name=_RUNTIME_DIRECTION_NAME_8616,
            region=function_addr,
            category="inertia_direction_state",
        ),
        variable_type=SimTypeLong(True),
        codegen=codegen,
    )


def lower_direction_flag_state_8616(codegen: object) -> bool:
    """Replace only opaque DF-derived ``d`` assignments with runtime state."""
    boundary = cast(_DirectionCodegen8616, codegen)
    project = boundary.project
    cfunc = boundary.cfunc
    empty = DirectionFlagStateStats8616(0, 0, 0, 0, 0)
    if project is None or cfunc is None or not isinstance(cfunc.statements, structured_c.CStatements):
        boundary._inertia_direction_flag_state_stats_8616 = empty
        return False
    direction_shape = project.arch.registers.get("d")
    if direction_shape is None or len(direction_shape) < 2:
        boundary._inertia_direction_flag_state_stats_8616 = empty
        return False

    raw = 0
    materialized = 0
    for node in _iter_c_nodes_deep_8616(cfunc.statements):
        if not isinstance(node, structured_c.CAssignment) or _register_shape_8616(node.lhs) != direction_shape[:2]:
            continue
        raw += 1
        if not _contains_unrenderable_input_8616(node.rhs):
            continue
        node.rhs = _runtime_direction_cvar_8616(codegen, cfunc.addr)
        materialized += 1

    if materialized:
        record_global_declaration_spec_8616(
            codegen,
            ctype=GlobalDeclarationCType8616.SIGNED_LONG,
            name=_RUNTIME_DIRECTION_NAME_8616,
            array_len=None,
        )
    boundary._inertia_direction_flag_state_stats_8616 = DirectionFlagStateStats8616(
        raw_fact_count=raw,
        normalized_fact_count=raw,
        classified_fact_count=materialized,
        materialized_count=materialized,
        failure_count=raw - materialized,
    )
    return materialized > 0
