"""Project proven stack storage names onto regenerated C-AST variables.

Layer: Types/Lowering.
Responsibility: consume the authoritative BP/entry-SP coordinate registry and
replay only its display-name projection onto exact angr stack ranges. This
module does not discover storage identity or infer names from rendered text.
Historical projections retain their evidence but reserve a display name only
while a corresponding C owner remains in the body, arguments or declarations.
Dynamic boundary: angr codegen and C-AST objects are third-party contracts.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping, Sequence
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_variable import SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from .stack_coordinate_rebinding import rebind_restored_stack_coordinate_registry_8616
from .stack_variable_coordinates import (
    StackVariableCoordinateRegistry8616,
    bind_stack_variable_coordinate_cvar_8616,
    machine_bp_offset_for_stack_variable_8616,
    stack_variable_coordinate_registry_8616,
)

_GENERATED_STACK_NAME_PREFIXES_8616 = ("arg_", "local_", "s_", "stack_", "var_")
logger: logging.Logger = logging.getLogger(__name__)


class _CVariableBoundary8616(Protocol):
    """Third-party CVariable fields used to synchronize projected names."""

    variable: object
    unified_variable: object | None


class _CFunctionBoundary8616(Protocol):
    """Third-party CFunction surfaces containing stack projections."""

    arg_list: object
    variables_in_use: object
    unified_local_vars: object
    statements: object


class _CodegenBoundary8616(Protocol):
    """Third-party codegen field exposing the rendered C function."""

    cfunc: _CFunctionBoundary8616


def generated_stack_variable_name_8616(name: object) -> bool:
    """Return whether a stack name is a generated, replaceable placeholder."""
    return (
        not isinstance(name, str)
        or not name
        or name.startswith(_GENERATED_STACK_NAME_PREFIXES_8616)
        or (name.startswith("v") and name[1:].isdigit())
    )


def publish_stack_variable_projection_display_names_8616(
    codegen: object,
    names_by_bp_offset: Mapping[int, str],
) -> int:
    """Publish proven names onto unique machine-BP stack projections."""
    published = 0
    for bp_offset, display_name in names_by_bp_offset.items():
        if not display_name:
            continue
        registry = stack_variable_coordinate_registry_8616(codegen)
        matches = tuple(
            projection
            for projection in registry.projections
            if projection.bp_offset == bp_offset
        )
        if len(matches) != 1:
            continue
        projection = matches[0]
        rebound = bind_stack_variable_coordinate_cvar_8616(
            codegen,
            bp_offset=projection.bp_offset,
            size=projection.size,
            cvar=projection.cvar,
            display_name=display_name,
        )
        if rebound is not None:
            published += 1
    return published


def publish_prototype_argument_projection_names_8616(
    codegen: object,
    names: Sequence[str],
) -> int:
    """Keep exact stack-coordinate projections coherent with argument renames."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        arguments = boundary.cfunc.arg_list
    except AttributeError:
        return 0
    if not isinstance(arguments, (list, tuple)):
        return 0
    registry = stack_variable_coordinate_registry_8616(codegen)
    published = 0
    for cvar, display_name in zip(arguments, names, strict=False):
        try:
            variable = cast(_CVariableBoundary8616, cvar).variable
        except AttributeError:
            continue
        if not isinstance(variable, SimStackVariable):
            continue
        projection = registry.for_variable(variable)
        if projection is None:
            continue
        rebound = bind_stack_variable_coordinate_cvar_8616(
            codegen,
            bp_offset=projection.bp_offset,
            size=projection.size,
            cvar=cvar,
            display_name=display_name,
        )
        if rebound is not None:
            published += 1
    return published


def _rename_generated_stack_variable_8616(variable: object, name: str) -> None:
    """Rename a generated or collision-suffixed exact stack projection."""
    if not isinstance(variable, SimStackVariable):
        return
    current_name = variable.name
    collision_prefix = f"{name}_"
    collision_suffix = (
        current_name[len(collision_prefix) :]
        if isinstance(current_name, str) and current_name.startswith(collision_prefix)
        else ""
    )
    if generated_stack_variable_name_8616(current_name) or collision_suffix.isdigit():
        variable.name = name


def _rename_projected_cvariable_8616(cvar: object, name: str) -> None:
    """Rename the physical and unified variables referenced by one CVariable."""
    boundary = cast(_CVariableBoundary8616, cvar)
    try:
        variable = boundary.variable
        unified_variable = boundary.unified_variable
    except AttributeError:
        return
    _rename_generated_stack_variable_8616(variable, name)
    _rename_generated_stack_variable_8616(unified_variable, name)


def _matches_entry_sp_range_8616(variable: object, entry_sp_offset: int, size: int) -> bool:
    """Return whether a variable is the exact projected storage range."""
    return (
        isinstance(variable, SimStackVariable)
        and variable.offset == entry_sp_offset
        and variable.size == size
    )


def _rename_declaration_entries_8616(entries: object, name: str) -> None:
    """Synchronize angr's declaration views for an already matched stack owner."""
    if isinstance(entries, (list, set, tuple)):
        for entry in entries:
            if isinstance(entry, tuple) and entry:
                _rename_projected_cvariable_8616(entry[0], name)


def apply_stack_variable_projection_name_8616(
    codegen: object,
    *,
    cvar: object,
    entry_sp_offset: int,
    size: int,
    name: str,
) -> None:
    """Synchronize one proven display name across exact C-AST projections."""
    _rename_projected_cvariable_8616(cvar, name)
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        cfunc = boundary.cfunc
    except AttributeError:
        return
    try:
        variables_in_use = cfunc.variables_in_use
    except AttributeError:
        variables_in_use = None
    if isinstance(variables_in_use, dict):
        for variable, candidate in variables_in_use.items():
            if _matches_entry_sp_range_8616(variable, entry_sp_offset, size):
                _rename_generated_stack_variable_8616(variable, name)
                _rename_projected_cvariable_8616(candidate, name)
    try:
        unified_local_vars = cfunc.unified_local_vars
    except AttributeError:
        unified_local_vars = None
    if isinstance(unified_local_vars, dict):
        for variable, entries in unified_local_vars.items():
            if not _matches_entry_sp_range_8616(variable, entry_sp_offset, size):
                continue
            _rename_generated_stack_variable_8616(variable, name)
            _rename_declaration_entries_8616(entries, name)


def _projected_display_name_8616(
    registry: StackVariableCoordinateRegistry8616,
    target_names: frozenset[str],
    variable: SimStackVariable,
) -> str | None:
    """Select a durable name for one exact or colliding stack projection."""
    projection = registry.for_variable(variable)
    if projection is None:
        projection = registry.for_entry_sp_range(variable.offset, variable.size)
    if projection is not None:
        return projection.display_name or None
    if variable.name in target_names and generated_stack_variable_name_8616(variable.name):
        sign = "m" if variable.offset < 0 else "p"
        return f"stack_sp_{sign}{abs(variable.offset):x}_{variable.size}"
    return None


def _reapply_cvariable_name_8616(
    registry: StackVariableCoordinateRegistry8616,
    target_names: frozenset[str],
    cvar: CVariable,
) -> bool:
    """Replay one coordinate-backed name onto an angr CVariable."""
    variable = cvar.variable
    if not isinstance(variable, SimStackVariable):
        return False
    name = _projected_display_name_8616(registry, target_names, variable)
    if name is None:
        return False
    previous_name = variable.name
    _rename_projected_cvariable_8616(cvar, name)
    return bool(variable.name != previous_name)


def _stack_variable_debug_key_8616(value: object) -> tuple[int, int, str | None] | None:
    """Return a compact debug key for one structured stack argument."""
    if not isinstance(value, CVariable) or not isinstance(value.variable, SimStackVariable):
        return None
    variable = value.variable
    return variable.offset, variable.size, variable.name


def _live_projection_names_8616(
    registry: StackVariableCoordinateRegistry8616,
    variables: Sequence[object],
) -> frozenset[str]:
    """Reserve names for current storage views, not obsolete intermediate owners."""
    live_names: set[str] = set()
    for variable in variables:
        if not isinstance(variable, SimStackVariable):
            continue
        projection = registry.for_variable(variable) or registry.for_entry_sp_range(variable.offset, variable.size)
        if projection is not None and projection.display_name:
            live_names.add(projection.display_name)
    return frozenset(live_names)


def _log_stack_coordinate_names_8616(
    registry: StackVariableCoordinateRegistry8616, cfunc: _CFunctionBoundary8616,
) -> None:
    """Emit optional coordinate diagnostics without mixing them into replay."""
    if os.environ.get("INERTIA_DEBUG_STACK_COORDINATES") == "1":
        arguments = cfunc.arg_list if isinstance(cfunc.arg_list, (list, tuple)) else ()
        logger.warning(
            "[stack-coordinate-names] projections=%r arguments=%r",
            tuple(
                (
                    item.bp_offset,
                    item.entry_sp_offset,
                    item.size,
                    item.display_name,
                    item.variable.name,
                )
                for item in registry.projections
            ),
            tuple(_stack_variable_debug_key_8616(argument) for argument in arguments),
        )


def reapply_stack_variable_projection_names_8616(codegen: object) -> bool:
    """Restore durable projected names across maps and regenerated AST clones."""
    registry = stack_variable_coordinate_registry_8616(codegen)
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        cfunc = boundary.cfunc
    except AttributeError:
        return False
    _log_stack_coordinate_names_8616(registry, cfunc)
    cvars: list[CVariable] = []
    try:
        variables_in_use = cfunc.variables_in_use
    except AttributeError:
        variables_in_use = None
    if isinstance(variables_in_use, dict):
        cvars.extend(value for value in variables_in_use.values() if isinstance(value, CVariable))
    try:
        statements = cfunc.statements
    except AttributeError:
        statements = None
    cvars.extend(node for node in _iter_c_nodes_deep_8616(statements) if isinstance(node, CVariable))
    try:
        current_arguments = cfunc.arg_list
    except AttributeError:
        current_arguments = ()
    try:
        declarations = cfunc.unified_local_vars
    except AttributeError:
        declarations = {}
    if isinstance(current_arguments, (list, tuple)):
        cvars.extend(argument for argument in current_arguments if isinstance(argument, CVariable))
    variables = [cvar.variable for cvar in cvars]
    if isinstance(declarations, dict):
        variables.extend(declarations)
    # Registry entries outlive intermediate expressions. Reserving their names
    # after those owners disappear invents collisions with unrelated live locals.
    target_names = _live_projection_names_8616(registry, variables)
    changed = False
    for cvar in cvars:
        changed = _reapply_cvariable_name_8616(registry, target_names, cvar) or changed
    return changed


__all__ = [
    "apply_stack_variable_projection_name_8616",
    "generated_stack_variable_name_8616",
    "machine_bp_offset_for_stack_variable_8616",
    "publish_prototype_argument_projection_names_8616",
    "publish_stack_variable_projection_display_names_8616",
    "reapply_stack_variable_projection_names_8616",
    "rebind_restored_stack_coordinate_registry_8616",
]
