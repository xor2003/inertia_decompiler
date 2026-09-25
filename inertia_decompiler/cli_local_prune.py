"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.postprocess.optimization.local_declarations import (
    dedupe_equivalent_stack_local_declarations_8616,
)

_LINEAR_TEMP_NAME_RE = re.compile(r"(?:v\d+|vvar_\d+)")


class _CFunctionLike(Protocol):
    """C function shape needed by local declaration pruning."""

    statements: object
    variables_in_use: object
    unified_local_vars: object


class _CodegenLike(Protocol):
    """Structured codegen shape needed by local declaration pruning."""

    cfunc: _CFunctionLike | None


class _AliasStorageLike(Protocol):
    """Alias-storage summary shape used by local declaration pruning."""

    identity: tuple[object, ...] | None


def _is_linear_temp_name(name: str | None) -> bool:
    return isinstance(name, str) and _LINEAR_TEMP_NAME_RE.fullmatch(name) is not None


def _collect_used_variable_ids_8616(
    cfunc: _CFunctionLike,
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
) -> set[int]:
    """Collect object identities of variables referenced by C nodes."""
    used_variables: set[int] = set()
    for node in iter_c_nodes_deep(cfunc.statements):
        if not isinstance(node, structured_c.CVariable):
            continue
        # dynamic codegen boundary: structured C variable nodes come from angr.
        variable = getattr(node, "variable", None)
        if variable is not None:
            used_variables.add(id(variable))
        # dynamic codegen boundary: unified variables are optional angr codegen fields.
        unified = getattr(node, "unified_variable", None)
        if unified is not None:
            used_variables.add(id(unified))
    return used_variables


def _drop_unused_linear_vars_in_use_8616(
    cfunc: _CFunctionLike,
    used_variables: set[int],
) -> bool:
    """Drop unused linear-temp register variables from variables_in_use."""
    changed = False
    variables_in_use = cfunc.variables_in_use
    if not isinstance(variables_in_use, dict):
        return False
    for variable in list(variables_in_use):
        if not isinstance(variable, SimRegisterVariable):
            continue
        # dynamic codegen boundary: SimVariable names are supplied by angr.
        if not _is_linear_temp_name(getattr(variable, "name", None)):
            continue
        if id(variable) in used_variables:
            continue
        del variables_in_use[variable]
        changed = True
    return changed


def _drop_unused_linear_unified_8616(
    cfunc: _CFunctionLike,
    used_variables: set[int],
) -> bool:
    """Drop unused linear-temp register variables from unified_local_vars."""
    changed = False
    unified_locals = cfunc.unified_local_vars
    if not isinstance(unified_locals, dict):
        return False
    for variable in list(unified_locals):
        if not isinstance(variable, SimRegisterVariable):
            continue
        # dynamic codegen boundary: SimVariable names are supplied by angr.
        if not _is_linear_temp_name(getattr(variable, "name", None)):
            continue
        entries = unified_locals[variable]
        # dynamic codegen boundary: CVariable entries are supplied by angr.
        if any(id(getattr(cvariable, "variable", None)) in used_variables for cvariable, _vartype in entries):
            continue
        del unified_locals[variable]
        changed = True
    return changed


def _prune_unused_linear_register_declarations(
    codegen: _CodegenLike,
    *,
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
) -> bool:
    cfunc = codegen.cfunc
    if cfunc is None:
        return False

    used_variables = _collect_used_variable_ids_8616(cfunc, iter_c_nodes_deep)

    changed = _drop_unused_linear_vars_in_use_8616(cfunc, used_variables)
    changed |= _drop_unused_linear_unified_8616(cfunc, used_variables)
    return changed


def _collect_used_variable_state_8616(
    cfunc: _CFunctionLike,
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    describe_alias_storage: Callable[[object], _AliasStorageLike],
) -> tuple[set[int], set[tuple[object, ...]]]:
    """Collect referenced variable ids and alias-storage identities."""
    used_variables: set[int] = set()
    used_storage_identities: set[tuple[object, ...]] = set()
    for node in iter_c_nodes_deep(cfunc.statements):
        if not isinstance(node, structured_c.CVariable):
            continue
        # dynamic codegen boundary: structured C variable nodes come from angr.
        variable = getattr(node, "variable", None)
        if variable is not None:
            used_variables.add(id(variable))
        # dynamic codegen boundary: unified variables are optional angr codegen fields.
        unified = getattr(node, "unified_variable", None)
        if unified is not None:
            used_variables.add(id(unified))
        storage_identity = describe_alias_storage(node).identity
        if storage_identity is not None:
            used_storage_identities.add(storage_identity)
    return used_variables, used_storage_identities


def _drop_unused_locals_in_use_8616(
    cfunc: _CFunctionLike,
    used_variables: set[int],
    used_storage_identities: set[tuple[object, ...]],
    describe_alias_storage: Callable[[object], _AliasStorageLike],
) -> bool:
    """Drop unused sim variables from variables_in_use."""
    changed = False
    variables_in_use = cfunc.variables_in_use
    if not isinstance(variables_in_use, dict):
        return False
    for variable in list(variables_in_use):
        if not isinstance(variable, (SimRegisterVariable, SimStackVariable)):
            continue
        if id(variable) in used_variables:
            continue
        cvar = variables_in_use[variable]
        if describe_alias_storage(cvar).identity in used_storage_identities:
            continue
        del variables_in_use[variable]
        changed = True
    return changed


def _drop_unused_locals_unified_8616(
    cfunc: _CFunctionLike,
    used_variables: set[int],
    used_storage_identities: set[tuple[object, ...]],
    describe_alias_storage: Callable[[object], _AliasStorageLike],
) -> bool:
    """Drop unused sim variables from unified_local_vars."""
    changed = False
    unified_locals = cfunc.unified_local_vars
    if not isinstance(unified_locals, dict):
        return False
    for variable in list(unified_locals):
        if not isinstance(variable, (SimRegisterVariable, SimStackVariable)):
            continue
        if id(variable) in used_variables:
            continue
        entries = unified_locals[variable]
        if any(
            describe_alias_storage(cvariable).identity in used_storage_identities
            for cvariable, _vartype in entries
        ):
            continue
        del unified_locals[variable]
        changed = True
    return changed


def _prune_unused_local_declarations(
    codegen: _CodegenLike,
    *,
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    describe_alias_storage: Callable[[object], _AliasStorageLike],
) -> bool:
    cfunc = codegen.cfunc
    if cfunc is None:
        return False

    changed = bool(dedupe_equivalent_stack_local_declarations_8616(codegen))

    used_variables, used_storage_identities = _collect_used_variable_state_8616(
        cfunc, iter_c_nodes_deep, describe_alias_storage,
    )

    changed |= _drop_unused_locals_in_use_8616(
        cfunc, used_variables, used_storage_identities, describe_alias_storage,
    )
    changed |= _drop_unused_locals_unified_8616(
        cfunc, used_variables, used_storage_identities, describe_alias_storage,
    )
    return changed
