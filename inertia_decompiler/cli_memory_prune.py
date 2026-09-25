"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable


class _CFunctionLike(Protocol):
    """C function shape needed by memory declaration pruning."""

    statements: object
    variables_in_use: object
    unified_local_vars: object


class _CodegenLike(Protocol):
    """Structured codegen shape needed by memory declaration pruning."""

    cfunc: _CFunctionLike | None


def _is_prunable_generated_memory_name_8616(name: object) -> bool:
    return isinstance(name, str) and (name.startswith("g_") or re.fullmatch(r"mem_[0-9A-Fa-f]+", name) is not None)


def _collect_used_variable_ids_8616(
    cfunc: object, iter_c_nodes_deep: Callable[[object], Iterable[object]]
) -> set[int]:
    """Collect ids of variables still referenced anywhere in the function body."""
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


def _prune_variables_in_use_8616(variables_in_use: object, used_variables: set[int]) -> bool:
    """Drop generated unused memory declarations from ``cfunc.variables_in_use``."""
    if not isinstance(variables_in_use, dict):
        return False
    changed = False
    for variable in list(variables_in_use):
        if not isinstance(variable, SimMemoryVariable):
            continue
        # dynamic codegen boundary: SimVariable names are supplied by angr.
        name = getattr(variable, "name", None)
        if not _is_prunable_generated_memory_name_8616(name):
            continue
        if id(variable) in used_variables:
            continue
        cvar = variables_in_use[variable]
        # dynamic codegen boundary: unified variables are optional angr codegen fields.
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and id(unified) in used_variables:
            continue
        del variables_in_use[variable]
        changed = True
    return changed


def _prune_unified_locals_8616(unified_locals: object, used_variables: set[int]) -> bool:
    """Drop generated unused memory declarations from ``cfunc.unified_local_vars``."""
    if not isinstance(unified_locals, dict):
        return False
    changed = False
    for variable in list(unified_locals):
        if not isinstance(variable, SimMemoryVariable):
            continue
        # dynamic codegen boundary: SimVariable names are supplied by angr.
        name = getattr(variable, "name", None)
        if not _is_prunable_generated_memory_name_8616(name):
            continue
        if id(variable) in used_variables:
            continue
        entries = unified_locals[variable]
        # dynamic codegen boundary: CVariable entries are supplied by angr.
        if any(id(getattr(cvariable, "variable", None)) in used_variables for cvariable, _vartype in entries):
            continue
        del unified_locals[variable]
        changed = True
    return changed


def _prune_unused_unnamed_memory_declarations(
    codegen: _CodegenLike,
    *,
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
) -> bool:
    cfunc = codegen.cfunc
    if cfunc is None:
        return False

    used_variables = _collect_used_variable_ids_8616(cfunc, iter_c_nodes_deep)
    changed = _prune_variables_in_use_8616(cfunc.variables_in_use, used_variables)
    return _prune_unified_locals_8616(cfunc.unified_local_vars, used_variables) or changed
