from __future__ import annotations

import re

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable, SimStackVariable


_LINEAR_TEMP_NAME_RE = re.compile(r"(?:v\d+|vvar_\d+)")


def _is_linear_temp_name(name: str | None) -> bool:
    return isinstance(name, str) and _LINEAR_TEMP_NAME_RE.fullmatch(name) is not None


def _prune_unused_linear_register_declarations(codegen, *, iter_c_nodes_deep) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    used_variables: set[int] = set()
    for node in iter_c_nodes_deep(codegen.cfunc.statements):
        if not isinstance(node, structured_c.CVariable):
            continue
        variable = getattr(node, "variable", None)
        if variable is not None:
            used_variables.add(id(variable))
        unified = getattr(node, "unified_variable", None)
        if unified is not None:
            used_variables.add(id(unified))

    changed = False

    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable in list(variables_in_use):
            if not isinstance(variable, SimRegisterVariable):
                continue
            if not _is_linear_temp_name(getattr(variable, "name", None)):
                continue
            if id(variable) in used_variables:
                continue
            del variables_in_use[variable]
            changed = True

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable in list(unified_locals):
            if not isinstance(variable, SimRegisterVariable):
                continue
            if not _is_linear_temp_name(getattr(variable, "name", None)):
                continue
            entries = unified_locals[variable]
            if any(id(getattr(cvariable, "variable", None)) in used_variables for cvariable, _vartype in entries):
                continue
            del unified_locals[variable]
            changed = True

    return changed


def _prune_unused_local_declarations(codegen, *, iter_c_nodes_deep, describe_alias_storage) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    used_variables: set[int] = set()
    used_storage_identities: set[tuple[object, ...]] = set()
    for node in iter_c_nodes_deep(codegen.cfunc.statements):
        if not isinstance(node, structured_c.CVariable):
            continue
        variable = getattr(node, "variable", None)
        if variable is not None:
            used_variables.add(id(variable))
        unified = getattr(node, "unified_variable", None)
        if unified is not None:
            used_variables.add(id(unified))
        storage_identity = describe_alias_storage(node).identity
        if storage_identity is not None:
            used_storage_identities.add(storage_identity)

    changed = False

    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
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

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable in list(unified_locals):
            if not isinstance(variable, (SimRegisterVariable, SimStackVariable)):
                continue
            if id(variable) in used_variables:
                continue
            entries = unified_locals[variable]
            if any(describe_alias_storage(cvariable).identity in used_storage_identities for cvariable, _vartype in entries):
                continue
            del unified_locals[variable]
            changed = True

    return changed
