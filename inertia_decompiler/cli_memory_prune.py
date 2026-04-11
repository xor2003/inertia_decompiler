from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable


def _prune_unused_unnamed_memory_declarations(codegen, *, iter_c_nodes_deep):
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
            if not isinstance(variable, SimMemoryVariable):
                continue
            name = getattr(variable, "name", None)
            if not isinstance(name, str) or not name.startswith("g_"):
                continue
            if id(variable) in used_variables:
                continue
            cvar = variables_in_use[variable]
            unified = getattr(cvar, "unified_variable", None)
            if unified is not None and id(unified) in used_variables:
                continue
            del variables_in_use[variable]
            changed = True

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable in list(unified_locals):
            if not isinstance(variable, SimMemoryVariable):
                continue
            name = getattr(variable, "name", None)
            if not isinstance(name, str) or not name.startswith("g_"):
                continue
            if id(variable) in used_variables:
                continue
            entries = unified_locals[variable]
            if any(id(getattr(cvariable, "variable", None)) in used_variables for cvariable, _vartype in entries):
                continue
            del unified_locals[variable]
            changed = True

    return changed
