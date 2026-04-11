from __future__ import annotations

import contextlib
import re

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeBottom
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable


def _materialize_missing_stack_local_declarations(codegen, *, stack_slot_identity_for_variable, stack_type_for_size):
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    unified_locals = getattr(cfunc, "unified_local_vars", None)
    if not isinstance(unified_locals, dict):
        unified_locals = {}
        setattr(cfunc, "unified_local_vars", unified_locals)

    arg_variables = {
        id(getattr(arg, "variable", None))
        for arg in getattr(cfunc, "arg_list", ()) or ()
        if getattr(arg, "variable", None) is not None
    }
    arg_identities = {
        stack_slot_identity_for_variable(getattr(arg, "variable", None))
        for arg in getattr(cfunc, "arg_list", ()) or ()
        if isinstance(getattr(arg, "variable", None), SimStackVariable)
    }
    arg_identities.discard(None)
    existing_identities = {
        identity
        for variable in unified_locals
        for identity in (stack_slot_identity_for_variable(variable),)
        if identity is not None
    }

    stack_local_candidates = getattr(codegen, "_inertia_stack_local_declaration_candidates", None)
    source_variables = stack_local_candidates.values() if isinstance(stack_local_candidates, dict) else getattr(cfunc, "variables_in_use", {}).items()

    changed = False
    for variable, cvar in source_variables:
        if not isinstance(variable, SimStackVariable):
            continue
        identity = stack_slot_identity_for_variable(variable)
        if id(variable) in arg_variables or identity in arg_identities:
            continue
        if identity is None or identity in existing_identities:
            continue
        variable_type = getattr(cvar, "variable_type", None)
        if variable_type is None:
            variable_type = stack_type_for_size(getattr(variable, "size", 0) or 2)
        unified_locals[variable] = {(cvar, variable_type)}
        existing_identities.add(identity)
        changed = True

    if changed:
        sort_local_vars = getattr(cfunc, "sort_local_vars", None)
        if callable(sort_local_vars):
            with contextlib.suppress(Exception):
                sort_local_vars()
    return changed


def _dedupe_codegen_variable_names_8616(codegen, *, make_unique_identifier):
    if getattr(codegen, "cfunc", None) is None:
        return False

    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if not isinstance(variables_in_use, dict) and not isinstance(unified_locals, dict):
        return False

    def is_generic_name(name: object) -> bool:
        return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None

    def preferred_name(variable, cvar) -> str | None:
        candidates = [
            getattr(variable, "name", None),
            getattr(cvar, "name", None),
            getattr(getattr(cvar, "unified_variable", None), "name", None),
        ]
        for candidate in candidates:
            if isinstance(candidate, str) and candidate and not is_generic_name(candidate):
                return candidate
        for candidate in candidates:
            if isinstance(candidate, str) and candidate:
                return candidate
        return None

    def sort_key(item):
        variable, cvar = item
        if isinstance(variable, SimStackVariable):
            offset = getattr(variable, "offset", 0)
            return (
                0,
                0 if isinstance(offset, int) and offset > 0 else 1,
                offset if isinstance(offset, int) else 0,
                getattr(variable, "size", 0) if isinstance(getattr(variable, "size", 0), int) else 0,
                getattr(variable, "name", "") or "",
            )
        if isinstance(variable, SimRegisterVariable):
            return (
                1,
                getattr(variable, "reg", 0),
                getattr(variable, "size", 0) if isinstance(getattr(variable, "size", 0), int) else 0,
                getattr(variable, "name", "") or "",
            )
        if isinstance(variable, SimMemoryVariable):
            return (
                2,
                getattr(variable, "addr", 0),
                getattr(variable, "size", 0) if isinstance(getattr(variable, "size", 0), int) else 0,
                getattr(variable, "name", "") or "",
            )
        return (3, getattr(variable, "name", "") or "", getattr(cvar, "name", "") or "")

    ordered_items = []
    for arg in getattr(codegen.cfunc, "arg_list", ()) or ():
        variable = getattr(arg, "variable", None)
        if variable is not None:
            ordered_items.append((variable, arg))
    ordered_items.extend(list(variables_in_use.items()) if isinstance(variables_in_use, dict) else [])
    if isinstance(unified_locals, dict):
        for variable, cvars in unified_locals.items():
            if variable not in variables_in_use and cvars:
                ordered_items.append((variable, next(iter(cvars))[0]))

    ordered_items.sort(key=sort_key)

    used_names: set[str] = set()
    seen_variables: set[int] = set()
    changed = False

    def apply_name(variable, cvar, new_name: str) -> None:
        nonlocal changed
        if getattr(variable, "name", None) != new_name:
            variable.name = new_name
            changed = True
        if getattr(cvar, "name", None) != new_name:
            try:
                cvar.name = new_name
            except Exception:
                pass
            else:
                changed = True
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and getattr(unified, "name", None) != new_name:
            unified.name = new_name
            changed = True

    for variable, cvar in ordered_items:
        if id(variable) in seen_variables:
            continue
        seen_variables.add(id(variable))
        name = preferred_name(variable, cvar)
        if name is None:
            continue
        if name in used_names:
            name = make_unique_identifier(name, used_names)
        else:
            used_names.add(name)
        apply_name(variable, cvar, name)

    if changed:
        sort_local_vars = getattr(codegen.cfunc, "sort_local_vars", None)
        if callable(sort_local_vars):
            with contextlib.suppress(Exception):
                sort_local_vars()
    return changed


def _materialize_missing_register_local_declarations(
    codegen,
    *,
    stack_slot_identity_for_variable,
    stack_type_for_size,
    structured_codegen_node,
    iter_c_nodes_deep,
):
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    unified_locals = getattr(cfunc, "unified_local_vars", None)
    if not isinstance(unified_locals, dict):
        unified_locals = {}
        setattr(cfunc, "unified_local_vars", unified_locals)

    arg_variables = {
        id(getattr(arg, "variable", None))
        for arg in getattr(cfunc, "arg_list", ()) or ()
        if getattr(arg, "variable", None) is not None
    }

    def _local_identity(variable) -> tuple[object, ...] | None:
        if isinstance(variable, SimStackVariable):
            identity = stack_slot_identity_for_variable(variable)
            if identity is not None:
                return ("stack", identity.base, getattr(identity, "offset", None), getattr(variable, "size", None))
            return ("stack", getattr(variable, "base", None), getattr(variable, "offset", None), getattr(variable, "size", None))
        if isinstance(variable, SimRegisterVariable):
            return ("reg", getattr(variable, "reg", None), getattr(variable, "size", None))
        return None

    existing_identities = {
        identity
        for variable in unified_locals
        if (identity := _local_identity(variable)) is not None
    }

    desired_segment_regs = {"cs", "ds", "es", "ss", "fs", "gs", "flags"}
    changed = False

    register_candidates: dict[int, tuple[object, object]] = {}
    for variable, cvar in getattr(cfunc, "variables_in_use", {}).items():
        if isinstance(variable, (SimRegisterVariable, SimStackVariable)):
            register_candidates[id(variable)] = (variable, cvar)

    root = getattr(cfunc, "statements", None)
    if structured_codegen_node(root):
        for node in iter_c_nodes_deep(root):
            if not isinstance(node, structured_c.CVariable):
                continue
            variable = getattr(node, "variable", None)
            if not isinstance(variable, (SimRegisterVariable, SimStackVariable)):
                continue
            register_candidates.setdefault(id(variable), (variable, node))

    for variable, cvar in register_candidates.values():
        identity = _local_identity(variable)
        if id(variable) in arg_variables or identity in existing_identities:
            continue

        reg_name = getattr(variable, "name", None)
        if isinstance(reg_name, str) and reg_name in desired_segment_regs:
            continue

        variable_type = getattr(cvar, "variable_type", None)
        if variable_type is None:
            variable_type = stack_type_for_size(getattr(variable, "size", 0) or 2)
        if variable_type is None:
            continue

        unified_locals[variable] = {(cvar, variable_type)}
        if identity is not None:
            existing_identities.add(identity)
        changed = True

    if changed:
        sort_local_vars = getattr(cfunc, "sort_local_vars", None)
        if callable(sort_local_vars):
            with contextlib.suppress(Exception):
                sort_local_vars()
    return changed


def _prune_void_function_return_values(codegen, *, iter_c_nodes_deep):
    if getattr(codegen, "cfunc", None) is None:
        return False

    prototype = getattr(codegen.cfunc, "prototype", None)
    if prototype is None or type(getattr(prototype, "returnty", None)) is not SimTypeBottom:
        return False

    changed = False
    for node in iter_c_nodes_deep(codegen.cfunc.statements):
        if not isinstance(node, structured_c.CReturn):
            continue
        if getattr(node, "retval", None) is None:
            continue
        node.retval = None
        changed = True

    return changed
