from __future__ import annotations

import re

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimStackVariable


def _stack_type_for_size(size: int):
    return SimTypeChar(False) if size == 1 else SimTypeShort(False)


def _promote_direct_stack_cvariable(codegen, cvar, size: int, type_) -> bool:
    changed = False

    variable = getattr(cvar, "variable", None)
    if variable is None:
        return False

    if getattr(variable, "size", 0) < size:
        variable.size = size
        changed = True
    if getattr(cvar, "variable_type", None) != type_:
        cvar.variable_type = type_
        changed = True

    unified = getattr(cvar, "unified_variable", None)
    if unified is not None and getattr(unified, "size", 0) < size:
        try:
            unified.size = size
            changed = True
        except Exception:
            pass

    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        tracked = variables_in_use.get(variable)
        if tracked is not None and getattr(tracked, "variable_type", None) != type_:
            tracked.variable_type = type_
            changed = True

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for tracked_var, cvar_and_vartypes in list(unified_locals.items()):
            if tracked_var is not variable:
                continue
            new_entries = set()
            for tracked_cvar, _vartype in cvar_and_vartypes:
                if getattr(tracked_cvar, "variable_type", None) != type_:
                    tracked_cvar.variable_type = type_
                    changed = True
                new_entries.add((tracked_cvar, type_))
            if new_entries != cvar_and_vartypes:
                unified_locals[tracked_var] = new_entries
                changed = True
            break

    return changed


def _attach_ss_stack_variables(
    project,
    codegen,
    *,
    match_ss_stack_reference,
    resolve_stack_cvar_at_offset,
    replace_c_children,
    stack_slot_identity_for_variable,
):
    if getattr(codegen, "cfunc", None) is None:
        return False

    created: dict[tuple[int, int], structured_c.CVariable] = {}
    promoted: set[tuple[int, int]] = set()

    def _stack_object_name(offset: int) -> str:
        if offset >= 0:
            return f"arg_{offset:x}"
        return f"local_{-offset:x}"

    def _stack_local_name_or_existing(*names: str | None, offset: int) -> str:
        for name in names:
            if isinstance(name, str) and name and not re.fullmatch(r"(?:v\d+|vvar_\d+)", name):
                return name
        return _stack_object_name(offset)

    def transform(node):
        nonlocal promoted
        matched = match_ss_stack_reference(node, project)
        if matched is None:
            return node
        stack_var, ref_cvar, extra_offset = matched

        type_ = getattr(node, "type", None)
        if type_ is None:
            return node

        bits = getattr(type_, "size", None)
        size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)
        final_offset = stack_var.offset + extra_offset
        promoted_offset = final_offset

        if size >= 4:
            resolved_cvar = resolve_stack_cvar_at_offset(codegen, final_offset)
            resolved_variable = getattr(resolved_cvar, "variable", None)
            if isinstance(resolved_variable, SimStackVariable):
                resolved_offset = getattr(resolved_variable, "offset", None)
                if resolved_offset == final_offset:
                    _promote_direct_stack_cvariable(codegen, resolved_cvar, size, type_)
                    key = (final_offset, size)
                    promoted.add(key)
                    existing = created.get(key)
                    if existing is not None:
                        return existing
                    created[key] = resolved_cvar
                    return resolved_cvar

        key = (promoted_offset, size)
        promoted.add(key)
        existing = created.get(key)
        if existing is not None:
            return existing
        if extra_offset == 0:
            local_name = _stack_local_name_or_existing(
                getattr(ref_cvar, "name", None),
                getattr(stack_var, "name", None),
                offset=promoted_offset,
            )
        else:
            local_name = _stack_object_name(promoted_offset)

        cvar = structured_c.CVariable(
            SimStackVariable(
                promoted_offset,
                size,
                base=getattr(stack_var, "base", "bp"),
                name=local_name,
                region=codegen.cfunc.addr,
            ),
            variable_type=type_,
            codegen=codegen,
        )
        created[key] = cvar
        return cvar

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if replace_c_children(root, transform):
        changed = True

    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        identity = stack_slot_identity_for_variable(variable)
        if identity is None:
            continue
        offset = getattr(variable, "offset", None)
        matching = [size for promoted_offset, size in promoted if promoted_offset == offset]
        if not matching:
            continue
        size = max(matching)
        target_type = _stack_type_for_size(size)
        if getattr(variable, "size", 0) < size:
            variable.size = size
            changed = True
        if getattr(cvar, "variable_type", None) != target_type:
            cvar.variable_type = target_type
            changed = True
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and getattr(unified, "size", 0) < size:
            try:
                unified.size = size
                changed = True
            except Exception:
                pass

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable, cvar_and_vartypes in list(unified_locals.items()):
            identity = stack_slot_identity_for_variable(variable)
            if identity is None:
                continue
            offset = getattr(variable, "offset", None)
            matching = [size for promoted_offset, size in promoted if promoted_offset == offset]
            if not matching:
                continue
            size = max(matching)
            target_type = _stack_type_for_size(size)
            new_entries = {(cvariable, target_type) for cvariable, _vartype in cvar_and_vartypes}
            if new_entries != cvar_and_vartypes:
                unified_locals[variable] = new_entries
                changed = True
    return changed
