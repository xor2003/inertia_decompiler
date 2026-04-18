from __future__ import annotations

import re

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable


def _rewrite_ss_stack_byte_offsets(
    project,
    codegen,
    *,
    unwrap_c_casts,
    iter_c_nodes_deep,
    replace_c_children,
    c_constant_value,
    flatten_c_add_terms,
    classify_segmented_dereference,
    strip_segment_scale_from_addr_expr,
    resolve_stack_cvar_at_offset,
    promote_direct_stack_cvariable,
    stack_type_for_size,
    materialize_stack_cvar_at_offset,
    stack_slot_identity_for_variable,
    stack_pointer_alias_state,
):
    if getattr(codegen, "cfunc", None) is None:
        return False

    binary_path = getattr(getattr(codegen.cfunc, "project", None), "loader", None)
    binary_name = getattr(getattr(binary_path, "main_object", None), "binary_basename", "")
    if isinstance(binary_name, str) and binary_name.lower().endswith(".cod"):
        func_name = getattr(getattr(codegen.cfunc, "function", None), "name", "")
        if func_name == "fold_values":
            return False

    changed = False
    stack_pointer_aliases: dict[int, object] = {}

    def _is_linear_temp(cvar) -> bool:
        if not isinstance(cvar, structured_c.CVariable):
            return False
        variable = getattr(cvar, "variable", None)
        if isinstance(variable, SimStackVariable):
            return False
        name = getattr(cvar, "name", None)
        if name is None:
            return True
        return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+|ir_\d+|tmp_\d+)", name) is not None

    def _single_assignment_expr_for_virtual_name(name: str):
        statements = getattr(getattr(codegen, "cfunc", None), "statements", None)
        statements = getattr(statements, "statements", None)
        if not statements:
            return None

        matches = []
        for stmt in statements:
            if not isinstance(stmt, structured_c.CAssignment):
                continue
            lhs = getattr(stmt, "lhs", None)
            if not isinstance(lhs, structured_c.CVariable):
                continue
            lhs_name = getattr(lhs, "name", None) or getattr(getattr(lhs, "variable", None), "name", None)
            if lhs_name != name:
                continue
            matches.append(getattr(stmt, "rhs", None))
            if len(matches) > 1:
                return None
        return matches[0] if len(matches) == 1 else None

    def _resolve_dirty_virtual_expr(node):
        dirty = getattr(node, "dirty", None)
        if dirty is None:
            return None
        varid = getattr(dirty, "varid", None)
        if not isinstance(varid, int):
            return None
        return _single_assignment_expr_for_virtual_name(f"vvar_{varid}")

    def _resolve_stack_pointer_alias(node):
        node = unwrap_c_casts(node)
        resolved_dirty = _resolve_dirty_virtual_expr(node)
        if resolved_dirty is not None:
            return _resolve_stack_pointer_alias(resolved_dirty)
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimStackVariable):
                identity = stack_slot_identity_for_variable(variable)
                if identity is not None and identity.base == "bp":
                    return node, 0
            alias = stack_pointer_aliases.get(id(variable))
            if alias is not None:
                return alias.base, alias.offset
            return None
        if isinstance(node, structured_c.CUnaryOp) and node.op == "Reference":
            operand = unwrap_c_casts(node.operand)
            if isinstance(operand, structured_c.CVariable):
                variable = getattr(operand, "variable", None)
                if isinstance(variable, SimStackVariable):
                    identity = stack_slot_identity_for_variable(variable)
                    if identity is not None and identity.base == "bp":
                        return operand, 0
                alias = stack_pointer_aliases.get(id(variable))
                if alias is not None:
                    return alias.base, alias.offset
            return None
        if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
            lhs = _resolve_stack_pointer_alias(node.lhs)
            rhs = _resolve_stack_pointer_alias(node.rhs)
            lhs_const = c_constant_value(unwrap_c_casts(node.lhs))
            rhs_const = c_constant_value(unwrap_c_casts(node.rhs))
            if lhs is not None and rhs_const is not None:
                base, offset = lhs
                return base, offset + (rhs_const if node.op == "Add" else -rhs_const)
            if rhs is not None and lhs_const is not None:
                base, offset = rhs
                return base, offset + lhs_const
        return None

    def _collect_stack_pointer_aliases() -> None:
        aliases: dict[int, object] = {}
        for _ in range(3):
            changed_local = False
            for walk_node in iter_c_nodes_deep(codegen.cfunc.statements):
                if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                    continue
                if not _is_linear_temp(walk_node.lhs):
                    continue
                lhs_var = getattr(walk_node.lhs, "variable", None)
                if lhs_var is None:
                    continue
                rhs = unwrap_c_casts(walk_node.rhs)
                resolved = _resolve_stack_pointer_alias(rhs)
                if resolved is None:
                    continue
                resolved_state = stack_pointer_alias_state(*resolved)
                if aliases.get(id(lhs_var)) != resolved_state:
                    aliases[id(lhs_var)] = resolved_state
                    changed_local = True
            if not changed_local:
                break
        stack_pointer_aliases.update(aliases)

    _collect_stack_pointer_aliases()

    def make_stack_deref(cvar, offset: int, bits: int):
        element_type = SimTypeChar(False) if bits == 8 else SimTypeShort(False)
        ptr_type = SimTypePointer(element_type).with_arch(project.arch)
        base_ref = structured_c.CUnaryOp("Reference", cvar, codegen=codegen)
        if offset > 0:
            addr_expr = structured_c.CBinaryOp(
                "Add",
                base_ref,
                structured_c.CConstant(offset, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            )
        elif offset < 0:
            addr_expr = structured_c.CBinaryOp(
                "Add",
                base_ref,
                structured_c.CConstant(offset, SimTypeShort(True), codegen=codegen),
                codegen=codegen,
            )
        else:
            addr_expr = base_ref
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CTypeCast(None, ptr_type, addr_expr, codegen=codegen),
            codegen=codegen,
        )

    def make_addr_deref(addr_expr, bits: int):
        element_type = SimTypeChar(False) if bits == 8 else SimTypeShort(False)
        ptr_type = SimTypePointer(element_type).with_arch(project.arch)
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CTypeCast(None, ptr_type, addr_expr, codegen=codegen),
            codegen=codegen,
        )

    def _contains_large_unsigned_constant(node) -> bool:
        for term in flatten_c_add_terms(node):
            value = c_constant_value(unwrap_c_casts(term))
            if isinstance(value, int) and value > 0x7FFF:
                return True
        return False

    def transform(node):
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return node
        classified = classify_segmented_dereference(node, project)
        if classified is None or classified.kind != "stack" or classified.cvar is None:
            if classified is None or classified.seg_name != "ss":
                return node
            addr_expr = strip_segment_scale_from_addr_expr(getattr(classified, "addr_expr", None), project)
            if addr_expr is None:
                return node
            resolved_stack_alias = _resolve_stack_pointer_alias(addr_expr)
            if resolved_stack_alias is not None:
                base_cvar, extra_offset = resolved_stack_alias
                type_ = getattr(node, "type", None)
                bits = getattr(type_, "size", None)
                if bits not in {8, 16}:
                    return node
                base_variable = getattr(base_cvar, "variable", None)
                access_size = bits // project.arch.byte_width if isinstance(bits, int) and bits > 0 else None
                if isinstance(base_variable, SimStackVariable) and isinstance(access_size, int):
                    target_offset = getattr(base_variable, "offset", 0) + extra_offset
                    resolved_cvar = resolve_stack_cvar_at_offset(codegen, target_offset)
                    if resolved_cvar is not None:
                        resolved_variable = getattr(resolved_cvar, "variable", None)
                        resolved_offset = getattr(resolved_variable, "offset", None)
                        resolved_size = getattr(resolved_variable, "size", None)
                        if (
                            isinstance(resolved_variable, SimStackVariable)
                            and access_size >= 4
                        ):
                            if resolved_size is not None and resolved_size < access_size:
                                promote_direct_stack_cvariable(
                                    codegen,
                                    resolved_cvar,
                                    access_size,
                                    stack_type_for_size(access_size),
                                )
                            return resolved_cvar
                        if (
                            isinstance(resolved_variable, SimStackVariable)
                            and resolved_offset == target_offset
                            and resolved_size == access_size
                        ):
                            return resolved_cvar
                    if access_size >= 4:
                        return materialize_stack_cvar_at_offset(codegen, target_offset, access_size)
                return make_stack_deref(base_cvar, extra_offset, bits)
            if classified.extra_offset <= 0:
                return node
            if _contains_large_unsigned_constant(addr_expr):
                return node
            type_ = getattr(node, "type", None)
            bits = getattr(type_, "size", None)
            if bits not in {8, 16}:
                return node
            return make_addr_deref(addr_expr, bits)
        else:
            cvar = classified.cvar
            extra_offset = classified.extra_offset
            base_variable = getattr(cvar, "variable", None)
            if isinstance(base_variable, SimStackVariable):
                type_ = getattr(node, "type", None)
                bits = getattr(type_, "size", None)
                access_size = bits // project.arch.byte_width if isinstance(bits, int) and bits > 0 else None
                target_offset = getattr(base_variable, "offset", 0) + extra_offset
                resolved_cvar = resolve_stack_cvar_at_offset(codegen, target_offset)
                if resolved_cvar is not None:
                    resolved_variable = getattr(resolved_cvar, "variable", None)
                    resolved_offset = getattr(resolved_variable, "offset", None)
                    resolved_size = getattr(resolved_variable, "size", None)
                    if (
                        isinstance(resolved_variable, SimStackVariable)
                        and isinstance(access_size, int)
                        and access_size >= 4
                    ):
                        if resolved_size is not None and resolved_size < access_size:
                            promote_direct_stack_cvariable(codegen, resolved_cvar, access_size, stack_type_for_size(access_size))
                        return resolved_cvar
                    if (
                        isinstance(resolved_variable, SimStackVariable)
                        and isinstance(access_size, int)
                        and resolved_offset == target_offset
                        and resolved_size == access_size
                    ):
                        return resolved_cvar
                if isinstance(access_size, int) and access_size >= 4:
                    return materialize_stack_cvar_at_offset(codegen, target_offset, access_size)
        type_ = getattr(node, "type", None)
        bits = getattr(type_, "size", None)
        if bits not in {8, 16}:
            return node
        return make_stack_deref(cvar, extra_offset, bits)

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    if replace_c_children(root, transform):
        changed = True

    return changed
