from __future__ import annotations

import contextlib
import re

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable


def _resolve_stack_cvar_at_offset(codegen, offset: int, *, stack_slot_identity_for_variable):
    if getattr(codegen, "cfunc", None) is None:
        return None
    if not isinstance(offset, int):
        return None

    arg_candidates: list[tuple[object, object]] = []
    arg_variable_ids = {
        id(getattr(arg, "variable", None))
        for arg in getattr(codegen.cfunc, "arg_list", ()) or ()
        if getattr(arg, "variable", None) is not None
    }
    arg_slot_identities = {
        stack_slot_identity_for_variable(getattr(arg, "variable", None))
        for arg in getattr(codegen.cfunc, "arg_list", ()) or ()
        if isinstance(getattr(arg, "variable", None), SimStackVariable)
    }
    arg_slot_identities.discard(None)
    for arg in getattr(codegen.cfunc, "arg_list", ()) or ():
        variable = getattr(arg, "variable", None)
        if isinstance(variable, SimStackVariable):
            arg_candidates.append((variable, arg))

    best_exact = None
    best_exact_score = None
    best_covering = None
    best_covering_score = None

    def _stack_name_is_generic(name: object) -> bool:
        return isinstance(name, str) and re.fullmatch(
            r"(?:arg_\d+|s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)",
            name,
        ) is not None

    def _stack_candidate_score(variable, cvar, *, exact: bool):
        identity = stack_slot_identity_for_variable(variable)
        if identity is None:
            return (-1, -1, -1, -1, -1)
        variable_name = getattr(variable, "name", None)
        cvar_name = getattr(cvar, "name", None)
        unified_name = getattr(getattr(cvar, "unified_variable", None), "name", None)
        preferred_name = next(
            (
                name
                for name in (variable_name, cvar_name, unified_name)
                if isinstance(name, str) and name and not _stack_name_is_generic(name)
            ),
            None,
        )
        is_arg_variable = 1 if id(variable) in arg_variable_ids else 0
        is_arg_slot = 1 if identity in arg_slot_identities else 0
        has_preferred_name = 1 if preferred_name is not None else 0
        size = getattr(variable, "size", None)
        size_rank = -size if isinstance(size, int) else 0
        exact_rank = 1 if exact else 0
        return (exact_rank, is_arg_variable, is_arg_slot, has_preferred_name, size_rank, -getattr(variable, "offset", 0))

    candidates = list(arg_candidates)
    candidates.extend(list(getattr(codegen.cfunc, "variables_in_use", {}).items()))

    for variable, cvar in candidates:
        if not isinstance(variable, SimStackVariable):
            continue
        identity = stack_slot_identity_for_variable(variable)
        if identity is None:
            continue

        base_offset = getattr(variable, "offset", None)
        size = getattr(variable, "size", None)
        if not isinstance(base_offset, int) or not isinstance(size, int):
            continue

        if base_offset == offset:
            score = _stack_candidate_score(variable, cvar, exact=True)
            if best_exact_score is None or score > best_exact_score:
                best_exact = cvar
                best_exact_score = score
            continue

        if base_offset <= offset < base_offset + size:
            score = _stack_candidate_score(variable, cvar, exact=False)
            if best_covering_score is None or score > best_covering_score:
                best_covering = cvar
                best_covering_score = score

    if best_exact is not None:
        return best_exact
    return best_covering


def _materialize_stack_cvar_at_offset(
    codegen,
    offset: int,
    size: int = 2,
    *,
    resolve_stack_cvar_at_offset,
    promote_direct_stack_cvariable,
    stack_type_for_size,
):
    if getattr(codegen, "cfunc", None) is None:
        return None
    if not isinstance(offset, int):
        return None

    resolved = resolve_stack_cvar_at_offset(codegen, offset)
    resolved_variable = getattr(resolved, "variable", None)
    if isinstance(resolved_variable, SimStackVariable) and getattr(resolved_variable, "offset", None) == offset:
        target_type = stack_type_for_size(size)
        promote_direct_stack_cvariable(codegen, resolved, size, target_type)
        return resolved

    target_type = stack_type_for_size(size)
    variable = SimStackVariable(
        offset,
        size,
        base="bp",
        name=_stack_object_name(offset),
        region=getattr(codegen.cfunc, "addr", None),
    )
    cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=codegen)

    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        variables_in_use[variable] = cvar

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        unified_locals[variable] = {(cvar, target_type)}

    stack_local_candidates = getattr(codegen, "_inertia_stack_local_declaration_candidates", None)
    if isinstance(stack_local_candidates, dict):
        stack_local_candidates[variable] = cvar

    sort_local_vars = getattr(codegen.cfunc, "sort_local_vars", None)
    if callable(sort_local_vars):
        with contextlib.suppress(Exception):
            sort_local_vars()

    return cvar


def _canonicalize_stack_cvar_expr(
    expr,
    codegen,
    *,
    unwrap_c_casts,
    resolve_stack_cvar_at_offset,
    active_expr_ids: set[int] | None = None,
):
    expr = unwrap_c_casts(expr)
    if active_expr_ids is None:
        active_expr_ids = set()
    expr_id = id(expr)
    if expr_id in active_expr_ids:
        return expr
    active_expr_ids.add(expr_id)
    if isinstance(expr, structured_c.CVariable):
        variable = getattr(expr, "variable", None)
        if isinstance(variable, SimStackVariable):
            offset = getattr(variable, "offset", None)
            if isinstance(offset, int):
                resolved = resolve_stack_cvar_at_offset(codegen, offset)
                if isinstance(resolved, structured_c.CVariable):
                    active_expr_ids.discard(expr_id)
                    return resolved
                resolved_variable = getattr(resolved, "variable", None)
                if isinstance(resolved_variable, SimStackVariable):
                    variable_type = getattr(resolved, "variable_type", None) or getattr(expr, "variable_type", None)
                    active_expr_ids.discard(expr_id)
                    return structured_c.CVariable(resolved_variable, variable_type=variable_type, codegen=codegen)
        active_expr_ids.discard(expr_id)
        return expr
    if isinstance(expr, structured_c.CUnaryOp):
        operand = _canonicalize_stack_cvar_expr(
            expr.operand,
            codegen,
            unwrap_c_casts=unwrap_c_casts,
            resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
            active_expr_ids=active_expr_ids,
        )
        if operand is not expr.operand:
            active_expr_ids.discard(expr_id)
            return structured_c.CUnaryOp(expr.op, operand, codegen=getattr(expr, "codegen", None))
        active_expr_ids.discard(expr_id)
        return expr
    if isinstance(expr, structured_c.CBinaryOp):
        lhs = _canonicalize_stack_cvar_expr(
            expr.lhs,
            codegen,
            unwrap_c_casts=unwrap_c_casts,
            resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
            active_expr_ids=active_expr_ids,
        )
        rhs = _canonicalize_stack_cvar_expr(
            expr.rhs,
            codegen,
            unwrap_c_casts=unwrap_c_casts,
            resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
            active_expr_ids=active_expr_ids,
        )
        if lhs is not expr.lhs or rhs is not expr.rhs:
            active_expr_ids.discard(expr_id)
            return structured_c.CBinaryOp(expr.op, lhs, rhs, codegen=getattr(expr, "codegen", None))
        active_expr_ids.discard(expr_id)
        return expr
    if isinstance(expr, structured_c.CTypeCast):
        inner = _canonicalize_stack_cvar_expr(
            expr.expr,
            codegen,
            unwrap_c_casts=unwrap_c_casts,
            resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
            active_expr_ids=active_expr_ids,
        )
        if inner is not expr.expr:
            active_expr_ids.discard(expr_id)
            return structured_c.CTypeCast(None, expr.type, inner, codegen=getattr(expr, "codegen", None))
        active_expr_ids.discard(expr_id)
        return expr
    active_expr_ids.discard(expr_id)
    return expr


def _canonicalize_stack_cvars(codegen, *, replace_c_children, canonicalize_stack_cvar_expr) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def transform(node):
        nonlocal changed
        if not isinstance(node, structured_c.CVariable):
            return node
        canonical = canonicalize_stack_cvar_expr(node, codegen)
        if canonical is not node:
            changed = True
            return canonical
        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    if replace_c_children(root, transform):
        changed = True

    return changed


def _resolve_stack_cvar_from_addr_expr(
    project,
    codegen,
    addr_expr,
    *,
    classify_segmented_addr_expr,
    resolve_stack_cvar_at_offset,
    promote_direct_stack_cvariable,
    materialize_stack_cvar_at_offset,
    stack_type_for_size,
):
    classified = classify_segmented_addr_expr(addr_expr, project)
    if classified is None or classified.kind != "stack" or classified.cvar is None:
        return None

    variable = getattr(classified.cvar, "variable", None)
    if not isinstance(variable, SimStackVariable):
        return None

    target_offset = getattr(variable, "offset", None)
    if not isinstance(target_offset, int):
        return None

    resolved_offset = target_offset + classified.extra_offset
    resolved = resolve_stack_cvar_at_offset(codegen, resolved_offset)
    resolved_variable = getattr(resolved, "variable", None)
    if isinstance(resolved_variable, SimStackVariable) and getattr(resolved_variable, "offset", None) == resolved_offset:
        promote_direct_stack_cvariable(codegen, resolved, 2, stack_type_for_size(2))
        return resolved
    return materialize_stack_cvar_at_offset(codegen, resolved_offset, 2)


def _stack_object_name(offset: int) -> str:
    if offset >= 0:
        return f"arg_{offset:x}"
    return f"local_{-offset:x}"
