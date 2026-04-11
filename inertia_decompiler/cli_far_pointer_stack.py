from __future__ import annotations

import re

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from .cli_storage_objects import (
    build_storage_object_artifact,
    storage_object_record_for_key,
)


def _coalesce_far_pointer_stack_expressions(
    project,
    codegen,
    *,
    unwrap_c_casts,
    segment_reg_name,
    iter_c_nodes_deep,
    resolve_stack_cvar_at_offset,
    build_access_trait_evidence_profiles,
    build_stable_access_object_hints,
    access_trait_variable_key,
    replace_c_children,
    describe_alias_storage,
):
    if getattr(codegen, "cfunc", None) is None:
        return False

    def expr_is_safe_inline_candidate(expr):
        expr = unwrap_c_casts(expr)
        if isinstance(expr, (structured_c.CConstant, structured_c.CVariable)):
            if isinstance(expr, structured_c.CVariable):
                variable = getattr(expr, "variable", None)
                if isinstance(variable, SimStackVariable):
                    return False
                if segment_reg_name(expr, project) is not None:
                    return False
            return True
        if isinstance(expr, structured_c.CTypeCast):
            return expr_is_safe_inline_candidate(expr.expr)
        if isinstance(expr, structured_c.CUnaryOp):
            return expr.op in {"Neg", "Not"} and expr_is_safe_inline_candidate(expr.operand)
        if isinstance(expr, structured_c.CBinaryOp):
            if expr.op not in {"Add", "Sub", "Mul", "And", "Or", "Xor", "Shl", "Shr"}:
                return False
            return expr_is_safe_inline_candidate(expr.lhs) and expr_is_safe_inline_candidate(expr.rhs)
        return False

    def make_mk_fp(segment_expr, offset_expr):
        return structured_c.CFunctionCall("MK_FP", None, [segment_expr, offset_expr], codegen=codegen)

    def expr_is_bare_storage_alias(expr) -> bool:
        expr = unwrap_c_casts(expr)
        if not isinstance(expr, structured_c.CVariable):
            return False
        variable = getattr(expr, "variable", None)
        if isinstance(variable, SimStackVariable):
            return True
        return segment_reg_name(expr, project) is not None

    def expr_uses_promoted_stack_storage(expr, minimum_size: int = 4) -> bool:
        for walk_node in iter_c_nodes_deep(expr):
            if not isinstance(walk_node, structured_c.CVariable):
                continue
            variable = getattr(walk_node, "variable", None)
            if not isinstance(variable, SimStackVariable):
                continue
            if getattr(variable, "size", 0) >= minimum_size:
                continue
            offset = getattr(variable, "offset", None)
            if isinstance(offset, int):
                resolved = resolve_stack_cvar_at_offset(codegen, offset)
                resolved_variable = getattr(resolved, "variable", None)
                if isinstance(resolved_variable, SimStackVariable) and getattr(resolved_variable, "size", 0) >= minimum_size:
                    continue
            return False
        return True

    def stack_variable_is_promoted(variable, minimum_size: int = 4) -> bool:
        if not isinstance(variable, SimStackVariable):
            return False
        if getattr(variable, "size", 0) >= minimum_size:
            return True
        offset = getattr(variable, "offset", None)
        if isinstance(offset, int):
            resolved = resolve_stack_cvar_at_offset(codegen, offset)
            resolved_variable = getattr(resolved, "variable", None)
            if isinstance(resolved_variable, SimStackVariable) and getattr(resolved_variable, "size", 0) >= minimum_size:
                return True
        return False

    traits_cache = getattr(project, "_inertia_access_traits", None)
    storage_object_artifact = None
    if isinstance(traits_cache, dict):
        traits = traits_cache.get(getattr(codegen.cfunc, "addr", None))
        if isinstance(traits, dict):
            storage_object_artifact = build_storage_object_artifact(
                traits,
                build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
                build_stable_access_object_hints=build_stable_access_object_hints,
            )
    if not storage_object_artifact or not storage_object_artifact.records:
        return False

    def member_offset_for_variable(variable) -> int | None:
        base_key = access_trait_variable_key(variable)
        if base_key is None:
            return None
        record = storage_object_record_for_key(storage_object_artifact, base_key)
        if record is None:
            return None
        return record.primary_member_offset()

    copy_aliases: dict[int, object] = {}
    for _ in range(3):
        changed_alias = False
        for walk_node in iter_c_nodes_deep(codegen.cfunc.statements):
            if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                continue
            lhs_var = getattr(walk_node.lhs, "variable", None)
            if lhs_var is None:
                continue
            rhs = unwrap_c_casts(walk_node.rhs)
            resolved_rhs = None
            if isinstance(rhs, structured_c.CVariable):
                rhs_var = getattr(rhs, "variable", None)
                if rhs_var is not None:
                    resolved_rhs = copy_aliases.get(id(rhs_var))
                    if resolved_rhs is None:
                        resolved_rhs = rhs
            elif getattr(rhs, "value", None) is not None and isinstance(getattr(rhs, "value", None), int):
                resolved_rhs = rhs
            elif expr_is_safe_inline_candidate(rhs):
                resolved_rhs = rhs
            if resolved_rhs is not None and expr_is_bare_storage_alias(resolved_rhs):
                resolved_rhs = None
            if resolved_rhs is None:
                continue
            lhs_member_offset = member_offset_for_variable(lhs_var)
            if lhs_member_offset is not None and not stack_variable_is_promoted(lhs_var):
                continue
            if copy_aliases.get(id(lhs_var)) != resolved_rhs:
                copy_aliases[id(lhs_var)] = resolved_rhs
                changed_alias = True
        if not changed_alias:
            break

    far_pointer_aliases: dict[int, object] = {}

    def resolve_alias_expr(expr):
        expr = unwrap_c_casts(expr)
        seen: set[int] = set()
        while isinstance(expr, structured_c.CVariable):
            variable = getattr(expr, "variable", None)
            if variable is None:
                break
            key = id(variable)
            if key in seen:
                break
            seen.add(key)
            if key in far_pointer_aliases:
                expr = far_pointer_aliases[key]
                continue
            alias_expr = copy_aliases.get(key)
            if alias_expr is None:
                break
            expr = unwrap_c_casts(alias_expr)
        return expr

    groups: dict[object, dict[str, list[tuple[structured_c.CVariable, object]]]] = {}
    for walk_node in iter_c_nodes_deep(codegen.cfunc.statements):
        if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
            continue
        lhs_var = getattr(walk_node.lhs, "variable", None)
        if not isinstance(lhs_var, SimStackVariable):
            continue
        lhs_facts = describe_alias_storage(walk_node.lhs)
        if lhs_facts.identity is None or lhs_facts.needs_synthesis():
            continue
        rhs = unwrap_c_casts(walk_node.rhs)
        if getattr(rhs, "value", None) is None and not expr_is_safe_inline_candidate(rhs):
            continue
        bucket = groups.setdefault(lhs_facts.identity, {"zero": [], "source": []})
        if getattr(rhs, "value", None) == 0:
            bucket["zero"].append((walk_node.lhs, rhs))
        else:
            bucket["source"].append((walk_node.lhs, rhs))

    def source_score(_cvar, expr) -> tuple[int, int, int]:
        expr = unwrap_c_casts(expr)
        variable = getattr(expr, "variable", None)
        name = getattr(variable, "name", None) or getattr(expr, "name", None)
        generic_name = isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None
        if isinstance(variable, SimStackVariable):
            return (0 if not generic_name else 2, getattr(variable, "offset", 0), getattr(variable, "size", 0))
        if isinstance(variable, SimMemoryVariable):
            return (0 if not generic_name else 2, getattr(variable, "addr", 0), getattr(variable, "size", 0))
        if isinstance(variable, SimRegisterVariable):
            return (3 if generic_name else 1, getattr(variable, "reg", 0), getattr(variable, "size", 0))
        if isinstance(expr, structured_c.CConstant):
            return (4, int(expr.value) if isinstance(expr.value, int) else 0, 0)
        return (4, 0, 0)

    for _storage_identity, parts in groups.items():
        if not parts["source"]:
            continue
        candidate_exprs = [cvar for cvar, _rhs in parts["source"] + parts["zero"]]
        if not candidate_exprs:
            continue
        candidate_facts = [describe_alias_storage(expr) for expr in candidate_exprs]
        if any(facts.needs_synthesis() or facts.identity is None for facts in candidate_facts):
            continue
        if any(
            not left.can_join(right)
            for idx, left in enumerate(candidate_facts)
            for right in candidate_facts[idx + 1 :]
        ):
            continue
        source_expr = None
        for cvar, rhs in sorted(parts["source"], key=lambda item: source_score(item[0], item[1])):
            variable = getattr(cvar, "variable", None)
            if not isinstance(variable, SimStackVariable):
                continue
            source_expr = resolve_alias_expr(rhs)
            member_offset = member_offset_for_variable(variable)
            if member_offset is not None:
                if not stack_variable_is_promoted(variable):
                    continue
                if not expr_uses_promoted_stack_storage(source_expr):
                    continue
                source_expr = make_mk_fp(
                    source_expr,
                    structured_c.CConstant(member_offset, SimTypeShort(False), codegen=codegen),
                )
            break
        if source_expr is None:
            continue
        for cvar, _rhs in parts["source"] + parts["zero"]:
            variable = getattr(cvar, "variable", None)
            if not isinstance(variable, SimStackVariable):
                continue
            far_pointer_aliases[id(variable)] = source_expr

    if not far_pointer_aliases:
        return False

    changed = False

    def transform(node):
        nonlocal changed
        if not isinstance(node, structured_c.CBinaryOp) or node.op != "Add":
            return node
        for lhs, rhs in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            lhs_unwrapped = resolve_alias_expr(lhs)
            if expr_is_bare_storage_alias(lhs_unwrapped):
                continue
            if (
                lhs_unwrapped is not lhs
                and expr_is_safe_inline_candidate(rhs)
                and not isinstance(lhs_unwrapped, (structured_c.CBinaryOp, structured_c.CFunctionCall))
            ):
                changed = True
                return make_mk_fp(lhs_unwrapped, rhs)
            rhs_unwrapped = resolve_alias_expr(rhs)
            if expr_is_bare_storage_alias(rhs_unwrapped):
                continue
            if (
                rhs_unwrapped is not rhs
                and expr_is_safe_inline_candidate(lhs)
                and not isinstance(rhs_unwrapped, (structured_c.CBinaryOp, structured_c.CFunctionCall))
            ):
                changed = True
                return make_mk_fp(rhs_unwrapped, lhs)
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
