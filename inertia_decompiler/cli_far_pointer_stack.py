"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from functools import partial
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from .cli_access_object_hints import BaseKey
from .cli_storage_objects import (
    EvidenceProfiles,
    StableHints,
    build_storage_object_artifact,
    storage_object_record_for_key,
)


class _CFunctionLike(Protocol):
    """Structured C function surface needed by far-pointer stack coalescing."""

    addr: int
    statements: object


class _CodegenLike(Protocol):
    """Codegen surface needed by far-pointer stack coalescing."""

    cfunc: _CFunctionLike | None


class _ProjectLike(Protocol):
    """Project surface used by far-pointer stack coalescing."""

    _inertia_access_traits: object


class _AliasStorageLike(Protocol):
    """Alias-storage summary needed to prove far-pointer stack pieces join."""

    identity: tuple[object, ...] | None

    def needs_synthesis(self) -> bool:
        """Return whether storage identity is too synthetic for this rewrite."""
        ...

    def can_join(self, other: object) -> bool:
        """Return whether two storage identities are adjacent compatible pieces."""
        ...


def _build_copy_aliases(
    statements: object,
    *,
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    unwrap_c_casts: Callable[[object], object],
    expr_is_safe_inline_candidate: Callable[[object], bool],
    expr_is_bare_storage_alias: Callable[[object], bool],
    member_offset_for_variable: Callable[[object], int | None],
    stack_variable_is_promoted: Callable[[object], bool],
) -> dict[int, object]:
    def _impl() -> dict[int, object]:
        copy_aliases: dict[int, object] = {}
        for _ in range(3):
            changed_alias = False
            for walk_node in iter_c_nodes_deep(statements):
                classified = _classify_copy_assignment(
                    walk_node,
                    copy_aliases,
                    unwrap_c_casts=unwrap_c_casts,
                    expr_is_safe_inline_candidate=expr_is_safe_inline_candidate,
                    expr_is_bare_storage_alias=expr_is_bare_storage_alias,
                )
                if classified is None:
                    continue
                lhs_var, resolved_rhs = classified
                lhs_member_offset = member_offset_for_variable(lhs_var)
                if lhs_member_offset is not None and not stack_variable_is_promoted(lhs_var):
                    continue
                if copy_aliases.get(id(lhs_var)) != resolved_rhs:
                    copy_aliases[id(lhs_var)] = resolved_rhs
                    changed_alias = True
            if not changed_alias:
                break
        return copy_aliases

    return _impl()


def _classify_copy_assignment(
    walk_node: object,
    copy_aliases: dict[int, object],
    *,
    unwrap_c_casts: Callable[[object], object],
    expr_is_safe_inline_candidate: Callable[[object], bool],
    expr_is_bare_storage_alias: Callable[[object], bool],
) -> tuple[object, object] | None:
    """Return ``(lhs_var, resolved_rhs)`` when the node records a copy alias, or ``None``."""
    if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(
        walk_node.lhs, structured_c.CVariable
    ):
        return None
    # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
    lhs_var = getattr(walk_node.lhs, "variable", None)
    if lhs_var is None:
        return None
    rhs = unwrap_c_casts(walk_node.rhs)
    resolved_rhs = None
    if isinstance(rhs, structured_c.CVariable):
        # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
        rhs_var = getattr(rhs, "variable", None)
        if rhs_var is not None:
            resolved_rhs = copy_aliases.get(id(rhs_var))
            if resolved_rhs is None:
                resolved_rhs = rhs
    # Dynamic codegen boundary: constant-like values may be carried by generated AST nodes.
    elif (getattr(rhs, "value", None) is not None and isinstance(getattr(rhs, "value", None), int)) or expr_is_safe_inline_candidate(rhs):
        resolved_rhs = rhs
    if resolved_rhs is not None and expr_is_bare_storage_alias(resolved_rhs):
        resolved_rhs = None
    if resolved_rhs is None:
        return None
    return lhs_var, resolved_rhs


def _source_score(_cvar: object, expr: object) -> tuple[int, int, int]:
    def _impl() -> tuple[int, int, int]:
        current_expr = _unwrap_expr_identity(expr)
        # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
        variable = getattr(current_expr, "variable", None)
        # Dynamic codegen boundary: names may live on either CVariable or SimVariable payloads.
        name = getattr(variable, "name", None) or getattr(current_expr, "name", None)
        generic_name = isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None
        if isinstance(variable, SimStackVariable):
            return (0 if not generic_name else 2, variable.offset, variable.size)
        if isinstance(variable, SimMemoryVariable):
            return (0 if not generic_name else 2, variable.addr, variable.size)
        if isinstance(variable, SimRegisterVariable):
            return (3 if generic_name else 1, variable.reg, variable.size)
        if isinstance(current_expr, structured_c.CConstant):
            return (4, int(current_expr.value) if isinstance(current_expr.value, int) else 0, 0)
        return (4, 0, 0)

    return _impl()


def _unwrap_expr_identity(expr: object) -> object:
    return expr


def _build_far_pointer_aliases(
    statements: object,
    *,
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    unwrap_c_casts: Callable[[object], object],
    describe_alias_storage: Callable[[object], _AliasStorageLike],
    expr_is_safe_inline_candidate: Callable[[object], bool],
    resolve_alias_expr: Callable[[object], object],
    member_offset_for_variable: Callable[[object], int | None],
    stack_variable_is_promoted: Callable[[object], bool],
    expr_uses_promoted_stack_storage: Callable[[object], bool],
    make_mk_fp: Callable[[object, object], object],
    codegen: _CodegenLike,
) -> dict[int, object]:
    def _impl() -> dict[int, object]:
        groups = _collect_far_pointer_groups(
            statements,
            iter_c_nodes_deep=iter_c_nodes_deep,
            unwrap_c_casts=unwrap_c_casts,
            describe_alias_storage=describe_alias_storage,
            expr_is_safe_inline_candidate=expr_is_safe_inline_candidate,
        )
        far_pointer_aliases: dict[int, object] = {}
        for parts in groups.values():
            source_expr = _select_group_source_expr(
                parts,
                describe_alias_storage=describe_alias_storage,
                resolve_alias_expr=resolve_alias_expr,
                member_offset_for_variable=member_offset_for_variable,
                stack_variable_is_promoted=stack_variable_is_promoted,
                expr_uses_promoted_stack_storage=expr_uses_promoted_stack_storage,
                make_mk_fp=make_mk_fp,
                codegen=codegen,
            )
            if source_expr is None:
                continue
            for cvar, _rhs in parts["source"] + parts["zero"]:
                # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
                variable = getattr(cvar, "variable", None)
                if isinstance(variable, SimStackVariable):
                    far_pointer_aliases[id(variable)] = source_expr
        return far_pointer_aliases

    return _impl()


def _collect_far_pointer_groups(
    statements: object,
    *,
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    unwrap_c_casts: Callable[[object], object],
    describe_alias_storage: Callable[[object], _AliasStorageLike],
    expr_is_safe_inline_candidate: Callable[[object], bool],
) -> dict[object, dict[str, list[tuple[structured_c.CVariable, object]]]]:
    """Bucket stack-targeting copy assignments by their alias-storage identity."""
    groups: dict[object, dict[str, list[tuple[structured_c.CVariable, object]]]] = {}
    for walk_node in iter_c_nodes_deep(statements):
        if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(
            walk_node.lhs, structured_c.CVariable
        ):
            continue
        # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
        lhs_var = getattr(walk_node.lhs, "variable", None)
        if not isinstance(lhs_var, SimStackVariable):
            continue
        lhs_facts = describe_alias_storage(walk_node.lhs)
        if lhs_facts.identity is None or lhs_facts.needs_synthesis():
            continue
        rhs = unwrap_c_casts(walk_node.rhs)
        # Dynamic codegen boundary: constant-like values may be carried by generated AST nodes.
        if getattr(rhs, "value", None) is None and not expr_is_safe_inline_candidate(rhs):
            continue
        bucket = groups.setdefault(lhs_facts.identity, {"zero": [], "source": []})
        # Dynamic codegen boundary: constant-like values may be carried by generated AST nodes.
        if getattr(rhs, "value", None) == 0:
            bucket["zero"].append((walk_node.lhs, rhs))
        else:
            bucket["source"].append((walk_node.lhs, rhs))
    return groups


def _select_group_source_expr(
    parts: dict[str, list[tuple[structured_c.CVariable, object]]],
    *,
    describe_alias_storage: Callable[[object], _AliasStorageLike],
    resolve_alias_expr: Callable[[object], object],
    member_offset_for_variable: Callable[[object], int | None],
    stack_variable_is_promoted: Callable[[object], bool],
    expr_uses_promoted_stack_storage: Callable[[object], bool],
    make_mk_fp: Callable[[object, object], object],
    codegen: _CodegenLike,
) -> object | None:
    """Return the resolved far-pointer source expression for one identity group, or ``None``."""
    if not parts["source"]:
        return None
    candidate_exprs = [cvar for cvar, _rhs in parts["source"] + parts["zero"]]
    if not candidate_exprs:
        return None
    candidate_facts = [describe_alias_storage(expr) for expr in candidate_exprs]
    if any(facts.needs_synthesis() or facts.identity is None for facts in candidate_facts):
        return None
    if any(
        not left.can_join(right)
        for idx, left in enumerate(candidate_facts)
        for right in candidate_facts[idx + 1 :]
    ):
        return None
    source_expr = None
    for cvar, rhs in sorted(parts["source"], key=lambda item: _source_score(item[0], item[1])):
        # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
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
    return source_expr


def _coalesce_far_pointer_stack_expressions(
    project: _ProjectLike,
    codegen: _CodegenLike,
    *,
    unwrap_c_casts: Callable[[object], object],
    segment_reg_name: Callable[[object, _ProjectLike], str | None],
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    resolve_stack_cvar_at_offset: Callable[[_CodegenLike, int], object],
    build_access_trait_evidence_profiles: Callable[[dict[str, dict[BaseKey, object]]], EvidenceProfiles],
    build_stable_access_object_hints: Callable[[dict[str, dict[BaseKey, object]]], StableHints],
    access_trait_variable_key: Callable[[object], BaseKey | None],
    replace_c_children: Callable[[object, Callable[[object], object]], bool],
    describe_alias_storage: Callable[[object], _AliasStorageLike],
) -> bool:
    cfunc = codegen.cfunc
    if cfunc is None:
        return False

    # Ownership boundary:
    # This pass may coalesce already-proven far-pointer stack expressions into a
    # cleaner AST form. It must not invent stack-slot identity or repair unresolved
    # generic carrier chains. If a far-pointer expression still depends on raw
    # vvar_/ir_/tmp_ SS/BP carriers, fix that earlier in stack lowering.

    expr_is_safe_inline_candidate = partial(
        _expr_is_safe_inline_candidate,
        unwrap_c_casts=unwrap_c_casts,
        segment_reg_name=segment_reg_name,
        project=project,
    )

    make_mk_fp = partial(_make_mk_fp, codegen)

    expr_is_bare_storage_alias = partial(
        _expr_is_bare_storage_alias,
        unwrap_c_casts=unwrap_c_casts,
        segment_reg_name=segment_reg_name,
        project=project,
    )
    expr_uses_promoted_stack_storage = partial(
        _expr_uses_promoted_stack_storage,
        iter_c_nodes_deep=iter_c_nodes_deep,
        resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
        codegen=codegen,
    )
    stack_variable_is_promoted = partial(
        _stack_variable_is_promoted,
        resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
        codegen=codegen,
    )

    traits_cache = project._inertia_access_traits
    storage_object_artifact = None
    if isinstance(traits_cache, dict):
        traits = traits_cache.get(cfunc.addr)
        if isinstance(traits, dict):
            storage_object_artifact = build_storage_object_artifact(
                traits,
                build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
                build_stable_access_object_hints=build_stable_access_object_hints,
            )
    if not storage_object_artifact or not storage_object_artifact.records:
        return False

    member_offset_for_variable = partial(
        _member_offset_for_variable,
        access_trait_variable_key=access_trait_variable_key,
        storage_object_artifact=storage_object_artifact,
    )

    copy_aliases = _build_copy_aliases(
        cfunc.statements,
        iter_c_nodes_deep=iter_c_nodes_deep,
        unwrap_c_casts=unwrap_c_casts,
        expr_is_safe_inline_candidate=expr_is_safe_inline_candidate,
        expr_is_bare_storage_alias=expr_is_bare_storage_alias,
        member_offset_for_variable=member_offset_for_variable,
        stack_variable_is_promoted=stack_variable_is_promoted,
    )

    far_pointer_aliases: dict[int, object] = {}

    resolve_alias_expr = partial(
        _resolve_alias_expr,
        unwrap_c_casts=unwrap_c_casts,
        far_pointer_aliases=far_pointer_aliases,
        copy_aliases=copy_aliases,
    )

    far_pointer_aliases.update(
        _build_far_pointer_aliases(
            cfunc.statements,
            iter_c_nodes_deep=iter_c_nodes_deep,
            unwrap_c_casts=unwrap_c_casts,
            describe_alias_storage=describe_alias_storage,
            expr_is_safe_inline_candidate=expr_is_safe_inline_candidate,
            resolve_alias_expr=resolve_alias_expr,
            member_offset_for_variable=member_offset_for_variable,
            stack_variable_is_promoted=stack_variable_is_promoted,
            expr_uses_promoted_stack_storage=expr_uses_promoted_stack_storage,
            make_mk_fp=make_mk_fp,
            codegen=codegen,
        )
    )

    if not far_pointer_aliases:
        return False

    changed = False

    def transform(node: object) -> object:
        nonlocal changed
        did_change, new_node = _transform_far_pointer_add_node(
            node,
            resolve_alias_expr=resolve_alias_expr,
            expr_is_bare_storage_alias=expr_is_bare_storage_alias,
            expr_is_safe_inline_candidate=expr_is_safe_inline_candidate,
            make_mk_fp=make_mk_fp,
        )
        if did_change:
            changed = True
        return new_node

    root = cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        cfunc.statements = new_root
        root = new_root
        changed = True
    if replace_c_children(root, transform):
        changed = True
    return changed


def _expr_is_safe_inline_candidate(
    expr: object,
    *,
    unwrap_c_casts: Callable[[object], object],
    segment_reg_name: Callable[[object, _ProjectLike], str | None],
    project: _ProjectLike,
) -> bool:
    """Return whether the expression is safe to inline into an ``MK_FP`` form."""
    expr = unwrap_c_casts(expr)
    if isinstance(expr, (structured_c.CConstant, structured_c.CVariable)):
        if isinstance(expr, structured_c.CVariable):
            # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
            variable = getattr(expr, "variable", None)
            if isinstance(variable, SimStackVariable):
                return False
            if segment_reg_name(expr, project) is not None:
                return False
        return True
    if isinstance(expr, structured_c.CTypeCast):
        return _expr_is_safe_inline_candidate(
            expr.expr, unwrap_c_casts=unwrap_c_casts, segment_reg_name=segment_reg_name, project=project
        )
    if isinstance(expr, structured_c.CUnaryOp):
        return expr.op in {"Neg", "Not"} and _expr_is_safe_inline_candidate(
            expr.operand, unwrap_c_casts=unwrap_c_casts, segment_reg_name=segment_reg_name, project=project
        )
    if isinstance(expr, structured_c.CBinaryOp):
        if expr.op not in {"Add", "Sub", "Mul", "And", "Or", "Xor", "Shl", "Shr"}:
            return False
        return _expr_is_safe_inline_candidate(
            expr.lhs, unwrap_c_casts=unwrap_c_casts, segment_reg_name=segment_reg_name, project=project
        ) and _expr_is_safe_inline_candidate(
            expr.rhs, unwrap_c_casts=unwrap_c_casts, segment_reg_name=segment_reg_name, project=project
        )
    return False


def _expr_is_bare_storage_alias(
    expr: object,
    *,
    unwrap_c_casts: Callable[[object], object],
    segment_reg_name: Callable[[object, _ProjectLike], str | None],
    project: _ProjectLike,
) -> bool:
    """Return whether the expression is a bare stack/segment storage alias."""
    expr = unwrap_c_casts(expr)
    if not isinstance(expr, structured_c.CVariable):
        return False
    # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
    variable = getattr(expr, "variable", None)
    if isinstance(variable, SimStackVariable):
        return True
    return segment_reg_name(expr, project) is not None


def _expr_uses_promoted_stack_storage(
    expr: object,
    *,
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    resolve_stack_cvar_at_offset: Callable[[_CodegenLike, int], object],
    codegen: _CodegenLike,
    minimum_size: int = 4,
) -> bool:
    """Return whether every stack variable in the expression resolves to promoted storage."""
    for walk_node in iter_c_nodes_deep(expr):
        if not isinstance(walk_node, structured_c.CVariable):
            continue
        # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
        variable = getattr(walk_node, "variable", None)
        if not isinstance(variable, SimStackVariable):
            continue
        if variable.size >= minimum_size:
            continue
        offset = variable.offset
        if isinstance(offset, int):
            resolved = resolve_stack_cvar_at_offset(codegen, offset)
            # Dynamic codegen boundary: resolved CVariable payloads are supplied by angr codegen.
            resolved_variable = getattr(resolved, "variable", None)
            if isinstance(resolved_variable, SimStackVariable) and resolved_variable.size >= minimum_size:
                continue
        return False
    return True


def _stack_variable_is_promoted(
    variable: object,
    *,
    resolve_stack_cvar_at_offset: Callable[[_CodegenLike, int], object],
    codegen: _CodegenLike,
    minimum_size: int = 4,
) -> bool:
    """Return whether a stack variable is itself, or resolves to, promoted storage."""
    if not isinstance(variable, SimStackVariable):
        return False
    if variable.size >= minimum_size:
        return True
    offset = variable.offset
    if isinstance(offset, int):
        resolved = resolve_stack_cvar_at_offset(codegen, offset)
        # Dynamic codegen boundary: resolved CVariable payloads are supplied by angr codegen.
        resolved_variable = getattr(resolved, "variable", None)
        if isinstance(resolved_variable, SimStackVariable) and resolved_variable.size >= minimum_size:
            return True
    return False


def _member_offset_for_variable(
    variable: object,
    *,
    access_trait_variable_key: Callable[[object], BaseKey | None],
    storage_object_artifact: object,
) -> int | None:
    """Return the recorded member offset for a stack variable, or ``None``."""
    base_key = access_trait_variable_key(variable)
    if base_key is None:
        return None
    record = storage_object_record_for_key(storage_object_artifact, base_key)
    if record is None:
        return None
    return cast(int | None, record.primary_member_offset())


def _resolve_alias_expr(
    expr: object,
    *,
    unwrap_c_casts: Callable[[object], object],
    far_pointer_aliases: dict[int, object],
    copy_aliases: dict[int, object],
) -> object:
    """Chase copy/far-pointer aliases to the effective source expression."""
    expr = unwrap_c_casts(expr)
    seen: set[int] = set()
    while isinstance(expr, structured_c.CVariable):
        # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
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


def _transform_far_pointer_add_node(
    node: object,
    *,
    resolve_alias_expr: Callable[[object], object],
    expr_is_bare_storage_alias: Callable[[object], bool],
    expr_is_safe_inline_candidate: Callable[[object], bool],
    make_mk_fp: Callable[[object, object], object],
) -> tuple[bool, object]:
    """Rewrite a binary ``Add`` node into ``MK_FP`` form when aliases prove a far pointer."""
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Add":
        return False, node
    for lhs, rhs in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        lhs_unwrapped = resolve_alias_expr(lhs)
        if expr_is_bare_storage_alias(lhs_unwrapped):
            continue
        if (
            lhs_unwrapped is not lhs
            and expr_is_safe_inline_candidate(rhs)
            and not isinstance(lhs_unwrapped, (structured_c.CBinaryOp, structured_c.CFunctionCall))
        ):
            return True, make_mk_fp(lhs_unwrapped, rhs)
        rhs_unwrapped = resolve_alias_expr(rhs)
        if expr_is_bare_storage_alias(rhs_unwrapped):
            continue
        if (
            rhs_unwrapped is not rhs
            and expr_is_safe_inline_candidate(lhs)
            and not isinstance(rhs_unwrapped, (structured_c.CBinaryOp, structured_c.CFunctionCall))
        ):
            return True, make_mk_fp(rhs_unwrapped, lhs)
    return False, node


def _make_mk_fp(
    codegen: _CodegenLike, segment_expr: object, offset_expr: object
) -> structured_c.CFunctionCall:
    """Build the ``MK_FP(segment, offset)`` call node bound to this codegen."""
    return structured_c.CFunctionCall("MK_FP", None, [segment_expr, offset_expr], codegen=codegen)
