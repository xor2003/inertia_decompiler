# cython: language_level=3, infer_types=True
"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations
import typing
import cython

import re
from collections.abc import Callable, Iterable
from functools import partial
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from inertia.lowering.object_lowering import BaseKey
from inertia.lowering.storage_objects import (
    EvidenceProfiles,
    StableHints,
    StorageObjectArtifact,
    build_storage_object_artifact,
    storage_object_record_for_key,
)
import operator
import builtins


class _CFunctionLike(Protocol):
    """Structured C function surface needed by far-pointer stack coalescing."""

    addr: cython.longlong
    statements: object


class _CodegenLike(Protocol):
    """Codegen surface needed by far-pointer stack coalescing."""

    cfunc: _CFunctionLike | None


class _ProjectLike(Protocol):
    """Project surface used by far-pointer stack coalescing."""

    _inertia_access_traits: object


class _AliasStorageLike(Protocol):
    """Alias-storage summary needed to prove far-pointer stack pieces join."""

    identity: object

    def needs_synthesis(self) -> cython.bint:
        """Return whether storage identity is too synthetic for this rewrite."""
        ...

    def can_join(self, other: object) -> cython.bint:
        """Return whether two storage identities are adjacent compatible pieces."""
        ...


def _build_copy_aliases(
    statements: object,
    *,
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    unwrap_c_casts: Callable[[object], object],
    expr_is_safe_inline_candidate: Callable[[object], cython.bint],
    expr_is_bare_storage_alias: Callable[[object], cython.bint],
    member_offset_for_variable: Callable[[object], int | None],
    stack_variable_is_promoted: Callable[[object], cython.bint],
) -> object:
    def _impl() -> object:
        classified: object
        lhs_member_offset: object
        walk_node: object
        copy_aliases: dict[cython.longlong, object] = {}
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
                if operator.ne(copy_aliases.get(id(lhs_var)), resolved_rhs):
                    copy_aliases[id(lhs_var)] = resolved_rhs
                    changed_alias = True
            if not changed_alias:
                break
        return copy_aliases

    return _impl()


@cython.ccall
def _classify_copy_assignment(
    walk_node: object,
    copy_aliases: object,
    *,
    unwrap_c_casts: Callable[[object], object],
    expr_is_safe_inline_candidate: Callable[[object], cython.bint],
    expr_is_bare_storage_alias: Callable[[object], cython.bint],
) -> object:
    """Return ``(lhs_var, resolved_rhs)`` when the node records a copy alias, or ``None``."""
    lhs_var: object
    resolved_rhs: object
    rhs_var: object
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


def _source_score(_cvar: object, expr: object) -> object:
    def _impl() -> tuple[cython.longlong, cython.longlong, cython.longlong]:
        variable: object
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


@cython.ccall
def _unwrap_expr_identity(expr: object) -> object:
    return expr


def _build_far_pointer_aliases(
    statements: object,
    *,
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    unwrap_c_casts: Callable[[object], object],
    describe_alias_storage: Callable[[object], _AliasStorageLike],
    expr_is_safe_inline_candidate: Callable[[object], cython.bint],
    resolve_alias_expr: Callable[[object], object],
    member_offset_for_variable: Callable[[object], int | None],
    stack_variable_is_promoted: Callable[[object], cython.bint],
    expr_uses_promoted_stack_storage: Callable[[object], cython.bint],
    make_mk_fp: Callable[[object, object], object],
    codegen: _CodegenLike,
) -> object:
    def _impl() -> object:
        source_expr: object
        variable: object
        _rhs: object
        cvar: object
        parts: object
        groups = _collect_far_pointer_groups(
            statements,
            iter_c_nodes_deep=iter_c_nodes_deep,
            unwrap_c_casts=unwrap_c_casts,
            describe_alias_storage=describe_alias_storage,
            expr_is_safe_inline_candidate=expr_is_safe_inline_candidate,
        )
        far_pointer_aliases: dict[cython.longlong, object] = {}
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


@cython.ccall
def _collect_far_pointer_groups(
    statements: object,
    *,
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    unwrap_c_casts: Callable[[object], object],
    describe_alias_storage: Callable[[object], _AliasStorageLike],
    expr_is_safe_inline_candidate: Callable[[object], cython.bint],
) -> object:
    """Bucket stack-targeting copy assignments by their alias-storage identity."""
    lhs_var: object
    walk_node: object
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
    parts: object,
    *,
    describe_alias_storage: Callable[[object], _AliasStorageLike],
    resolve_alias_expr: Callable[[object], object],
    member_offset_for_variable: Callable[[object], int | None],
    stack_variable_is_promoted: Callable[[object], cython.bint],
    expr_uses_promoted_stack_storage: Callable[[object], cython.bint],
    make_mk_fp: Callable[[object, object], object],
    codegen: _CodegenLike,
) -> object | None:
    """Return the resolved far-pointer source expression for one identity group, or ``None``."""
    member_offset: object
    variable: object
    cvar: object
    rhs: object
    if not parts["source"]:
        return None
    candidate_exprs = [cvar for cvar, _rhs in iter(parts["source"] + parts["zero"])]
    if not candidate_exprs:
        return None
    candidate_facts = [describe_alias_storage(expr) for expr in iter(candidate_exprs)]
    if any(facts.needs_synthesis() or facts.identity is None for facts in iter(candidate_facts)):
        return None
    if any(
        not left.can_join(right)
        for idx, left in builtins.iter(enumerate(candidate_facts))
        for right in iter(candidate_facts[idx + 1 :])
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
    replace_c_children: Callable[[object, Callable[[object], object]], cython.bint],
    describe_alias_storage: Callable[[object], _AliasStorageLike],
) -> cython.bint:
    cfunc: object
    traits: object
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

    far_pointer_aliases: dict[cython.longlong, object] = {}

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


@cython.ccall
def _expr_is_safe_inline_candidate(
    expr: object,
    *,
    unwrap_c_casts: Callable[[object], object],
    segment_reg_name: Callable[[object, _ProjectLike], str | None],
    project: _ProjectLike,
) -> cython.bint:
    """Return whether the expression is safe to inline into an ``MK_FP`` form."""
    variable: object
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


@cython.ccall
def _expr_is_bare_storage_alias(
    expr: object,
    *,
    unwrap_c_casts: Callable[[object], object],
    segment_reg_name: Callable[[object, _ProjectLike], str | None],
    project: _ProjectLike,
) -> cython.bint:
    """Return whether the expression is a bare stack/segment storage alias."""
    variable: object
    expr = unwrap_c_casts(expr)
    if not isinstance(expr, structured_c.CVariable):
        return False
    # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
    variable = getattr(expr, "variable", None)
    if isinstance(variable, SimStackVariable):
        return True
    return segment_reg_name(expr, project) is not None


@cython.ccall
def _expr_uses_promoted_stack_storage(
    expr: object,
    *,
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    resolve_stack_cvar_at_offset: Callable[[_CodegenLike, int], object],
    codegen: _CodegenLike,
    minimum_size: cython.longlong = 4,
) -> cython.bint:
    """Return whether every stack variable in the expression resolves to promoted storage."""
    resolved_variable: object
    variable: object
    walk_node: object
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


@cython.ccall
def _stack_variable_is_promoted(
    variable: object,
    *,
    resolve_stack_cvar_at_offset: Callable[[_CodegenLike, int], object],
    codegen: _CodegenLike,
    minimum_size: cython.longlong = 4,
) -> cython.bint:
    """Return whether a stack variable is itself, or resolves to, promoted storage."""
    resolved_variable: object
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


@cython.ccall
def _member_offset_for_variable(
    variable: object,
    *,
    access_trait_variable_key: Callable[[object], BaseKey | None],
    storage_object_artifact: StorageObjectArtifact,
) -> int | None:
    """Return the recorded member offset for a stack variable, or ``None``."""
    base_key: object
    record: object
    base_key = access_trait_variable_key(variable)
    if base_key is None:
        return None
    record = storage_object_record_for_key(storage_object_artifact, base_key)
    if record is None:
        return None
    return record.primary_member_offset()


@cython.ccall
def _resolve_alias_expr(
    expr: object,
    *,
    unwrap_c_casts: Callable[[object], object],
    far_pointer_aliases: object,
    copy_aliases: object,
) -> object:
    """Chase copy/far-pointer aliases to the effective source expression."""
    alias_expr: object
    variable: object
    expr = unwrap_c_casts(expr)
    seen: set[cython.longlong] = set()
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


@cython.ccall
def _transform_far_pointer_add_node(
    node: object,
    *,
    resolve_alias_expr: Callable[[object], object],
    expr_is_bare_storage_alias: Callable[[object], cython.bint],
    expr_is_safe_inline_candidate: Callable[[object], cython.bint],
    make_mk_fp: Callable[[object, object], object],
) -> tuple[cython.bint, object]:
    """Rewrite a binary ``Add`` node into ``MK_FP`` form when aliases prove a far pointer."""
    lhs: object
    rhs: object
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


@cython.ccall
def _make_mk_fp(
    codegen: _CodegenLike, segment_expr: object, offset_expr: object
) -> structured_c.CFunctionCall:
    """Build the ``MK_FP(segment, offset)`` call node bound to this codegen."""
    return structured_c.CFunctionCall("MK_FP", None, [segment_expr, offset_expr], codegen=codegen)
