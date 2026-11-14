# cython: language_level=3, infer_types=True
"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations
import cython

import contextlib
import re
import typing
from collections.abc import Callable, Iterable
from typing import Any, TypeGuard, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeBottom
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
import operator
import builtins

_STACK_BP_PLACEHOLDER_RE = re.compile(
    r"<[^>\n]*\|Stack\s+(?P<base>bp)(?P<sign>[+-])0x(?P<offset>[0-9A-Fa-f]+),\s*(?P<size>\d+)\s*B>"
)

CNode = typing.TypeAliasType("CNode", object)
CVariableLike = typing.TypeAliasType("CVariableLike", object)
StackIdentity = typing.TypeAliasType("StackIdentity", object)


@cython.ccall
def _dynamic_codegen_attr(obj: object, name: object, default: Any = None) -> Any:  # noqa: ANN401
    """Read a dynamic angr structured-codegen attribute at the CLI boundary."""
    # Dynamic codegen boundary: angr C-AST nodes expose version-dependent fields.
    return getattr(obj, name, default)


@cython.ccall
def _materialized_stack_placeholder_variable(
    codegen: object,
    cvar: object,
    *,
    stack_type_for_size: Callable[[int], object],
) -> object:
    match: object
    variable_type: object
    variable = _dynamic_codegen_attr(cvar, "variable", None)
    placeholder_name = _dynamic_codegen_attr(variable, "name", None)
    if not isinstance(placeholder_name, str):
        placeholder_name = _dynamic_codegen_attr(cvar, "name", None)
    if not isinstance(placeholder_name, str):
        return None

    match = _STACK_BP_PLACEHOLDER_RE.search(placeholder_name)
    if match is None:
        return None

    offset = int(match.group("offset"), 16)
    if match.group("sign") == "-":
        offset = -offset
    size = max(int(match.group("size")), 1)
    region = _dynamic_codegen_attr(_dynamic_codegen_attr(codegen, "cfunc", None), "addr", None)
    stack_var = SimStackVariable(
        offset,
        size,
        base=match.group("base"),
        name=f"s_{offset & 0xFFFF:x}",
        region=region,
    )
    variable_type = _dynamic_codegen_attr(cvar, "variable_type", None)
    if variable_type is None:
        variable_type = stack_type_for_size(size)
    return stack_var, variable_type


@cython.ccall
def _is_materialized_named_stack_cvar(node: object) -> cython.bint:
    if not isinstance(node, structured_c.CVariable):
        return False
    variable = _dynamic_codegen_attr(node, "variable", None)
    if not isinstance(variable, SimStackVariable):
        return False
    name = _dynamic_codegen_attr(node, "name", None) or _dynamic_codegen_attr(variable, "name", None)
    if not isinstance(name, str):
        return False
    if _STACK_BP_PLACEHOLDER_RE.search(name) is not None:
        return False
    return re.fullmatch(r"(?:arg_\d+|local_\d+|s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)", name) is None


@cython.ccall
def _generic_stack_local_name(name: object) -> cython.bint:
    return (
        isinstance(name, str)
        and re.fullmatch(r"(?:arg_\d+|local_\d+|s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)", name) is not None
    )


@cython.ccall
def _stack_name_from_cvar(cvar: object) -> object:
    candidate: object
    for candidate in (
        _dynamic_codegen_attr(cvar, "name", None),
        _dynamic_codegen_attr(_dynamic_codegen_attr(cvar, "variable", None), "name", None),
        _dynamic_codegen_attr(_dynamic_codegen_attr(cvar, "unified_variable", None), "name", None),
    ):
        if isinstance(candidate, str) and candidate:
            return candidate
    return None


@cython.ccall
def _set_stack_cvar_name(cvar: object, name: object) -> cython.bint:
    target: object
    changed = False
    for target in (
        _dynamic_codegen_attr(cvar, "variable", None),
        _dynamic_codegen_attr(cvar, "unified_variable", None),
    ):
        if target is None:
            continue
        with contextlib.suppress(Exception):
            if operator.ne(_dynamic_codegen_attr(target, "name", None), name):
                typing.cast(typing.Any, target).name = name
                changed = True
    with contextlib.suppress(Exception):
        if operator.ne(_dynamic_codegen_attr(cvar, "name", None), name):
            typing.cast(typing.Any, cvar).name = name
            changed = True
    return changed


@cython.ccall
def _canonical_stack_declaration_name(
    variable: object,
    *,
    identity: object,
    arg_variables: object,
    arg_identities: object,
) -> object:
    if not isinstance(variable, SimStackVariable):
        return None
    offset = _dynamic_codegen_attr(identity, "offset", _dynamic_codegen_attr(variable, "offset", None))
    if not isinstance(offset, int):
        return None
    if id(variable) in arg_variables or identity in arg_identities:
        return f"arg_{offset:x}"
    if offset >= 0:
        return f"local_{offset:x}"
    return f"local_{-offset:x}"


@cython.ccall
def _normalize_generic_stack_cvar_name(
    cvar: object,
    *,
    identity: object,
    arg_variables: object,
    arg_identities: object,
) -> cython.bint:
    current = _stack_name_from_cvar(cvar)
    if not _generic_stack_local_name(current):
        return False
    new_name = _canonical_stack_declaration_name(
        _dynamic_codegen_attr(cvar, "variable", None),
        identity=identity,
        arg_variables=arg_variables,
        arg_identities=arg_identities,
    )
    if not isinstance(new_name, str) or not new_name or new_name == current:
        return False
    return _set_stack_cvar_name(cvar, new_name)


@cython.ccall
def _sync_unified_stack_local_names_from_live_cvars(
    *,
    cfunc: object,
    unified_locals: object,
    stack_slot_identity_for_variable: Callable[[object], object | None],
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
) -> cython.bint:
    root: object
    root = _dynamic_codegen_attr(cfunc, "statements", None)
    if root is None or not isinstance(unified_locals, dict):
        return False

    live_name_by_identity = _live_stack_name_by_identity(
        root, stack_slot_identity_for_variable, iter_c_nodes_deep
    )

    if not live_name_by_identity:
        return False

    return _sync_unified_local_names(
        unified_locals, live_name_by_identity, stack_slot_identity_for_variable
    )


@cython.ccall
def _live_stack_name_by_identity(
    root: object,
    stack_slot_identity_for_variable: Callable[[object], object | None],
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
) -> object:
    """Collect the first non-generic stack-local name per slot identity."""
    identity: object
    node: object
    live_name_by_identity: dict[object, str] = {}
    for node in iter_c_nodes_deep(root):
        if not _is_materialized_named_stack_cvar(node):
            continue
        variable = _dynamic_codegen_attr(node, "variable", None)
        identity = stack_slot_identity_for_variable(variable)
        if identity is None or identity in live_name_by_identity:
            continue
        name = _stack_name_from_cvar(node)
        if isinstance(name, str) and name and not _generic_stack_local_name(name):
            live_name_by_identity[identity] = name
    return live_name_by_identity


@cython.ccall
def _sync_unified_local_names(
    unified_locals: object,
    live_name_by_identity: object,
    stack_slot_identity_for_variable: Callable[[object], object | None],
) -> cython.bint:
    """Apply collected live names to unified-locals variables and cvar entries."""
    name: object
    cvar: object
    entries: object
    variable: object
    vartype: object
    changed = False
    for variable, entries in list(unified_locals.items()):
        identity = stack_slot_identity_for_variable(variable)
        name = live_name_by_identity.get(identity)
        if name is None:
            continue
        current = _dynamic_codegen_attr(variable, "name", None)
        if isinstance(current, str) and current and not _generic_stack_local_name(current) and operator.ne(current, name):
            continue
        with contextlib.suppress(Exception):
            if operator.ne(_dynamic_codegen_attr(variable, "name", None), name):
                cast(Any, variable).name = name
                changed = True
        if not isinstance(entries, set):
            continue
        rebuilt = set()
        for cvar, vartype in entries:
            changed = _set_stack_cvar_name(cvar, name) or changed
            rebuilt.add((cvar, vartype))
        unified_locals[variable] = rebuilt
    return changed


def _make_placeholder_canonicalizer(
    *,
    codegen: object,
    stack_type_for_size: Callable[[int], object],
    variables_in_use: object,
    stack_local_candidates: object,
    placeholder_cache: object,
    changed_ref: object,
) -> Callable[[object], object]:
    def _canonical_placeholder_cvar(node: object) -> object:
        replacement: object
        if not isinstance(node, structured_c.CVariable):
            return node
        replacement = _materialized_stack_placeholder_variable(
            codegen,
            node,
            stack_type_for_size=stack_type_for_size,
        )
        if replacement is None:
            return node
        stack_var, variable_type = replacement
        key = _dynamic_codegen_attr(_dynamic_codegen_attr(node, "variable", None), "name", None) or _dynamic_codegen_attr(
            node, "name", None
        )
        if isinstance(key, str) and key in placeholder_cache:
            return placeholder_cache[key]
        original_var = _dynamic_codegen_attr(node, "variable", None)
        try:
            node.variable = stack_var
        except Exception:
            replacement_cvar = structured_c.CVariable(stack_var, variable_type=variable_type, codegen=codegen)
            _record_placeholder_replacement(
                replacement_cvar, stack_var, key, original_var,
                variables_in_use=variables_in_use,
                stack_local_candidates=stack_local_candidates,
                placeholder_cache=placeholder_cache,
                changed_ref=changed_ref,
                drop_original_candidate=False,
            )
            return replacement_cvar
        typing.cast(typing.Any, node).variable_type = variable_type
        _record_placeholder_replacement(
            node, stack_var, key, original_var,
            variables_in_use=variables_in_use,
            stack_local_candidates=stack_local_candidates,
            placeholder_cache=placeholder_cache,
            changed_ref=changed_ref,
            drop_original_candidate=True,
        )
        return node

    return _canonical_placeholder_cvar


@cython.ccall
def _record_placeholder_replacement(
    replacement_cvar: object,
    replacement_var: object,
    key: object,
    original_var: object,
    *,
    variables_in_use: object,
    stack_local_candidates: object,
    placeholder_cache: object,
    changed_ref: object,
    drop_original_candidate: cython.bint,
) -> None:
    """Register one materialized placeholder in every tracking projection."""
    if isinstance(variables_in_use, dict):
        if original_var in variables_in_use:
            variables_in_use.pop(original_var, None)
        variables_in_use[replacement_var] = replacement_cvar
    if isinstance(stack_local_candidates, dict):
        if drop_original_candidate and original_var is not None:
            stack_local_candidates.pop(id(original_var), None)
        stack_local_candidates[id(replacement_var)] = (replacement_var, replacement_cvar)
    if isinstance(key, str):
        placeholder_cache[key] = replacement_cvar
    changed_ref["changed"] = True


def _prune_dead_placeholder_variables(
    *,
    cfunc: object,
    variables_in_use: object,
    stack_local_candidates: object,
    unified_locals: object,
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
) -> cython.bint:
    def _impl() -> cython.bint:
        root: object
        variable: object
        root = _dynamic_codegen_attr(cfunc, "statements", None)
        if not isinstance(variables_in_use, dict) or root is None:
            return False
        changed = False
        live_variable_ids = {
            id(_dynamic_codegen_attr(node, "variable", None))
            for node in builtins.iter(iter_c_nodes_deep(root))
            if isinstance(node, structured_c.CVariable) and _dynamic_codegen_attr(node, "variable", None) is not None
        }
        for variable in list(variables_in_use):
            name = _dynamic_codegen_attr(variable, "name", None)
            if not isinstance(name, str) or _STACK_BP_PLACEHOLDER_RE.search(name) is None:
                continue
            if id(variable) in live_variable_ids:
                continue
            variables_in_use.pop(variable, None)
            if isinstance(stack_local_candidates, dict):
                stack_local_candidates.pop(id(variable), None)
            if isinstance(unified_locals, dict):
                unified_locals.pop(variable, None)
            changed = True
        return changed

    return _impl()


@cython.ccall
def _materialize_unified_stack_locals(
    *,
    source_variables: Iterable[tuple[object, object]],
    unified_locals: object,
    arg_variables: object,
    arg_identities: object,
    existing_identities: object,
    stack_slot_identity_for_variable: Callable[[object], object | None],
    stack_type_for_size: Callable[[int], object],
) -> cython.bint:
    identity: object
    variable_type: object
    cvar: object
    variable: object
    changed = False
    for variable, cvar in source_variables:
        if not isinstance(variable, SimStackVariable):
            continue
        identity = stack_slot_identity_for_variable(variable)
        if id(variable) in arg_variables or identity in arg_identities:
            continue
        if _normalize_generic_stack_cvar_name(
            cvar,
            identity=identity,
            arg_variables=arg_variables,
            arg_identities=arg_identities,
        ):
            changed = True
        if identity is None or identity in existing_identities:
            continue
        variable_type = _dynamic_codegen_attr(cvar, "variable_type", None)
        if variable_type is None:
            variable_type = stack_type_for_size(_dynamic_codegen_attr(variable, "size", 0) or 2)
        unified_locals[variable] = {(cvar, variable_type)}
        existing_identities.add(identity)
        changed = True
    return changed


def _canonicalize_stack_placeholders_in_root(
    codegen: object,
    cfunc: object,
    root: object,
    *,
    canonicalize: Callable[[object], object],
    replace_c_children: Callable[[object, Callable[[object], object]], cython.bint],
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    stack_slot_identity_for_variable: Callable[[object], object | None],
    unified_locals: object,
    source_by_id: object,
    existing_identities: object,
    changed_ref: object,
) -> None:
    """Rewrite placeholder stack cvars in the root block and refresh evidence."""
    node: object
    cfunc_node = cast(Any, cfunc)
    new_root = canonicalize(root)
    if new_root is not root:
        cfunc_node.statements = new_root
        if hasattr(cfunc_node, "body"):
            cfunc_node.body = new_root
    if replace_c_children(cfunc_node.statements, canonicalize):
        changed_ref["changed"] = True
    existing_identities.update(
        identity
        for node in builtins.iter(iter_c_nodes_deep(cfunc_node.statements))
        if _is_materialized_named_stack_cvar(node)
        for identity in iter((stack_slot_identity_for_variable(_dynamic_codegen_attr(node, "variable", None)),))
        if identity is not None
    )
    for node in iter_c_nodes_deep(cfunc_node.statements):
        if not isinstance(node, structured_c.CVariable):
            continue
        variable = _dynamic_codegen_attr(node, "variable", None)
        if isinstance(variable, SimStackVariable):
            source_by_id.setdefault(id(variable), (variable, node))
    if _sync_unified_stack_local_names_from_live_cvars(
        cfunc=cfunc,
        unified_locals=unified_locals,
        stack_slot_identity_for_variable=stack_slot_identity_for_variable,
        iter_c_nodes_deep=iter_c_nodes_deep,
    ):
        changed_ref["changed"] = True
        typing.cast(typing.Any, codegen)._inertia_stack_declaration_name_synced_count_8616 = int(_dynamic_codegen_attr(codegen, "_inertia_stack_declaration_name_synced_count_8616", 0) or 0) + 1


@cython.ccall
def _stack_arg_identity_sets(
    cfunc: object,
    unified_locals: Iterable[object],
    stack_slot_identity_for_variable: Callable[[object], object | None],
) -> tuple[set[cython.longlong], set[object], set[object]]:
    """Build arg-variable ids, arg slot identities, and existing identities."""
    arg_variables = {
        id(_dynamic_codegen_attr(arg, "variable", None))
        for arg in iter(_dynamic_codegen_attr(cfunc, "arg_list", ()) or ())
        if _dynamic_codegen_attr(arg, "variable", None) is not None
    }
    arg_identities = {
        stack_slot_identity_for_variable(_dynamic_codegen_attr(arg, "variable", None))
        for arg in iter(_dynamic_codegen_attr(cfunc, "arg_list", ()) or ())
        if isinstance(_dynamic_codegen_attr(arg, "variable", None), SimStackVariable)
    }
    arg_identities.discard(None)
    existing_identities = {
        identity
        for variable in iter(unified_locals)
        for identity in iter((stack_slot_identity_for_variable(variable),))
        if identity is not None
    }
    return arg_variables, arg_identities, existing_identities


@cython.ccall
def _stack_source_by_id(
    cfunc: object,
    stack_local_candidates: object,
) -> object:
    """Merge declaration candidates and in-use vars into id -> (variable, cvar)."""
    cvar: object
    variable: object
    source_by_id: dict[cython.longlong, tuple[object, object]] = {}
    if isinstance(stack_local_candidates, dict):
        for variable, cvar in stack_local_candidates.values():
            source_by_id[id(variable)] = (variable, cvar)
    variables_in_use_obj = _dynamic_codegen_attr(cfunc, "variables_in_use", None)
    if isinstance(variables_in_use_obj, dict):
        for variable, cvar in variables_in_use_obj.items():
            source_by_id.setdefault(id(variable), (variable, cvar))
    return source_by_id


def _materialize_missing_stack_local_declarations(
    codegen: object,
    *,
    stack_slot_identity_for_variable: Callable[[object], object | None],
    stack_type_for_size: Callable[[int], object],
    replace_c_children: Callable[[object, Callable[[object], object]], cython.bint],
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
) -> cython.bint:
    def _impl() -> cython.bint:
        cfunc: object
        root: object
        cfunc = _dynamic_codegen_attr(codegen, "cfunc", None)
        if cfunc is None:
            return False

        unified_locals = _dynamic_codegen_attr(cfunc, "unified_local_vars", None)
        if not isinstance(unified_locals, dict):
            unified_locals = {}
            typing.cast(typing.Any, cfunc).unified_local_vars = unified_locals

        arg_variables, arg_identities, existing_identities = _stack_arg_identity_sets(
            cfunc, unified_locals, stack_slot_identity_for_variable
        )

        stack_local_candidates = _dynamic_codegen_attr(codegen, "_inertia_stack_local_declaration_candidates", None)
        source_by_id = _stack_source_by_id(cfunc, stack_local_candidates)

        changed_ref = {"changed": False}
        placeholder_cache: dict[str, structured_c.CVariable] = {}
        variables_in_use = _dynamic_codegen_attr(cfunc, "variables_in_use", None)
        _canonical_placeholder_cvar = _make_placeholder_canonicalizer(
            codegen=codegen,
            stack_type_for_size=stack_type_for_size,
            variables_in_use=variables_in_use,
            stack_local_candidates=stack_local_candidates,
            placeholder_cache=placeholder_cache,
            changed_ref=changed_ref,
        )

        root = _dynamic_codegen_attr(cfunc, "statements", None)
        if root is not None:
            _canonicalize_stack_placeholders_in_root(
                codegen,
                cfunc,
                root,
                canonicalize=_canonical_placeholder_cvar,
                replace_c_children=replace_c_children,
                iter_c_nodes_deep=iter_c_nodes_deep,
                stack_slot_identity_for_variable=stack_slot_identity_for_variable,
                unified_locals=unified_locals,
                source_by_id=source_by_id,
                existing_identities=existing_identities,
                changed_ref=changed_ref,
            )
        if _prune_dead_placeholder_variables(
            cfunc=cfunc,
            variables_in_use=variables_in_use,
            stack_local_candidates=stack_local_candidates,
            unified_locals=unified_locals,
            iter_c_nodes_deep=iter_c_nodes_deep,
        ):
            changed_ref["changed"] = True

        if _materialize_unified_stack_locals(
            source_variables=tuple(source_by_id.values()),
            unified_locals=unified_locals,
            arg_variables=arg_variables,
            arg_identities=arg_identities,
            existing_identities=existing_identities,
            stack_slot_identity_for_variable=stack_slot_identity_for_variable,
            stack_type_for_size=stack_type_for_size,
        ):
            changed_ref["changed"] = True

        if changed_ref["changed"]:
            sort_local_vars = _dynamic_codegen_attr(cfunc, "sort_local_vars", None)
            if callable(sort_local_vars):
                with contextlib.suppress(Exception):
                    sort_local_vars()
        return changed_ref["changed"]

    return _impl()


def _dedupe_codegen_variable_names_8616(
    codegen: object, *, make_unique_identifier: Callable[[str, set[str]], str]
) -> cython.bint:
    def _impl() -> cython.bint:
        cfunc: object
        name: object
        cvar: object
        variable: object
        cfunc = _dynamic_codegen_attr(codegen, "cfunc", None)
        if cfunc is None:
            return False

        variables_in_use = _dynamic_codegen_attr(cfunc, "variables_in_use", None)
        unified_locals = _dynamic_codegen_attr(cfunc, "unified_local_vars", None)
        if not isinstance(variables_in_use, dict) and not isinstance(unified_locals, dict):
            return False

        ordered_items = _dedup_ordered_items(cfunc, variables_in_use, unified_locals)
        ordered_items.sort(key=_dedup_variable_sort_key)

        used_names: set[str] = set()
        seen_variables: set[cython.longlong] = set()
        changed = False

        for variable, cvar in ordered_items:
            if id(variable) in seen_variables:
                continue
            seen_variables.add(id(variable))
            _normalize_dedup_sort_ident(variable, cvar)
            name = _preferred_dedup_name(variable, cvar)
            if name is None:
                continue
            if name in used_names:
                name = make_unique_identifier(name, used_names)
            else:
                used_names.add(name)
            changed = _apply_dedup_name(variable, cvar, name) or changed

        if changed:
            sort_local_vars = _dynamic_codegen_attr(cfunc, "sort_local_vars", None)
            if callable(sort_local_vars):
                with contextlib.suppress(Exception):
                    sort_local_vars()
        return changed

    return _impl()


@cython.ccall
def _is_generic_dedup_name(name: object) -> cython.bint:
    """Return True for codegen's auto vNN/vvar_N placeholder names."""
    return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None


@cython.ccall
def _is_dedup_identifier(name: object) -> TypeGuard[str]:
    """Return True when the value is a valid C identifier."""
    return isinstance(name, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is not None


@cython.ccall
def _preferred_dedup_name(variable: object, cvar: object) -> object:
    """Pick the best available identifier across variable/cvar projections."""
    candidate: object
    candidates = [
        _dynamic_codegen_attr(variable, "name", None),
        _dynamic_codegen_attr(variable, "ident", None),
        _dynamic_codegen_attr(cvar, "name", None),
        _dynamic_codegen_attr(_dynamic_codegen_attr(cvar, "unified_variable", None), "name", None),
    ]
    for candidate in candidates:
        if _is_dedup_identifier(candidate) and not _is_generic_dedup_name(candidate):
            return candidate
    for candidate in candidates:
        if _is_dedup_identifier(candidate):
            return candidate
    return None


@cython.ccall
def _normalize_dedup_sort_ident(variable: object, cvar: object) -> None:
    """Give the variable an `ident` fallback so codegen sorting stays stable."""
    ident: object
    ident = _dynamic_codegen_attr(variable, "ident", None)
    if isinstance(ident, str):
        return
    fallback = _preferred_dedup_name(variable, cvar)
    if not isinstance(fallback, str) or not fallback:
        fallback = _dynamic_codegen_attr(variable, "name", None)
    if not isinstance(fallback, str) or not fallback:
        fallback = f"var_{id(variable):x}"
    with contextlib.suppress(Exception):
        typing.cast(typing.Any, variable).ident = fallback if ident is None else str(ident)


@cython.ccall
def _dedup_variable_sort_key(item: object) -> tuple[object, ...]:
    """Sort key ordering stack args, registers, memory, then leftovers by name."""
    variable, cvar = item
    variable_name = _dynamic_codegen_attr(variable, "name", None)
    cvar_name = _dynamic_codegen_attr(cvar, "name", None)
    variable_name_key = variable_name if isinstance(variable_name, str) else ""
    cvar_name_key = cvar_name if isinstance(cvar_name, str) else ""
    if isinstance(variable, SimStackVariable):
        offset = _dynamic_codegen_attr(variable, "offset", 0)
        size = _dynamic_codegen_attr(variable, "size", 0)
        return (
            0,
            0 if isinstance(offset, int) and offset > 0 else 1,
            offset if isinstance(offset, int) else 0,
            -size if isinstance(size, int) else 0,
            variable_name_key,
        )
    if isinstance(variable, SimRegisterVariable):
        reg = _dynamic_codegen_attr(variable, "reg", 0)
        return (
            1,
            reg if isinstance(reg, int) else 0,
            _dynamic_codegen_attr(variable, "size", 0) if isinstance(_dynamic_codegen_attr(variable, "size", 0), int) else 0,
            variable_name_key,
        )
    if isinstance(variable, SimMemoryVariable):
        addr = _dynamic_codegen_attr(variable, "addr", 0)
        return (
            2,
            addr if isinstance(addr, int) else 0,
            _dynamic_codegen_attr(variable, "size", 0) if isinstance(_dynamic_codegen_attr(variable, "size", 0), int) else 0,
            variable_name_key,
        )
    return (3, variable_name_key, cvar_name_key)


@cython.ccall
def _dedup_ordered_items(cfunc: object, variables_in_use: object, unified_locals: object) -> object:
    """Collect (variable, cvar) pairs from args, in-use, and unified locals."""
    variable: object
    arg: object
    cvars: object
    ordered_items = []
    for arg in _dynamic_codegen_attr(cfunc, "arg_list", ()) or ():
        variable = _dynamic_codegen_attr(arg, "variable", None)
        if variable is not None:
            ordered_items.append((variable, arg))
    ordered_items.extend(list(variables_in_use.items()) if isinstance(variables_in_use, dict) else [])
    if isinstance(unified_locals, dict):
        for variable, cvars in unified_locals.items():
            if variable not in variables_in_use and cvars:
                ordered_items.append((variable, next(iter(cvars))[0]))
    return ordered_items


@cython.ccall
def _apply_dedup_name(variable: object, cvar: object, new_name: object) -> cython.bint:
    """Write the deduped name across variable/cvar/unified projections."""
    unified: object
    changed = False
    if operator.ne(_dynamic_codegen_attr(variable, "name", None), new_name):
        typing.cast(typing.Any, variable).name = new_name
        changed = True
    if operator.ne(_dynamic_codegen_attr(cvar, "name", None), new_name):
        try:
            typing.cast(typing.Any, cvar).name = new_name
        except Exception:
            pass
        else:
            changed = True
    unified = _dynamic_codegen_attr(cvar, "unified_variable", None)
    if unified is not None and operator.ne(_dynamic_codegen_attr(unified, "name", None), new_name):
        unified.name = new_name
        changed = True
    return changed


def _materialize_missing_register_local_declarations(
    codegen: object,
    *,
    stack_slot_identity_for_variable: Callable[[object], object | None],
    stack_type_for_size: Callable[[int], object],
    structured_codegen_node: Callable[[object], cython.bint],
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
) -> cython.bint:
    def _impl() -> cython.bint:
        cfunc: object
        cvar: object
        variable: object
        cfunc = _dynamic_codegen_attr(codegen, "cfunc", None)
        if cfunc is None:
            return False

        unified_locals = _dynamic_codegen_attr(cfunc, "unified_local_vars", None)
        if not isinstance(unified_locals, dict):
            unified_locals = {}
            typing.cast(typing.Any, cfunc).unified_local_vars = unified_locals

        arg_variables = {
            id(_dynamic_codegen_attr(arg, "variable", None))
            for arg in iter(_dynamic_codegen_attr(cfunc, "arg_list", ()) or ())
            if _dynamic_codegen_attr(arg, "variable", None) is not None
        }

        def local_identity(variable: object) -> object:
            return _register_local_identity(variable, stack_slot_identity_for_variable)

        existing_identities = {
            identity for variable in iter(unified_locals) if (identity := local_identity(variable)) is not None
        }

        desired_segment_regs = {"cs", "ds", "es", "ss", "fs", "gs", "flags"}
        changed = False

        register_candidates = _register_declaration_candidates(cfunc, structured_codegen_node, iter_c_nodes_deep)

        for variable, cvar in register_candidates.values():
            changed = _materialize_register_candidate(
                variable,
                cvar,
                local_identity=local_identity,
                arg_variables=arg_variables,
                unified_locals=unified_locals,
                existing_identities=existing_identities,
                desired_segment_regs=desired_segment_regs,
                stack_type_for_size=stack_type_for_size,
            ) or changed

        if changed:
            sort_local_vars = _dynamic_codegen_attr(cfunc, "sort_local_vars", None)
            if callable(sort_local_vars):
                with contextlib.suppress(Exception):
                    sort_local_vars()
        return changed

    return _impl()


@cython.ccall
def _register_local_identity(
    variable: object,
    stack_slot_identity_for_variable: Callable[[object], object | None],
) -> object:
    """Compute the declaration identity key for stack/register variables."""
    identity: object
    if isinstance(variable, SimStackVariable):
        identity = stack_slot_identity_for_variable(variable)
        if identity is not None:
            return (
                "stack",
                _dynamic_codegen_attr(identity, "base", None),
                _dynamic_codegen_attr(identity, "offset", None),
                _dynamic_codegen_attr(variable, "size", None),
            )
        return (
            "stack",
            _dynamic_codegen_attr(variable, "base", None),
            _dynamic_codegen_attr(variable, "offset", None),
            _dynamic_codegen_attr(variable, "size", None),
        )
    if isinstance(variable, SimRegisterVariable):
        return (
            "reg",
            _dynamic_codegen_attr(variable, "reg", None),
            _dynamic_codegen_attr(variable, "size", None),
        )
    return None


@cython.ccall
def _register_declaration_candidates(
    cfunc: object,
    structured_codegen_node: Callable[[object], cython.bint],
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
) -> object:
    """Collect (variable, cvar) candidates from in-use vars and the statement root."""
    cvar: object
    node: object
    variable: object
    register_candidates: dict[cython.longlong, tuple[object, object]] = {}
    for variable, cvar in _dynamic_codegen_attr(cfunc, "variables_in_use", {}).items():
        if isinstance(variable, (SimRegisterVariable, SimStackVariable)):
            register_candidates[id(variable)] = (variable, cvar)

    root = _dynamic_codegen_attr(cfunc, "statements", None)
    if structured_codegen_node(root):
        for node in iter_c_nodes_deep(root):
            if not isinstance(node, structured_c.CVariable):
                continue
            variable = _dynamic_codegen_attr(node, "variable", None)
            if not isinstance(variable, (SimRegisterVariable, SimStackVariable)):
                continue
            register_candidates.setdefault(id(variable), (variable, node))
    return register_candidates


def _materialize_register_candidate(
    variable: object,
    cvar: object,
    *,
    local_identity: Callable[[object], tuple[object, ...] | None],
    arg_variables: object,
    unified_locals: object,
    existing_identities: object,
    desired_segment_regs: object,
    stack_type_for_size: Callable[[int], object],
) -> cython.bint:
    """Declare one register/stack candidate in unified_locals when warranted."""
    declared_variable: object
    identity: object
    variable_type: object
    identity = local_identity(variable)
    if id(variable) in arg_variables:
        return False
    if isinstance(variable, SimRegisterVariable):
        declared_variable = next(
            (
                candidate
                for candidate in iter(unified_locals)
                if isinstance(candidate, SimRegisterVariable) and candidate == variable
            ),
            None,
        )
        if declared_variable is not None:
            if _dynamic_codegen_attr(cvar, "unified_variable", None) is not declared_variable:
                with contextlib.suppress(Exception):
                    typing.cast(typing.Any, cvar).unified_variable = declared_variable
                    return True
            return False
    elif identity in existing_identities:
        return False

    reg_name = _dynamic_codegen_attr(variable, "name", None)
    if isinstance(reg_name, str) and reg_name in desired_segment_regs:
        return False

    variable_type = _dynamic_codegen_attr(cvar, "variable_type", None)
    if variable_type is None:
        variable_type = stack_type_for_size(_dynamic_codegen_attr(variable, "size", 0) or 2)
    if variable_type is None:
        return False

    unified_locals[variable] = {(cvar, variable_type)}
    if identity is not None:
        existing_identities.add(identity)
    return True


@cython.ccall
def _prune_void_function_return_values(
    codegen: object, *, iter_c_nodes_deep: Callable[[object], Iterable[object]]
) -> cython.bint:
    cfunc: object
    prototype: object
    container: object
    cfunc = _dynamic_codegen_attr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    prototype = _void_function_prototype(codegen, cfunc)
    returnty = _dynamic_codegen_attr(prototype, "returnty", None) if prototype is not None else None
    if type(returnty) is not SimTypeBottom or _dynamic_codegen_attr(returnty, "label", None) != "void":
        return False

    if not cfunc:
        return False
    changed = False
    for container in tuple(iter_c_nodes_deep(_dynamic_codegen_attr(cfunc, "statements", None))):
        if not isinstance(container, structured_c.CStatements):
            continue
        is_root_container = container is _dynamic_codegen_attr(cfunc, "statements", None)
        if _prune_void_returns_in_container(container, is_root_container, codegen):
            changed = True

    return changed


@cython.ccall
def _void_function_prototype(codegen: object, cfunc: object) -> object | None:
    """Resolve the first available function prototype across known codegen slots."""
    candidate: object
    for candidate in (
        _dynamic_codegen_attr(cfunc, "prototype", None),
        _dynamic_codegen_attr(cfunc, "functy", None),
        _dynamic_codegen_attr(_dynamic_codegen_attr(codegen, "_func", None), "prototype", None),
        _dynamic_codegen_attr(_dynamic_codegen_attr(codegen, "_inertia_current_function_8616", None), "prototype", None),
    ):
        if candidate is not None and _dynamic_codegen_attr(candidate, "returnty", None) is not None:
            return cast(object, candidate)
    return None


@cython.ccall
def _rewrite_void_return_stmt(stmt: object, is_root_container: cython.bint, is_last: cython.bint, codegen: object) -> object:
    """Rewrite a void return statement; return list of replacement stmts or None to keep."""
    retval: object
    retval = _dynamic_codegen_attr(stmt, "retval", None)
    if retval is None:
        return None
    if isinstance(retval, structured_c.CFunctionCall):
        out: list[object] = [
            structured_c.CExpressionStatement(
                retval,
                codegen=_dynamic_codegen_attr(stmt, "codegen", codegen),
            )
        ]
        if not (is_root_container and is_last):
            out.append(
                structured_c.CReturn(None, codegen=_dynamic_codegen_attr(stmt, "codegen", codegen))
            )
        return out
    cast(Any, stmt).retval = None
    return [stmt]


@cython.ccall
def _prune_void_returns_in_container(container: object, is_root_container: cython.bint, codegen: object) -> cython.bint:
    """Rewrite void-valued returns inside one statement container."""
    replacement: object
    index: object
    stmt: object
    statements = list(_dynamic_codegen_attr(container, "statements", ()) or ())
    if not statements:
        return False
    rewritten: list[object] = []
    local_changed = False
    for index, stmt in enumerate(statements):
        if not isinstance(stmt, structured_c.CReturn):
            rewritten.append(stmt)
            continue
        replacement = _rewrite_void_return_stmt(stmt, is_root_container, operator.eq(index, len(statements) - 1), codegen)
        if replacement is None:
            rewritten.append(stmt)
        else:
            rewritten.extend(replacement)
            local_changed = True
    if local_changed:
        cast(Any, container).statements = (
            rewritten if isinstance(_dynamic_codegen_attr(container, "statements", None), list) else tuple(rewritten)
        )
        return True
    return False
