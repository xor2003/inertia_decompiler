from __future__ import annotations

import re
from typing import Any, Callable, TypeAlias

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from .cli_access_object_hints import AccessTraitObjectHint, BaseKey


StableHints: TypeAlias = dict[BaseKey, AccessTraitObjectHint]
ReplaceCChildren: TypeAlias = Callable[[Any, Callable[[Any], Any]], bool]


def _should_attach_access_trait_names(
    codegen: Any,
    *,
    has_stable_access_object_hints: Callable[[Any], bool],
) -> bool:
    return has_stable_access_object_hints(codegen)


def _attach_access_trait_field_names(
    project: Any,
    codegen: Any,
    *,
    should_attach_access_trait_names: Callable[[Any], bool],
    build_stable_access_object_hints: Callable[[dict[BaseKey, object]], StableHints],
    stable_access_object_hint_for_key: Callable[[StableHints, BaseKey | None], AccessTraitObjectHint | None],
    access_trait_variable_key: Callable[[Any], BaseKey | None],
    stack_object_name: Callable[[int], str],
    access_trait_field_name: Callable[[int, int], str],
    replace_c_children: ReplaceCChildren,
) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False
    if not should_attach_access_trait_names(codegen):
        return False

    cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(cache, dict):
        return False
    traits = cache.get(getattr(codegen.cfunc, "addr", None))
    if not isinstance(traits, dict):
        return False
    object_hints = build_stable_access_object_hints(traits)
    if not object_hints:
        return False

    def is_generic_stack_name(name: object) -> bool:
        return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None

    def stack_rewrite_decision(variable: Any) -> AccessTraitObjectHint | None:
        base_key = access_trait_variable_key(variable)
        if base_key is None:
            return None
        return stable_access_object_hint_for_key(object_hints, base_key)

    changed = False

    def rename_stack_variable(cvar: Any, *, suffix: int = 0) -> Any:
        nonlocal changed
        variable = getattr(cvar, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return None
        decision = stack_rewrite_decision(variable)
        if decision is None or not decision.should_rename_stack():
            return None
        name = getattr(variable, "name", None)
        if not is_generic_stack_name(name) and not (isinstance(name, str) and name.startswith("field_")):
            return None
        if decision.kind == "stack":
            field_name = stack_object_name(getattr(variable, "offset", suffix))
        else:
            field_name = access_trait_field_name(suffix, getattr(variable, "size", 1))
        if getattr(variable, "name", None) != field_name:
            variable.name = field_name
            changed = True
        if getattr(cvar, "name", None) != field_name:
            try:
                cvar.name = field_name
            except Exception:
                pass
            else:
                changed = True
        return cvar

    def transform(node: Any) -> Any:
        if isinstance(node, structured_c.CVariable):
            renamed = rename_stack_variable(node, suffix=0)
            if renamed is not None:
                return renamed
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


def _attach_pointer_member_names(
    project: Any,
    codegen: Any,
    *,
    should_attach_access_trait_names: Callable[[Any], bool],
    build_stable_access_object_hints: Callable[[dict[BaseKey, object]], StableHints],
    stable_access_object_hint_for_key: Callable[[StableHints, BaseKey | None], AccessTraitObjectHint | None],
    access_trait_variable_key: Callable[[Any], BaseKey | None],
    access_trait_field_name: Callable[[int, int], str],
    replace_c_children: ReplaceCChildren,
) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False
    if not should_attach_access_trait_names(codegen):
        return False

    cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(cache, dict):
        return False
    traits = cache.get(getattr(codegen.cfunc, "addr", None))
    if not isinstance(traits, dict):
        return False
    object_hints = build_stable_access_object_hints(traits)
    if not object_hints:
        return False

    def is_generic_name(name: object) -> bool:
        return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None

    def candidate_field_names(base_key: BaseKey) -> tuple[str, ...]:
        hint = stable_access_object_hint_for_key(object_hints, base_key)
        if hint is None:
            return ()
        if hint.kind not in {"member", "array", "induction"}:
            return ()
        return hint.candidate_field_names(access_trait_field_name=access_trait_field_name)

    changed = False
    assigned_names: dict[int, str] = {}
    name_cursors: dict[BaseKey, int] = {}

    def assign_member_name(base_key: BaseKey) -> str | None:
        names = candidate_field_names(base_key)
        if not names:
            return None
        index = name_cursors.get(base_key, 0)
        if index < len(names):
            field_name = names[index]
            name_cursors[base_key] = index + 1
            return field_name
        return names[-1]

    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable, cvar in list(variables_in_use.items()):
            if not isinstance(variable, (SimRegisterVariable, SimStackVariable, SimMemoryVariable)):
                continue
            if not is_generic_name(getattr(variable, "name", None)) and not is_generic_name(getattr(cvar, "name", None)):
                continue
            base_key = access_trait_variable_key(variable)
            if base_key is None:
                continue
            field_name = assign_member_name(base_key)
            if field_name is None:
                continue
            target = getattr(cvar, "unified_variable", None) or getattr(cvar, "variable", None)
            if target is not None and getattr(target, "name", None) != field_name:
                target.name = field_name
                changed = True
            if getattr(variable, "name", None) != field_name:
                variable.name = field_name
                changed = True
            if getattr(cvar, "name", None) != field_name:
                setattr(cvar, "name", field_name)
                changed = True
            assigned_names[id(variable)] = field_name

    def rename_member_variable(cvar: Any) -> Any:
        nonlocal changed
        if not isinstance(cvar, structured_c.CVariable):
            return None
        variable = getattr(cvar, "variable", None)
        if not isinstance(variable, (SimRegisterVariable, SimStackVariable, SimMemoryVariable)):
            return None
        if not is_generic_name(getattr(variable, "name", None)) and not is_generic_name(getattr(cvar, "name", None)):
            return None
        base_key = access_trait_variable_key(variable)
        if base_key is None:
            return None
        field_name = assigned_names.get(id(variable))
        if field_name is None:
            field_name = assign_member_name(base_key)
        if field_name is None:
            return None
        if getattr(variable, "name", None) != field_name:
            variable.name = field_name
            changed = True
        if getattr(cvar, "name", None) != field_name:
            try:
                setattr(cvar, "name", field_name)
            except Exception:
                pass
            else:
                changed = True
        return cvar

    def transform(node: Any) -> Any:
        if isinstance(node, structured_c.CVariable):
            renamed = rename_member_variable(node)
            if renamed is not None:
                return renamed
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


