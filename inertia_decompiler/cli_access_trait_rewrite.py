from __future__ import annotations

import re

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable


def _should_attach_access_trait_names(codegen, *, build_access_trait_evidence_profiles) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    project = getattr(codegen, "project", None)
    if project is None:
        return False
    cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(cache, dict):
        return False
    traits = cache.get(getattr(cfunc, "addr", None))
    if not isinstance(traits, dict):
        return False
    profiles = build_access_trait_evidence_profiles(traits)
    return any(profile.has_any_evidence() for profile in profiles.values())


def _attach_access_trait_field_names(
    project,
    codegen,
    *,
    should_attach_access_trait_names,
    build_access_trait_evidence_profiles,
    access_trait_variable_key,
    access_trait_profile_for_key,
    AccessTraitRewriteDecision,
    stack_object_name,
    access_trait_field_name,
    replace_c_children,
):
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
    evidence_profiles = build_access_trait_evidence_profiles(traits)

    def is_generic_stack_name(name: object) -> bool:
        return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None

    def stack_rewrite_decision(variable):
        base_key = access_trait_variable_key(variable)
        if base_key is None:
            return None
        profile = access_trait_profile_for_key(evidence_profiles, base_key)
        if profile is None or profile.best_rewrite_kind() is None:
            return None
        return AccessTraitRewriteDecision(base_key, profile)

    changed = False

    def rename_stack_variable(cvar, *, suffix: int = 0):
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
        if decision.preferred_kind() == "stack":
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

    def transform(node):
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
    project,
    codegen,
    *,
    should_attach_access_trait_names,
    access_trait_member_candidates,
    build_access_trait_evidence_profiles,
    access_trait_profile_for_key,
    access_trait_variable_key,
    AccessTraitRewriteDecision,
    replace_c_children,
):
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

    def is_generic_name(name: object) -> bool:
        return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None

    evidence = access_trait_member_candidates(traits)
    evidence_profiles = build_access_trait_evidence_profiles(traits)
    if not evidence:
        return False

    def candidate_field_names(base_key: tuple[object, ...]) -> tuple[str, ...]:
        profile = access_trait_profile_for_key(evidence_profiles, base_key)
        if profile is None:
            return ()
        decision = AccessTraitRewriteDecision(base_key, profile)
        if decision.preferred_kind() is None:
            return ()
        return decision.candidate_field_names()

    changed = False
    assigned_names: dict[int, str] = {}
    name_cursors: dict[tuple[object, ...], int] = {}

    def assign_member_name(base_key: tuple[object, ...]) -> str | None:
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
                cvar.name = field_name
                changed = True
            assigned_names[id(variable)] = field_name

    def rename_member_variable(cvar):
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
                cvar.name = field_name
            except Exception:
                pass
            else:
                changed = True
        return cvar

    def transform(node):
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
