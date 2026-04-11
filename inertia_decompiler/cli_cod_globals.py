from __future__ import annotations

from typing import Any, Callable, TypeAlias

from angr.analyses.decompiler.structured_codegen import c as structured_c

from .cli_access_object_hints import AccessTraitObjectHint, BaseKey
from .cli_storage_objects import (
    build_storage_object_artifact,
    storage_object_record_for_key,
)


StableHints: TypeAlias = dict[BaseKey, AccessTraitObjectHint]
ReplaceCChildren: TypeAlias = Callable[[Any, Callable[[Any], Any]], bool]


def _coalesce_cod_word_global_loads(
    project: Any,
    codegen: Any,
    synthetic_globals: Any,
    *,
    collect_access_traits: Callable[[Any, Any], Any],
    build_access_trait_evidence_profiles: Callable[[dict[str, dict[BaseKey, object]]], Any],
    build_stable_access_object_hints: Callable[[dict[str, dict[BaseKey, object]]], StableHints],
    global_load_addr: Callable[[Any, Any], int | None],
    match_scaled_high_byte: Callable[[Any, Any], int | None],
    synthetic_word_global_variable: Callable[[Any, Any, int, dict[int, structured_c.CVariable]], structured_c.CVariable | None],
    replace_c_children: ReplaceCChildren,
) -> bool:
    if not synthetic_globals or getattr(codegen, "cfunc", None) is None:
        return False

    traits_cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(traits_cache, dict) or getattr(codegen.cfunc, "addr", None) not in traits_cache:
        collect_access_traits(project, codegen)
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

    created: dict[int, structured_c.CVariable] = {}

    def transform(node: Any) -> Any:
        if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
            return node

        for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            low_addr = global_load_addr(low_expr, project)
            if low_addr is None:
                continue

            if storage_object_artifact is not None:
                record = storage_object_record_for_key(storage_object_artifact, ("mem", low_addr))
                if record is not None and record.object_kind == "member":
                    continue

            cvar = synthetic_word_global_variable(codegen, synthetic_globals, low_addr, created)
            if cvar is None:
                continue

            high_addr = match_scaled_high_byte(high_expr, project)
            if high_addr != low_addr + 1:
                continue

            return cvar

        return node

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
    return changed
