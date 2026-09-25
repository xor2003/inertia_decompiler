"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c

from .cli_access_object_hints import AccessTraitObjectHint, BaseKey
from .cli_storage_objects import (
    EvidenceProfiles,
    build_storage_object_artifact,
    storage_object_record_for_key,
)

type StableHints = dict[BaseKey, AccessTraitObjectHint]
type ReplaceCChildren = Callable[[object, Callable[[object], object]], bool]


class _CFunctionLike(Protocol):
    """C function shape needed by this legacy CLI cleanup helper."""

    addr: int
    statements: object


class _CodegenLike(Protocol):
    """Structured codegen shape needed by this legacy CLI cleanup helper."""

    cfunc: _CFunctionLike | None


@dataclass(slots=True)
class _CodGlobalLoadFold8616:
    """Mutable fold state for coalescing scaled word-global loads."""

    codegen: _CodegenLike
    synthetic_globals: object
    storage_object_artifact: object
    project: object
    global_load_addr: Callable[[object, object], int | None]
    match_scaled_high_byte: Callable[[object, object], int | None]
    synthetic_word_global_variable: Callable[
        [_CodegenLike, object, int, dict[int, structured_c.CVariable]], structured_c.CVariable | None
    ]
    created: dict[int, structured_c.CVariable] = field(default_factory=dict)

    def transform(self, node: object) -> object:
        """Replace one adjacent low+high byte global-load pair with a word global."""
        if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
            return node

        for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            low_addr = self.global_load_addr(low_expr, self.project)
            if low_addr is None:
                continue

            if self.storage_object_artifact is not None:
                record = storage_object_record_for_key(self.storage_object_artifact, ("mem", low_addr))
                if record is not None and record.object_kind == "member":
                    continue

            cvar = self.synthetic_word_global_variable(
                self.codegen, self.synthetic_globals, low_addr, self.created
            )
            if cvar is None:
                continue

            high_addr = self.match_scaled_high_byte(high_expr, self.project)
            if high_addr != low_addr + 1:
                continue

            return cvar

        return node


def _storage_object_artifact_for(
    project: object,
    codegen: _CodegenLike,
    cfunc: _CFunctionLike,
    *,
    collect_access_traits: Callable[[object, _CodegenLike], object],
    build_access_trait_evidence_profiles: Callable[[dict[str, dict[BaseKey, object]]], EvidenceProfiles],
    build_stable_access_object_hints: Callable[[dict[str, dict[BaseKey, object]]], StableHints],
) -> object:
    """Return the storage-object artifact for this function's access traits."""
    # dynamic angr boundary: access traits are attached to Project by earlier passes.
    traits_cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(traits_cache, dict) or cfunc.addr not in traits_cache:
        collect_access_traits(project, codegen)
        # dynamic angr boundary: collect_access_traits refreshes the Project cache.
        traits_cache = getattr(project, "_inertia_access_traits", None)

    if not isinstance(traits_cache, dict):
        return None
    traits = traits_cache.get(cfunc.addr)
    if not isinstance(traits, dict):
        return None
    return build_storage_object_artifact(
        traits,
        build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        build_stable_access_object_hints=build_stable_access_object_hints,
    )


def _coalesce_cod_word_global_loads(
    project: object,
    codegen: _CodegenLike,
    synthetic_globals: object,
    *,
    collect_access_traits: Callable[[object, _CodegenLike], object],
    build_access_trait_evidence_profiles: Callable[[dict[str, dict[BaseKey, object]]], EvidenceProfiles],
    build_stable_access_object_hints: Callable[[dict[str, dict[BaseKey, object]]], StableHints],
    global_load_addr: Callable[[object, object], int | None],
    match_scaled_high_byte: Callable[[object, object], int | None],
    synthetic_word_global_variable: Callable[
        [_CodegenLike, object, int, dict[int, structured_c.CVariable]], structured_c.CVariable | None
    ],
    replace_c_children: ReplaceCChildren,
) -> bool:
    cfunc = codegen.cfunc
    if not synthetic_globals or cfunc is None:
        return False

    storage_object_artifact = _storage_object_artifact_for(
        project,
        codegen,
        cfunc,
        collect_access_traits=collect_access_traits,
        build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        build_stable_access_object_hints=build_stable_access_object_hints,
    )

    folder = _CodGlobalLoadFold8616(
        codegen,
        synthetic_globals,
        storage_object_artifact,
        project,
        global_load_addr,
        match_scaled_high_byte,
        synthetic_word_global_variable,
    )
    root = cfunc.statements
    new_root = folder.transform(root)
    changed = False
    if new_root is not root:
        cfunc.statements = new_root
        root = new_root
        changed = True

    if replace_c_children(root, folder.transform):
        changed = True
    return changed
