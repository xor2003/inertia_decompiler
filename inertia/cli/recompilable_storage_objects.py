# cython: language_level=3, infer_types=True
"""Layer: Recompilable output.

Responsibility: summarize already-proven storage object artifacts for recompilation diagnostics.
Forbidden: object-shape guessing, source-backed names, or semantic recovery.

Package ownership contract (canonical inertia/cli package):
Layer: CLI/fallback/reporting.
Owns command entrypoints, fallback orchestration, diagnostics, and reporting of recovered evidence.
Do not perform frontend, IR, semantic, alias, widening, lowering, structuring, rewrite,
postprocess, or validation work here.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from inertia.lowering.access_profiles import build_access_trait_evidence_profiles
from inertia.lowering.object_lowering import BaseKey, _build_stable_access_object_hints
from inertia.lowering.storage_objects import (
    StorageObjectArtifact,
    build_storage_object_artifact,
)
import dataclasses
import builtins

__all__ = [
    "AccessTraitCache",
    "RecompilableStorageObjectSummary",
    "RecompilableStorageTraitSurface",
    "build_recompilable_storage_object_artifact",
    "summarize_recompilable_storage_object_artifact",
]

AccessTraitTraits = typing.TypeAliasType("AccessTraitTraits", dict[str, dict[BaseKey, object]])
AccessTraitCache = typing.TypeAliasType("AccessTraitCache", Mapping[int | None, AccessTraitTraits])


@runtime_checkable
class RecompilableStorageTraitSurface(Protocol):
    """Typed project surface that carries already-proven access trait evidence."""

    _inertia_access_traits: AccessTraitCache


@dataclasses.dataclass(frozen=True, )
class RecompilableStorageObjectSummary:
    """Counts and categories from recompilable storage object diagnostics."""

    record_count: cython.longlong
    refusal_count: cython.longlong
    object_kinds: object
    refusal_reasons: object


def build_recompilable_storage_object_artifact(
    project: object,
    function_addr: int | None,
) -> StorageObjectArtifact | None:
    """Build a storage-object artifact from a typed project access-trait surface."""
    traits: object
    if not isinstance(project, RecompilableStorageTraitSurface):
        return None
    traits_cache = project._inertia_access_traits
    traits = traits_cache.get(function_addr)
    if not isinstance(traits, dict):
        return None
    return build_storage_object_artifact(
        traits,
        build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        build_stable_access_object_hints=lambda current_traits: _build_stable_access_object_hints(
            current_traits,
            build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        ),
    )


@cython.ccall
def summarize_recompilable_storage_object_artifact(
    artifact: object,
) -> RecompilableStorageObjectSummary:
    """Summarize accepted and refused recompilable storage object evidence."""
    if artifact is None:
        return RecompilableStorageObjectSummary(
            record_count=0,
            refusal_count=0,
            object_kinds=(),
            refusal_reasons=(),
        )
    return RecompilableStorageObjectSummary(
        record_count=len(artifact.records),
        refusal_count=len(artifact.refusals),
        object_kinds=tuple(sorted({record.object_kind for record in builtins.iter(artifact.records.values())})),
        refusal_reasons=tuple(sorted({refusal.reason for refusal in builtins.iter(artifact.refusals.values())})),
    )
