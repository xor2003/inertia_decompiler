"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import typing
from collections.abc import Callable
from dataclasses import dataclass

from inertia.lowering.object_lowering import AccessTraitObjectHint, BaseKey

from .cli_storage_objects import (
    EvidenceProfiles,
    StableHints,
    StorageObjectArtifact,
    build_storage_object_artifact,
)

__all__ = [
    "AccessRewriteArtifact",
    "has_access_rewrite_artifact",
    "load_access_rewrite_artifact",
]


@dataclass(frozen=True)
class AccessRewriteArtifact:
    """Stable object-hint rewrite data derived from typed access evidence."""

    object_hints: StableHints
    refusal_reasons: dict[BaseKey, str]


def _stable_object_hints_from_artifact(storage_object_artifact: StorageObjectArtifact) -> StableHints:
    return {
        base_key: AccessTraitObjectHint(
            base_key=record.base_key,
            kind=record.object_kind,
            candidates=tuple((offset, 1, 1) for offset in record.candidate_offsets),
        )
        for base_key, record in storage_object_artifact.records.items()
    }


def load_access_rewrite_artifact(
    project: object,
    function_addr: int | None,
    *,
    build_access_trait_evidence_profiles: Callable[[dict[str, dict[BaseKey, object]]], EvidenceProfiles],
    build_stable_access_object_hints: Callable[[dict[str, dict[BaseKey, object]]], StableHints],
) -> AccessRewriteArtifact | None:
    """Load or build the access rewrite artifact cached on an angr project."""
    if function_addr is None:
        return None
    # dynamic angr boundary: Inertia attaches optional analysis caches to Project.
    cache = getattr(project, "_inertia_access_rewrite_artifact_cache", None)
    if isinstance(cache, dict):
        cached = cache.get(function_addr)
        if isinstance(cached, AccessRewriteArtifact):
            return cached
    # dynamic angr boundary: access traits are populated by earlier CLI analysis passes.
    traits_cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(traits_cache, dict):
        return None
    traits = traits_cache.get(function_addr)
    if not isinstance(traits, dict):
        return None
    storage_object_artifact: StorageObjectArtifact = build_storage_object_artifact(
        traits,
        build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        build_stable_access_object_hints=build_stable_access_object_hints,
    )
    object_hints = _stable_object_hints_from_artifact(storage_object_artifact)
    refusal_reasons = {base_key: refusal.reason for base_key, refusal in storage_object_artifact.refusals.items()}
    if not object_hints and not refusal_reasons:
        return None
    artifact = AccessRewriteArtifact(
        object_hints=object_hints,
        refusal_reasons=refusal_reasons,
    )
    if not isinstance(cache, dict):
        cache = {}
        # dynamic angr boundary: persist the derived artifact cache on Project.
        typing.cast(typing.Any, project)._inertia_access_rewrite_artifact_cache = cache
    cache[function_addr] = artifact
    return artifact


def has_access_rewrite_artifact(
    project: object,
    function_addr: int | None,
    *,
    build_access_trait_evidence_profiles: Callable[[dict[str, dict[BaseKey, object]]], EvidenceProfiles],
    build_stable_access_object_hints: Callable[[dict[str, dict[BaseKey, object]]], StableHints],
) -> bool:
    """Return whether a function has stable access rewrite object hints."""
    artifact = load_access_rewrite_artifact(
        project,
        function_addr,
        build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        build_stable_access_object_hints=build_stable_access_object_hints,
    )
    return artifact is not None and bool(artifact.object_hints)
