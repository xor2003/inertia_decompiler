from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .cli_access_object_hints import AccessTraitObjectHint, BaseKey
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
    object_hints: StableHints
    refusal_reasons: dict[BaseKey, str]


def load_access_rewrite_artifact(
    project: object,
    function_addr: int | None,
    *,
    build_access_trait_evidence_profiles: Callable[[dict[str, dict[BaseKey, object]]], EvidenceProfiles],
    build_stable_access_object_hints: Callable[[dict[str, dict[BaseKey, object]]], StableHints],
) -> AccessRewriteArtifact | None:
    if function_addr is None:
        return None
    cache = getattr(project, "_inertia_access_rewrite_artifact_cache", None)
    if isinstance(cache, dict):
        cached = cache.get(function_addr)
        if isinstance(cached, AccessRewriteArtifact):
            return cached
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
    object_hints = {
        base_key: AccessTraitObjectHint(
            base_key=record.base_key,
            kind=record.object_kind,
            candidates=tuple((offset, 1, 1) for offset in record.candidate_offsets),
        )
        for base_key, record in storage_object_artifact.records.items()
    }
    refusal_reasons = {
        base_key: refusal.reason for base_key, refusal in storage_object_artifact.refusals.items()
    }
    if not object_hints and not refusal_reasons:
        return None
    artifact = AccessRewriteArtifact(
        object_hints=object_hints,
        refusal_reasons=refusal_reasons,
    )
    if not isinstance(cache, dict):
        cache = {}
        setattr(project, "_inertia_access_rewrite_artifact_cache", cache)
    cache[function_addr] = artifact
    return artifact


def has_access_rewrite_artifact(
    project: object,
    function_addr: int | None,
    *,
    build_access_trait_evidence_profiles: Callable[[dict[str, dict[BaseKey, object]]], EvidenceProfiles],
    build_stable_access_object_hints: Callable[[dict[str, dict[BaseKey, object]]], StableHints],
) -> bool:
    artifact = load_access_rewrite_artifact(
        project,
        function_addr,
        build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        build_stable_access_object_hints=build_stable_access_object_hints,
    )
    return artifact is not None and bool(artifact.object_hints)
