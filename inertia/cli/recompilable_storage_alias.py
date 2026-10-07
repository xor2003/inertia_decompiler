"""Layer: Recompilable output.

Responsibility: export alias-proven storage identities into recompilation artifacts.
Forbidden: alias ownership, source-backed naming, or text-derived storage recovery.

Package ownership contract (canonical inertia/cli package):
Layer: CLI/fallback/reporting.
Owns command entrypoints, fallback orchestration, diagnostics, and reporting of recovered evidence.
Do not perform frontend, IR, semantic, alias, widening, lowering, structuring, rewrite,
postprocess, or validation work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from inertia.alias.alias_model_impl import AliasStorageFacts, _StackSlotIdentity

from .recompilable_storage_map import RecompilableStorageMapArtifact
from .recompilable_storage_map_producer import (
    SegmentedCodegenStorageSurface,
    SegmentedStorageSeed,
    export_recompilable_storage_map_from_codegen,
)

__all__ = [
    "AliasBackedStorageSeed",
    "export_recompilable_storage_map_from_alias_facts",
]


@dataclass(frozen=True, slots=True)
class AliasBackedStorageSeed:
    """Alias-proven storage seed prepared for recompilable storage-map export."""

    alias_facts: AliasStorageFacts
    segment_reg: str | None = None
    stable_object_kind: str | None = None
    stable_object_name: str | None = None


def _segment_seed_from_alias_seed(seed: AliasBackedStorageSeed) -> SegmentedStorageSeed | None:
    facts = seed.alias_facts
    identity = facts.identity
    domain = facts.domain
    width = domain.width or 0

    if facts.needs_synthesis() or identity is None or width <= 0:
        return None

    identity_kind, identity_value = identity

    if identity_kind == "stack":
        if not isinstance(identity_value, _StackSlotIdentity):
            return None
        return SegmentedStorageSeed(
            segment_reg="SS",
            offset=identity_value.offset,
            width=width,
            identity_kind="stack_slot",
            stable_object_kind=seed.stable_object_kind,
            stable_object_name=seed.stable_object_name,
        )

    if identity_kind == "memory":
        if seed.segment_reg is None:
            return None
        if not isinstance(identity_value, int):
            return None
        return SegmentedStorageSeed(
            segment_reg=seed.segment_reg,
            offset=identity_value,
            width=width,
            identity_kind="global",
            stable_object_kind=seed.stable_object_kind,
            stable_object_name=seed.stable_object_name,
        )

    return None


def export_recompilable_storage_map_from_alias_facts(
    codegen: SegmentedCodegenStorageSurface,
    seeds: tuple[AliasBackedStorageSeed, ...],
) -> RecompilableStorageMapArtifact:
    """Export alias-proven storage facts into a recompilable segmented map."""
    mapped = tuple(
        segment_seed
        for seed in seeds
        for segment_seed in (_segment_seed_from_alias_seed(seed),)
        if segment_seed is not None
    )
    return export_recompilable_storage_map_from_codegen(codegen, mapped)
