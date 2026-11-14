# cython: language_level=3, infer_types=True
"""Layer: Recompilable output.

Responsibility: convert proven codegen storage seeds into recompilation storage maps.
Forbidden: segment recovery, alias ownership, or source/COD-backed storage synthesis.

Package ownership contract (canonical inertia/cli package):
Layer: CLI/fallback/reporting.
Owns command entrypoints, fallback orchestration, diagnostics, and reporting of recovered evidence.
Do not perform frontend, IR, semantic, alias, widening, lowering, structuring, rewrite,
postprocess, or validation work here.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Protocol

from .recompilable_storage_map import (
    RecompilableStorageMapArtifact,
    RecompilableStorageMapCandidate,
    build_recompilable_storage_map,
)
import dataclasses

__all__ = [
    "SegmentedCodegenStorageSurface",
    "SegmentedStorageSeed",
    "export_recompilable_storage_map_from_codegen",
]

SegmentSummaryEntry = typing.TypeAliasType("SegmentSummaryEntry", Mapping[str, object])
SegmentSummaryBuckets = typing.TypeAliasType("SegmentSummaryBuckets", Mapping[str, Mapping[str, SegmentSummaryEntry]])
SegmentLoweringMap = typing.TypeAliasType("SegmentLoweringMap", Mapping[str, SegmentSummaryEntry])


class SegmentedCodegenStorageSurface(Protocol):
    """Typed codegen attributes required for recompilable storage-map export."""

    _inertia_segmented_memory_summary: SegmentSummaryBuckets
    _inertia_segmented_memory_lowering: SegmentLoweringMap


@dataclasses.dataclass(frozen=True, )
class SegmentedStorageSeed:
    """Proven segmented storage seed exported from codegen or alias evidence."""

    segment_reg: object
    offset: cython.longlong
    width: cython.longlong
    identity_kind: object
    stable_object_kind: object = None
    stable_object_name: object = None


@cython.ccall
def _segment_summary_entry(codegen: SegmentedCodegenStorageSurface, segment_reg: object) -> SegmentSummaryEntry:
    entry: object
    bucket: object
    summary = codegen._inertia_segmented_memory_summary
    normalized = segment_reg.upper()
    for bucket in ("stable", "over_associated", "unknown"):
        entry = summary.get(bucket, {}).get(normalized)
        if entry is not None:
            return entry
    return {}


@cython.ccall
def _segment_lowering_entry(codegen: SegmentedCodegenStorageSurface, segment_reg: object) -> SegmentSummaryEntry:
    lowering = codegen._inertia_segmented_memory_lowering
    return lowering.get(segment_reg.upper(), {})


@cython.ccall
def _segment_value_from_summary(entry: SegmentSummaryEntry, classification: object) -> int | None:
    known_values: object
    if classification != "const":
        return None
    known_values = entry.get("known_values")
    if not isinstance(known_values, tuple) or len(known_values) != 1:
        return None
    value = known_values[0]
    return value if isinstance(value, int) else None


@cython.ccall
def _candidate_from_seed(
    codegen: SegmentedCodegenStorageSurface,
    seed: SegmentedStorageSeed,
) -> RecompilableStorageMapCandidate:
    summary_entry = _segment_summary_entry(codegen, seed.segment_reg)
    lowering_entry = _segment_lowering_entry(codegen, seed.segment_reg)
    classification = str(lowering_entry.get("classification") or summary_entry.get("classification") or "unknown")
    allow_linear_lowering = bool(lowering_entry.get("allow_linear_lowering", False))
    return RecompilableStorageMapCandidate(
        segment_reg=seed.segment_reg.upper(),
        segment_value=_segment_value_from_summary(summary_entry, classification),
        offset=seed.offset,
        width=seed.width,
        identity_kind=seed.identity_kind,
        association_classification=classification,
        allow_linear_lowering=allow_linear_lowering,
        stable_object_kind=seed.stable_object_kind,
        stable_object_name=seed.stable_object_name,
    )


def export_recompilable_storage_map_from_codegen(
    codegen: SegmentedCodegenStorageSurface,
    seeds: Iterable[SegmentedStorageSeed],
) -> RecompilableStorageMapArtifact:
    """Export a deterministic recompilable storage map from typed codegen evidence."""
    candidates = tuple(_candidate_from_seed(codegen, seed) for seed in iter(seeds))
    return build_recompilable_storage_map(candidates)
