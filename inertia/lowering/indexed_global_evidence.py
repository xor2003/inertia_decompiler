"""Represent indexed global identities consumed by segmented lowering.

Layer: Types/Lowering.
Responsibility: carry indexed global storage identities and materialize complete
caller source-family facts into compatible aggregate element evidence.
Consumes alias, widening, and typed facts. This module does not mutate codegen.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .callee_global_object_sources import GlobalObjectSourceEvidence8616


@dataclass(frozen=True, slots=True)
class IndexedSegmentedGlobalEvidence8616:
    """Indexed global load evidence keyed by base offset and width."""

    base_offset: int
    name: str
    relative_disp: int
    width: int
    aggregate_type_name: str | None = None


def merge_global_object_source_evidence_8616(
    evidence: tuple[IndexedSegmentedGlobalEvidence8616, ...],
    source_evidence: GlobalObjectSourceEvidence8616,
) -> tuple[
    tuple[IndexedSegmentedGlobalEvidence8616, ...],
    GlobalObjectSourceEvidence8616,
]:
    """Merge complete source families while retaining stronger symbol names."""
    merged = {
        (item.base_offset & 0xFFFF, int(item.width)): item for item in evidence
    }
    materialized_count = 0
    failure_count = source_evidence.failure_count
    for fact in source_evidence.source_facts:
        aggregate_name = f"g_{fact.family_base_offset & 0xFFFF:04X}"
        canonical_base = fact.canonical_base_offset & 0xFFFF
        canonical_candidates = (
            item
            for (base_offset, _width), item in merged.items()
            if base_offset == canonical_base
        )
        canonical_item = max(
            canonical_candidates,
            key=lambda item: int(item.width),
            default=None,
        )
        name = (
            canonical_item.name
            if canonical_item is not None
            else f"g_{canonical_base:04X}"
        )
        relative_disp = (
            (fact.base_offset - canonical_base + 0x8000) & 0xFFFF
        ) - 0x8000
        views = (
            IndexedSegmentedGlobalEvidence8616(
                base_offset=fact.base_offset & 0xFFFF,
                name=name,
                relative_disp=relative_disp,
                width=fact.element_width,
                aggregate_type_name=aggregate_name,
            ),
            *(
                IndexedSegmentedGlobalEvidence8616(
                    base_offset=(fact.base_offset + field_offset) & 0xFFFF,
                    name=name,
                    relative_disp=relative_disp + field_offset,
                    width=1,
                    aggregate_type_name=aggregate_name,
                )
                for field_offset in fact.field_offsets
            ),
        )
        conflicts = any(
            existing.aggregate_type_name not in {None, aggregate_name}
            for view in views
            if (existing := merged.get((view.base_offset, view.width))) is not None
        )
        if conflicts:
            failure_count += 1
            continue
        for view in views:
            key = (view.base_offset, view.width)
            merged[key] = view
        materialized_count += 1
    return tuple(merged.values()), replace(
        source_evidence,
        materialized_count=materialized_count,
        failure_count=failure_count,
    )


__all__ = [
    "IndexedSegmentedGlobalEvidence8616",
    "merge_global_object_source_evidence_8616",
]
