"""Sequence-merge eligibility helpers for region structuring.

Layer: Structuring.
Responsibility: owns sequence merge eligibility policy for region structuring.

This keeps loop-preservation policy outside the main structuring driver.
"""

from __future__ import annotations

from .structuring_region import DominatorInfo, Region, RegionGraph, RegionType


def _can_reach_region(graph: RegionGraph, src: Region, dst: Region) -> bool:
    """Return True when `src` can reach `dst` through successor edges."""
    worklist = [src]
    seen: set[Region] = set()

    while worklist:
        region = worklist.pop()
        if region in seen:
            continue
        seen.add(region)
        for succ in graph.successors(region):
            if succ == dst:
                return True
            if succ not in seen:
                worklist.append(succ)

    return False


def merge_would_hide_cycle(
    graph: RegionGraph,
    dominators: DominatorInfo | None,
    region: Region,
    other: Region,
) -> bool:
    """Return True when merging `other` into `region` would erase a loop edge."""
    if dominators is None:
        return False
    return dominators.dominates(region, other) and _can_reach_region(graph, other, region)


def _region_shape_blocks_merge_8616(region: Region, succ: Region) -> bool:
    """Return True when region kinds or identity already forbid sequencing."""
    return (
        succ.region_type in (RegionType.Loop, RegionType.IncSwitch)
        or region.region_type == RegionType.Condition
        or succ == region
        or region.condition_expr is not None
    )


def _typed_metadata_blocks_merge_8616(region: Region, succ: Region) -> bool:
    """Return True when typed IR evidence still owns either region's flow."""
    return (
        bool(region.metadata.get("typed_ir_has_condition", False))
        or bool(succ.metadata.get("typed_ir_has_condition", False))
        or bool(succ.metadata.get("typed_ir_has_phi", False))
    )


def sequence_merge_is_safe(
    graph: RegionGraph,
    dominators: DominatorInfo | None,
    region: Region,
    succ: Region,
) -> bool:
    """Return True when `region -> succ` is safe to collapse as a sequence.

    The key guard is loop preservation: do not consume a successor that feeds a
    back-edge to the region, because that hides a natural loop before cyclic
    analysis can see it.
    """
    if _region_shape_blocks_merge_8616(region, succ):
        return False
    if _typed_metadata_blocks_merge_8616(region, succ):
        return False
    if len(graph.predecessors(succ)) != 1:
        return False
    if succ not in region.successors:
        return False
    return not merge_would_hide_cycle(graph, dominators, region, succ)
