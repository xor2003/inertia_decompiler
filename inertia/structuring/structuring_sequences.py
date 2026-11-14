# cython: language_level=3, infer_types=True
"""Sequence-merge eligibility helpers for region structuring.

Layer: Structuring.
Responsibility: owns sequence merge eligibility policy for region structuring.

This keeps loop-preservation policy outside the main structuring driver.

Package ownership contract (canonical inertia/structuring package):
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from inertia.structuring.structuring_region import DominatorInfo, Region, RegionGraph, RegionType
import operator


@cython.ccall
def _can_reach_region(graph: RegionGraph, src: Region, dst: Region) -> cython.bint:
    """Return True when `src` can reach `dst` through successor edges."""
    region: object
    succ: object
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


@cython.ccall
def merge_would_hide_cycle(
    graph: RegionGraph,
    dominators: object,
    region: Region,
    other: Region,
) -> cython.bint:
    """Return True when merging `other` into `region` would erase a loop edge."""
    if dominators is None:
        return False
    return dominators.dominates(region, other) and _can_reach_region(graph, other, region)


@cython.ccall
def _region_shape_blocks_merge_8616(region: Region, succ: Region) -> cython.bint:
    """Return True when region kinds or identity already forbid sequencing."""
    return (
        succ.region_type in (RegionType.Loop, RegionType.IncSwitch)
        or operator.eq(region.region_type, RegionType.Condition)
        or succ == region
        or region.condition_expr is not None
    )


@cython.ccall
def _typed_metadata_blocks_merge_8616(region: Region, succ: Region) -> cython.bint:
    """Return True when typed IR evidence still owns either region's flow."""
    return (
        bool(region.metadata.get("typed_ir_has_condition", False))
        or bool(succ.metadata.get("typed_ir_has_condition", False))
        or bool(succ.metadata.get("typed_ir_has_phi", False))
    )


@cython.ccall
def sequence_merge_is_safe(
    graph: RegionGraph,
    dominators: DominatorInfo | None,
    region: Region,
    succ: Region,
) -> cython.bint:
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
