"""Grouped region-based structuring pass for the 16-bit decompiler.

Layer: Structuring.
Responsibility: run region structuring over grouped CFG fragments with typed metadata.
Dynamic boundary: wraps angr/codegen compatibility graph objects while typed
grouping metadata remains in the structuring layer.
"""

from __future__ import annotations

import traceback
import typing
from typing import Any, cast

from .ir.condition_ir import ConditionIR
from .structuring_abnormal_loops import AbnormalLoopStructureAnalysis
from .structuring_analysis import Region, RegionBasedStructuringPass, RegionGraph, RegionType
from .structuring_grouped_graph_builder import build_grouped_region_graph


def _edge_guard_graph_summary_8616(graph: object) -> dict[str, object]:
    """Summarize typed edge-guard evidence from a dynamic angr/codegen compatibility boundary graph."""
    guarded_regions = 0
    eq_guarded_regions = 0
    two_way_heads_with_eq_guarded_successor = 0
    sample_regions: list[dict[str, object]] = []
    candidate_heads: list[dict[str, object]] = []
    dynamic_graph = cast(Any, graph)
    for region in sorted(dynamic_graph.nodes or (), key=lambda item: int(getattr(item, "region_id", 0) or 0)):
        guards = tuple(getattr(region, "metadata", {}).get("typed_condition_edge_guards", ()) or ())
        typed_guards = tuple(guard for guard in guards if isinstance(guard, ConditionIR))
        eq_guards = tuple(guard for guard in typed_guards if guard.op == "eq")
        if typed_guards:
            guarded_regions += 1
        if eq_guards:
            eq_guarded_regions += 1
        successors = tuple(cast(tuple[Any, ...], getattr(region, "successors", ()) or ()))
        successor_eq_count = 0
        for succ in successors:
            succ_guards = tuple(getattr(succ, "metadata", {}).get("typed_condition_edge_guards", ()) or ())
            if any(isinstance(guard, ConditionIR) and guard.op == "eq" for guard in succ_guards):
                successor_eq_count += 1
        if len(successors) == 2 and successor_eq_count == 1:
            two_way_heads_with_eq_guarded_successor += 1
            continuation = next(
                (
                    succ
                    for succ in successors
                    if not any(
                        isinstance(guard, ConditionIR) and guard.op == "eq"
                        for guard in tuple(getattr(succ, "metadata", {}).get("typed_condition_edge_guards", ()) or ())
                    )
                ),
                None,
            )
            chain: list[int | None] = []
            seen = {region}
            current = continuation
            while current is not None and current not in seen and len(chain) < 6:
                seen.add(current)
                chain.append(getattr(current, "block_addr", None))
                current_successors = tuple(cast(tuple[Any, ...], getattr(current, "successors", ()) or ()))
                if len(current_successors) != 1:
                    break
                current = current_successors[0]
            candidate_heads.append(
                {
                    "addr": getattr(region, "block_addr", None),
                    "continuation_chain": chain,
                    "successor_addrs": [getattr(succ, "block_addr", None) for succ in successors],
                }
            )
        if (typed_guards or successor_eq_count) and len(sample_regions) < 12:
            sample_regions.append(
                {
                    "addr": getattr(region, "block_addr", None),
                    "guard_ops": [guard.op for guard in typed_guards],
                    "successor_addrs": [getattr(succ, "block_addr", None) for succ in successors],
                    "successor_eq_guard_count": successor_eq_count,
                }
            )
    return {
        "guarded_regions": guarded_regions,
        "eq_guarded_regions": eq_guarded_regions,
        "two_way_heads_with_eq_guarded_successor": two_way_heads_with_eq_guarded_successor,
        "sample_regions": sample_regions,
        "candidate_heads": candidate_heads[:12],
    }


def _structured_region_artifacts_8616(
    structured: object,
) -> tuple[list[dict[str, object]], list[object], list[dict[str, object]]]:
    """Collect non-linear region, loop-plan, and switch artifacts."""
    structured_regions: list[dict[str, object]] = []
    abnormal_loop_regions: list[object] = []
    typed_edge_switch_region_artifacts: list[dict[str, object]] = []
    dynamic_structured = cast(Any, structured)
    for region in dynamic_structured.nodes:
        if region.region_type != RegionType.Linear:
            structured_regions.append(
                {
                    "addr": region.block_addr,
                    "type": region.region_type.value,
                    "metadata_keys": list(region.metadata.keys()),
                }
            )
        if "abnormal_loop_plan" in region.metadata:
            abnormal_loop_regions.append(region.metadata["abnormal_loop_plan"])
        switch_artifact = region.metadata.get("typed_edge_switch_region_artifact")
        if isinstance(switch_artifact, dict):
            typed_edge_switch_region_artifacts.append(dict(switch_artifact))
    return structured_regions, abnormal_loop_regions, typed_edge_switch_region_artifacts


def _merge_cfunc_stats_8616(codegen: object, stats: dict[str, object]) -> None:
    """Merge the pass stats record into the cfunc stats surface."""
    codegen_dynamic = cast(Any, codegen)
    cfunc = codegen_dynamic.cfunc
    cfunc_stats = getattr(cfunc, "_structuring_stats", None)
    if not isinstance(cfunc_stats, dict):
        cfunc_stats = {}
        try:
            cfunc._structuring_stats = cfunc_stats
        except AttributeError:
            cfunc_stats = None
    if isinstance(cfunc_stats, dict):
        cfunc_stats.update(stats)


class GroupedRegionBasedStructuringPass(RegionBasedStructuringPass):
    """Run region structuring on grouped region graphs with typed evidence."""

    def __call__(self, codegen: object) -> bool:
        """Apply grouped region-based structuring to codegen."""
        if getattr(codegen, "cfunc", None) is None:
            return False
        return self._apply(codegen)

    def _stats_record_8616(
        self,
        structured: object,
        initial_graph_summary: dict[str, object],
    ) -> dict[str, object]:
        """Build the grouped-structuring stats record for this run."""
        structured_regions, abnormal_loop_regions, switch_artifacts = (
            _structured_region_artifacts_8616(structured)
        )
        return {
            "iterations": self.stats.iterations,
            "regions_reduced": self.stats.regions_reduced,
            "cycles_resolved": self.stats.cycles_resolved,
            "sequences_created": self.stats.sequences_created,
            "edge_guard_switches_detected": self.stats.edge_guard_switches_detected,
            "final_node_count": len(cast(Any, structured).nodes),
            "initial_graph_summary": initial_graph_summary,
            "final_graph_summary": _edge_guard_graph_summary_8616(structured),
            "structured_regions": structured_regions,
            "abnormal_loop_regions": abnormal_loop_regions,
            "typed_edge_switch_region_artifacts": switch_artifacts,
        }

    def _apply(self, codegen: object) -> bool:
        """Apply grouped structuring across the dynamic codegen boundary."""
        try:
            graph, entry = self._build_region_graph(codegen)
            if graph is None or entry is None or len(graph.nodes) < 2:
                return False
            initial_graph_summary = _edge_guard_graph_summary_8616(graph)

            analysis = AbnormalLoopStructureAnalysis(graph)
            structured = analysis.structure()
            self.stats = analysis.stats
            typing.cast(typing.Any, codegen)._inertia_grouped_structuring_graph = structured

            stats = self._stats_record_8616(structured, initial_graph_summary)
            typing.cast(typing.Any, codegen)._inertia_grouped_structuring_stats_8616 = dict(stats)
            _merge_cfunc_stats_8616(codegen, stats)

            return False
        except Exception as ex:
            typing.cast(typing.Any, codegen)._inertia_grouped_structuring_error_8616 = {
                    "type": type(ex).__name__,
                    "message": str(ex),
                    "traceback": "".join(traceback.format_exception(type(ex), ex, ex.__traceback__, limit=4)),
                }
            return False

    def _build_region_graph(self, codegen: object) -> tuple[RegionGraph | None, Region | None]:
        """Build the grouped-region graph through the structuring graph-builder contract."""
        result = build_grouped_region_graph(codegen)
        return result.graph_result.graph, result.graph_result.entry


def apply_grouped_region_based_structuring(codegen: object) -> bool:
    """Apply grouped region-based structuring to codegen."""
    import os

    enabled = os.environ.get("INERTIA_RUN_GROUPED_STRUCTURING_IN_STAGE", "1").strip().lower()
    if enabled in {"0", "false", "no", "off"}:
        return False
    pass_instance = GroupedRegionBasedStructuringPass()
    return pass_instance(codegen)


def describe_x86_16_grouped_structuring_pass_surface() -> dict[str, object]:
    """Describe the grouped structuring pass integration surface."""
    return {
        "pass_class": "GroupedRegionBasedStructuringPass",
        "graph_builder": "build_grouped_region_graph",
        "analysis_class": "AbnormalLoopStructureAnalysis",
        "purpose": "Feed grouped region graphs into the real region-based structuring driver.",
    }


__all__ = [
    "GroupedRegionBasedStructuringPass",
    "apply_grouped_region_based_structuring",
    "describe_x86_16_grouped_structuring_pass_surface",
]
