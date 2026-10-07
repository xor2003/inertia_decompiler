"""Layer: Structuring.

Responsibility: publish grouped-entry CFG artifacts before region structuring/codegen.
Forbidden: alias ownership, type recovery, rewrite cleanup, or source/COD/text-backed repair.

Package ownership contract (canonical inertia/structuring package):
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import typing

from inertia.structuring.structuring_grouped_graph_builder import build_grouped_region_graph


def apply_x86_16_cross_entry_grouping(codegen: object) -> bool:
    """Publish grouped-entry CFG artifacts without marking structuring changed.

    The real grouped structuring pass rebuilds and consumes its own grouped
    graph.  This pass exposes deterministic artifacts for diagnostics and
    validation manifests only, so it must not become ``last_pass`` evidence.
    Dynamic attribute boundary: codegen is a third-party angr/codegen
    compatibility object that intentionally carries optional diagnostic metadata.
    """
    grouped_graph = build_grouped_region_graph(codegen)
    artifact = grouped_graph.grouped_units.grouping if grouped_graph.grouped_units is not None else None
    typing.cast(typing.Any, codegen)._inertia_cfg_grouping_artifact = artifact
    typing.cast(typing.Any, codegen)._inertia_grouped_region_graph = grouped_graph.graph_result.graph
    if artifact is None:
        typing.cast(typing.Any, codegen)._inertia_grouped_entry_candidate_ids = ()
        typing.cast(typing.Any, codegen)._inertia_entry_fragment_ids = ()
        typing.cast(typing.Any, codegen)._inertia_cross_entry_grouped_units = grouped_graph.grouped_units
        typing.cast(typing.Any, codegen)._inertia_cross_entry_unit_members = ()
        return False
    grouped_entry_candidate_ids = tuple(artifact.grouped_entry_candidate_ids)
    entry_fragment_ids = tuple(artifact.entry_fragment_ids)
    typing.cast(typing.Any, codegen)._inertia_grouped_entry_candidate_ids = grouped_entry_candidate_ids
    typing.cast(typing.Any, codegen)._inertia_entry_fragment_ids = entry_fragment_ids
    typing.cast(typing.Any, codegen)._inertia_cross_entry_grouped_units = grouped_graph.grouped_units
    member_region_ids = (
        tuple(sorted({region_id for unit in grouped_graph.grouped_units.units for region_id in unit.member_region_ids}))
        if grouped_graph.grouped_units is not None
        else ()
    )
    typing.cast(typing.Any, codegen)._inertia_cross_entry_unit_members = member_region_ids
    return False


def describe_x86_16_cross_entry_grouping_surface() -> dict[str, object]:
    """Describe the grouped-entry CFG artifact publication surface."""
    return {
        "producer": "build_cfg_grouping_artifact",
        "artifact_attr": "_inertia_cfg_grouping_artifact",
        "candidate_attr": "_inertia_grouped_entry_candidate_ids",
        "entry_fragment_attr": "_inertia_entry_fragment_ids",
        "grouped_unit_attr": "_inertia_cross_entry_grouped_units",
        "grouped_graph_attr": "_inertia_grouped_region_graph",
        "purpose": "Run CFG grouping export before region structuring/codegen.",
    }


__all__ = [
    "apply_x86_16_cross_entry_grouping",
    "describe_x86_16_cross_entry_grouping_surface",
]
