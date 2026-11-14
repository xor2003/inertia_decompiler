# cython: language_level=3, infer_types=True
"""Layer: Structuring.

Responsibility: derive cross-entry grouped units from CFG ownership artifacts.
Forbidden: alias ownership, type/materialization recovery, or source/COD/text-backed grouping.

Package ownership contract (canonical inertia/structuring package):
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from typing import Protocol

from inertia.structuring.structuring_cfg_grouping import (
    CFGGroupingArtifact,
    CFGGroupingRecord,
    build_cfg_grouping_artifact,
)
from inertia.structuring.structuring_cfg_snapshot import CFGSnapshotNode
import dataclasses

__all__ = (
    "CrossEntryGroupedUnit",
    "CrossEntryGroupedUnitArtifact",
    "CrossEntryGroupedUnitRefusal",
    "apply_x86_16_cross_entry_grouped_units",
    "build_x86_16_cross_entry_grouped_units",
    "describe_x86_16_cross_entry_grouped_unit_surface",
)


class _CrossEntryGroupedUnitCodegen(Protocol):
    _inertia_cross_entry_grouped_units: CrossEntryGroupedUnitArtifact | None
    _inertia_cross_entry_unit_members: object


@dataclasses.dataclass(frozen=True, )
class _SnapshotNodeFallback:
    """Fallback snapshot node used only when grouped ownership data is incomplete."""

    predecessor_ids: tuple[cython.longlong, ...] = ()


@dataclasses.dataclass(frozen=True, )
class CrossEntryGroupedUnit:
    """Accepted grouped multi-entry CFG unit derived from ownership artifacts."""

    anchor_shared_region_id: cython.longlong
    primary_entry_region_ids: object
    entry_fragment_region_ids: object
    shared_region_ids: object
    member_region_ids: object
    refusal_reason: object = None


@dataclasses.dataclass(frozen=True, )
class CrossEntryGroupedUnitRefusal:
    """Reason a candidate grouped CFG unit must remain unmaterialized."""

    anchor_shared_region_id: cython.longlong
    shared_region_ids: object
    external_predecessor_region_ids: object
    ambiguous_predecessor_region_ids: object
    refusal_reason: object


@dataclasses.dataclass(frozen=True, )
class CrossEntryGroupedUnitArtifact:
    """Cross-entry grouping result plus honest refusal diagnostics."""

    grouping: CFGGroupingArtifact
    units: object
    refusals: object
    refused_anchor_region_ids: object

    def summary_line(self) -> str:
        """Return a compact deterministic status line for reports."""
        return f"cross_entry_grouped_units units={len(self.units)} refused={len(self.refused_anchor_region_ids)}"

    def to_dict(self) -> object:
        """Serialize grouped-unit evidence for diagnostics and tests."""

        def _impl() -> dict[str, object]:
            return {
                "grouping": self.grouping.to_dict(),
                "refused_anchor_region_ids": [hex(region_id) for region_id in iter(self.refused_anchor_region_ids)],
                "refusals": [
                    {
                        "anchor_shared_region_id": hex(refusal.anchor_shared_region_id),
                        "shared_region_ids": [hex(region_id) for region_id in iter(refusal.shared_region_ids)],
                        "external_predecessor_region_ids": [
                            hex(region_id) for region_id in iter(refusal.external_predecessor_region_ids)
                        ],
                        "ambiguous_predecessor_region_ids": [
                            hex(region_id) for region_id in iter(refusal.ambiguous_predecessor_region_ids)
                        ],
                        "refusal_reason": refusal.refusal_reason,
                    }
                    for refusal in iter(self.refusals)
                ],
                "units": [
                    {
                        "anchor_shared_region_id": hex(unit.anchor_shared_region_id),
                        "primary_entry_region_ids": [hex(region_id) for region_id in iter(unit.primary_entry_region_ids)],
                        "entry_fragment_region_ids": [hex(region_id) for region_id in iter(unit.entry_fragment_region_ids)],
                        "shared_region_ids": [hex(region_id) for region_id in iter(unit.shared_region_ids)],
                        "member_region_ids": [hex(region_id) for region_id in iter(unit.member_region_ids)],
                        "refusal_reason": unit.refusal_reason,
                    }
                    for unit in iter(self.units)
                ],
            }

        return _impl()


@cython.ccall
def _shared_component_8616(
    shared_region_id: cython.longlong,
    shared_region_id_set: object,
    snapshot_nodes: object,
    visited_shared_region_ids: object,
) -> tuple[cython.longlong, ...]:
    """Flood one connected shared-region component, marking it visited."""
    current_node: object
    current_region_id: object
    neighbor_region_id: object
    component_worklist = [shared_region_id]
    component_shared_region_ids: set[cython.longlong] = set()
    while component_worklist:
        current_region_id = component_worklist.pop()
        if current_region_id in component_shared_region_ids:
            continue
        component_shared_region_ids.add(current_region_id)
        visited_shared_region_ids.add(current_region_id)
        current_node = snapshot_nodes.get(current_region_id)
        if current_node is None:
            continue
        neighbor_ids = set(current_node.predecessor_ids) | set(current_node.successor_ids)
        for neighbor_region_id in neighbor_ids:
            if (
                neighbor_region_id in shared_region_id_set
                and neighbor_region_id not in component_shared_region_ids
            ):
                component_worklist.append(neighbor_region_id)
    return tuple(sorted(component_shared_region_ids))


def _component_predecessor_groups_8616(
    component_region_ids: object,
    snapshot_nodes: object,
    record_by_region_id: object,
) -> tuple[list[cython.longlong], tuple[cython.longlong, ...], tuple[cython.longlong, ...], tuple[cython.longlong, ...]]:
    """Census external predecessors of one component by grouping kind."""
    component_set = set(component_region_ids)
    external_predecessor_ids = sorted(
        {
            predecessor_region_id
            for component_region_id in iter(component_region_ids)
            for predecessor_region_id in iter(snapshot_nodes.get(
                component_region_id, _SnapshotNodeFallback(),
            ).predecessor_ids)
            if predecessor_region_id not in component_set
            and predecessor_region_id in record_by_region_id
        }
    )
    primary_entry_region_ids = tuple(
        region_id
        for region_id in iter(external_predecessor_ids)
        if record_by_region_id[region_id].grouping_kind == "primary_entry"
    )
    entry_fragment_region_ids = tuple(
        region_id
        for region_id in iter(external_predecessor_ids)
        if record_by_region_id[region_id].grouping_kind == "entry_fragment"
    )
    ambiguous_predecessor_ids = tuple(
        region_id
        for region_id in iter(external_predecessor_ids)
        if record_by_region_id[region_id].grouping_kind == "grouped_entry_candidate"
    )
    return (
        external_predecessor_ids,
        primary_entry_region_ids,
        entry_fragment_region_ids,
        ambiguous_predecessor_ids,
    )


@cython.ccall
def _process_shared_component_8616(
    shared_region_id: cython.longlong,
    shared_region_id_set: object,
    snapshot_nodes: object,
    record_by_region_id: object,
    visited_shared_region_ids: object,
) -> CrossEntryGroupedUnit | CrossEntryGroupedUnitRefusal:
    """Classify one shared-region component as a unit or a typed refusal."""
    refusal_reason: object
    component_shared_region_ids_tuple = _shared_component_8616(
        shared_region_id,
        shared_region_id_set,
        snapshot_nodes,
        visited_shared_region_ids,
    )
    anchor_shared_region_id = component_shared_region_ids_tuple[0]
    (
        external_predecessor_ids,
        primary_entry_region_ids,
        entry_fragment_region_ids,
        ambiguous_predecessor_ids,
    ) = _component_predecessor_groups_8616(
        component_shared_region_ids_tuple, snapshot_nodes, record_by_region_id,
    )
    refusal_reason = None
    if ambiguous_predecessor_ids:
        refusal_reason = "shared_predecessor_anchor"
    elif not primary_entry_region_ids and not entry_fragment_region_ids:
        refusal_reason = "no_external_entry_context"
    if refusal_reason is not None:
        return CrossEntryGroupedUnitRefusal(
            anchor_shared_region_id=anchor_shared_region_id,
            shared_region_ids=component_shared_region_ids_tuple,
            external_predecessor_region_ids=tuple(external_predecessor_ids),
            ambiguous_predecessor_region_ids=ambiguous_predecessor_ids,
            refusal_reason=refusal_reason,
        )
    member_region_ids = tuple(
        sorted(
            set(primary_entry_region_ids)
            | set(entry_fragment_region_ids)
            | set(component_shared_region_ids_tuple)
            | set(ambiguous_predecessor_ids)
        )
    )
    return CrossEntryGroupedUnit(
        anchor_shared_region_id=anchor_shared_region_id,
        primary_entry_region_ids=primary_entry_region_ids,
        entry_fragment_region_ids=entry_fragment_region_ids,
        shared_region_ids=component_shared_region_ids_tuple,
        member_region_ids=member_region_ids,
        refusal_reason=None,
    )


def build_x86_16_cross_entry_grouped_units(codegen: object) -> CrossEntryGroupedUnitArtifact | None:
    """Build grouped CFG units from existing structuring ownership artifacts."""
    grouping: object
    shared_region_id: object
    grouping = build_cfg_grouping_artifact(codegen)
    if grouping is None:
        return None

    record_by_region_id = {record.region_id: record for record in iter(grouping.records)}
    snapshot_nodes = {node.region_id: node for node in iter(grouping.indirect.ownership.snapshot.nodes)}
    shared_region_ids = tuple(sorted(grouping.grouped_entry_candidate_ids))
    shared_region_id_set = set(shared_region_ids)
    units: list[CrossEntryGroupedUnit] = []
    refusals: list[CrossEntryGroupedUnitRefusal] = []
    visited_shared_region_ids: set[cython.longlong] = set()

    for shared_region_id in shared_region_ids:
        if shared_region_id in visited_shared_region_ids:
            continue
        if shared_region_id not in snapshot_nodes:
            refusals.append(
                CrossEntryGroupedUnitRefusal(
                    anchor_shared_region_id=shared_region_id,
                    shared_region_ids=(shared_region_id,),
                    external_predecessor_region_ids=(),
                    ambiguous_predecessor_region_ids=(),
                    refusal_reason="missing_snapshot_node",
                )
            )
            continue
        outcome = _process_shared_component_8616(
            shared_region_id,
            shared_region_id_set,
            snapshot_nodes,
            record_by_region_id,
            visited_shared_region_ids,
        )
        if isinstance(outcome, CrossEntryGroupedUnitRefusal):
            refusals.append(outcome)
        else:
            units.append(outcome)

    return CrossEntryGroupedUnitArtifact(
        grouping=grouping,
        units=tuple(units),
        refusals=tuple(sorted(refusals, key=lambda item: item.anchor_shared_region_id)),
        refused_anchor_region_ids=tuple(sorted({item.anchor_shared_region_id for item in iter(refusals)})),
    )


@cython.ccall
def apply_x86_16_cross_entry_grouped_units(codegen: _CrossEntryGroupedUnitCodegen) -> cython.bint:
    """Attach grouped-unit artifacts to the codegen structuring boundary."""
    artifact: object
    artifact = build_x86_16_cross_entry_grouped_units(codegen)
    codegen._inertia_cross_entry_grouped_units = artifact
    if artifact is None:
        codegen._inertia_cross_entry_unit_members = ()
        return False
    member_region_ids = tuple(sorted({region_id for unit in iter(artifact.units) for region_id in iter(unit.member_region_ids)}))
    codegen._inertia_cross_entry_unit_members = member_region_ids
    return bool(artifact.units)


@cython.ccall
def describe_x86_16_cross_entry_grouped_unit_surface() -> dict[str, object]:
    """Describe the grouped-unit integration attributes for architecture tests."""
    return {
        "producer": "build_x86_16_cross_entry_grouped_units",
        "artifact_attr": "_inertia_cross_entry_grouped_units",
        "member_attr": "_inertia_cross_entry_unit_members",
        "purpose": "Materialize grouped multi-entry CFG units before region structuring.",
    }
