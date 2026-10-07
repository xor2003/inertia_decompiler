"""Fail-closed abnormal-loop eligibility for region structuring.

Layer: Structuring.
Responsibility: require explicit typed eligibility before any future abnormal-loop work.
Forbidden: default-allow eligibility, graph mutation, region collapse, or C mutation.

Package ownership contract (canonical inertia/structuring package):
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from inertia.structuring.natural_loop_topology import (
    LoopTopologyVerdict8616,
    NaturalLoopTopology8616,
)
from inertia.structuring.structuring_analysis import StructureAnalysis
from inertia.structuring.structuring_region import DominatorInfo, Region, RegionGraph


@dataclass(frozen=True, slots=True)
class LoopEdgeRef:
    """Stable metadata reference for an edge between two region ids."""

    source_region_id: int | None
    target_region_id: int | None

    def to_dict(self) -> dict[str, int | None]:
        """Serialize this edge reference for structuring metadata."""
        return {
            "source_region_id": self.source_region_id,
            "target_region_id": self.target_region_id,
        }


@dataclass(frozen=True, slots=True)
class AbnormalLoopNormalizationPlan:
    """Typed eligibility result for a future abnormal-loop normalization slice."""

    verdict: LoopTopologyVerdict8616
    header_region_id: int
    body_region_ids: tuple[int, ...]
    abnormal_entries: tuple[LoopEdgeRef, ...]
    abnormal_exits: tuple[LoopEdgeRef, ...]
    entry_variable_name: str | None
    exit_variable_name: str | None
    refusal_reason: str | None = None

    @property
    def needs_entry_variable(self) -> bool:
        """Return whether abnormal entries require a selector variable."""
        return bool(self.abnormal_entries)

    @property
    def needs_exit_variable(self) -> bool:
        """Return whether multiple exits require a selector variable."""
        return bool(self.abnormal_exits)

    @property
    def can_normalize(self) -> bool:
        """Return whether exact proof authorizes a selector materialization."""
        return self.verdict is LoopTopologyVerdict8616.PROVEN and bool(
            self.entry_variable_name or self.exit_variable_name
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize this plan for region metadata and diagnostics."""
        return {
            "verdict": self.verdict.value,
            "header_region_id": self.header_region_id,
            "body_region_ids": list(self.body_region_ids),
            "abnormal_entries": [edge.to_dict() for edge in self.abnormal_entries],
            "abnormal_exits": [edge.to_dict() for edge in self.abnormal_exits],
            "entry_variable_name": self.entry_variable_name,
            "exit_variable_name": self.exit_variable_name,
            "refusal_reason": self.refusal_reason,
            "can_normalize": self.can_normalize,
        }


def build_abnormal_loop_normalization_plan(
    graph: RegionGraph,
    dominators: DominatorInfo | None,
    topology: NaturalLoopTopology8616,
) -> AbnormalLoopNormalizationPlan:
    """Default-deny abnormal normalization without exact typed eligibility."""
    del dominators
    matching_headers = tuple(region for region in graph.nodes if region.region_id == topology.header)
    reason: str | None
    if len(matching_headers) != 1:
        verdict = LoopTopologyVerdict8616.UNKNOWN_REFUSE
        reason = "missing-topology-header"
    else:
        header = matching_headers[0]
        eligibility_key = "typed_ir_allow_abnormal_loop_normalization"
        if eligibility_key not in header.metadata:
            verdict = LoopTopologyVerdict8616.UNKNOWN_REFUSE
            reason = "missing-typed-condition-eligibility"
        elif header.metadata[eligibility_key] is not True:
            verdict = LoopTopologyVerdict8616.UNKNOWN_REFUSE
            reason = "typed-condition-eligibility-not-proven"
        else:
            verdict = topology.verdict
            reason = topology.refusal_reason

    return AbnormalLoopNormalizationPlan(
        verdict=verdict,
        header_region_id=topology.header,
        body_region_ids=topology.body,
        abnormal_entries=(),
        abnormal_exits=(),
        entry_variable_name=None,
        exit_variable_name=None,
        refusal_reason=reason,
    )


def apply_abnormal_loop_normalization(
    graph: RegionGraph,
    header: Region,
    topology: NaturalLoopTopology8616,
    plan: AbnormalLoopNormalizationPlan,
) -> bool:
    """Refuse mutation until a later slice proves abnormal topology and conditions."""
    del graph, header, topology, plan
    return False


class AbnormalLoopStructureAnalysis(StructureAnalysis):
    """Analysis variant that inherits mutation-free natural-loop publication."""


__all__ = [
    "AbnormalLoopNormalizationPlan",
    "AbnormalLoopStructureAnalysis",
    "LoopEdgeRef",
    "apply_abnormal_loop_normalization",
    "build_abnormal_loop_normalization_plan",
]
