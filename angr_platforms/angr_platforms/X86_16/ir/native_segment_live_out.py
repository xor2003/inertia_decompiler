"""Preserve architectural segment outputs in native SSA reaching definitions.

Layer: IR/native SSA adapter.
Responsibility: publish uses of segment definitions reaching machine returns.
Segment state is caller-visible independently of a source-language return type
or a general-purpose callee-saved register convention. Native DCE must consume
these uses before deleting definitions. Existing IR state and lowering retain
ownership of segment values and their C projection; this pass recovers neither.

Only reaching definitions are retained, not every historical segment write.
This boundary does not claim interprocedural call-clobber recovery or repair
effects already lost upstream. No assembly, rendered C, names or sidecars are
used as evidence.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, cast

from angr.ailment.statement import Return
from angr.analyses.s_reaching_definitions.s_rda_view import SRDAView
from angr.analyses.s_reaching_definitions.s_reaching_definitions import SReachingDefinitions
from angr.code_location import AILCodeLocation
from angr.knowledge_plugins.key_definitions.constants import ObservationPoint, ObservationPointType

from .segment_state_transfer import SEGMENT_REGISTERS


@dataclass(frozen=True, slots=True)
class NativeSegmentLiveOutReport8616:
    """Census of native segment definitions consumed as return-boundary uses."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


class _NativeSegmentBoundary8616(Protocol):
    """Owned report attached to the dynamic third-party analysis instance."""

    _inertia_segment_live_out_report_8616: NativeSegmentLiveOutReport8616


def preserve_native_segment_live_outs_8616(analysis: SReachingDefinitions) -> NativeSegmentLiveOutReport8616:
    """Add return uses for exactly the segment versions reaching each return."""
    graph = analysis.func_graph
    if analysis.project.arch.name != "86_16" or analysis.func is None or graph is None:
        return NativeSegmentLiveOutReport8616()
    blocks = {(block.addr, block.idx): block for block in graph}
    points: list[ObservationPoint] = [
        ("node", key, ObservationPointType.OP_AFTER)
        for key, block in blocks.items()
        if block.statements and isinstance(block.statements[-1], Return)
    ]
    if not points:
        return NativeSegmentLiveOutReport8616()
    observations = SRDAView(analysis.model).observe(points, entry=blocks.get((analysis.func_addr, None)))
    count = 0
    for (_, key, _), registers in observations.items():
        block = blocks[key]
        terminal = block.statements[-1]
        location = AILCodeLocation(block.addr, block.idx, len(block.statements) - 1, terminal.tags.get("ins_addr"))
        for name in sorted(SEGMENT_REGISTERS):
            offset, _size = analysis.project.arch.registers[name]
            # Retain every observed view: a partial or unexpected width is not
            # evidence that the architectural output can be discarded.
            for variable_id in set(registers.get(offset, {}).values()):
                if (None, location) not in analysis.model.all_vvar_uses[variable_id]:
                    analysis.model.add_vvar_use(variable_id, None, location)
                count += 1
    return NativeSegmentLiveOutReport8616(count, count, count, count, 0)


def apply_native_segment_live_out_compatibility_8616() -> None:
    """Install segment-use publication after native SSA model construction."""
    original = cast(Callable[[SReachingDefinitions], None], SReachingDefinitions._analyze)
    if original.__name__ == "_analyze_with_segment_live_outs_8616":
        return

    def _analyze_with_segment_live_outs_8616(self: SReachingDefinitions) -> None:
        """Keep native analysis intact and publish the architecture's outputs."""
        original(self)
        report = preserve_native_segment_live_outs_8616(self)
        cast(_NativeSegmentBoundary8616, self)._inertia_segment_live_out_report_8616 = report

    SReachingDefinitions._analyze = _analyze_with_segment_live_outs_8616
