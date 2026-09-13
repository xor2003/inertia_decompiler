"""Preserve architectural segment outputs in native SSA reaching definitions.

Layer: IR/native SSA adapter.
Responsibility: publish segment return uses and retain stack-backed GP outputs
until owned Alias/Lowering can discharge their segmented restore effects.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
Segment state is caller-visible independently of a source-language return type
or a general-purpose callee-saved register convention. Native DCE must consume
these uses before deleting definitions. Existing IR state and lowering retain
ownership of segment values and their C projection; this pass recovers neither.

Only reaching definitions are retained, not every historical segment write.
This boundary does not claim interprocedural call-clobber recovery or repair
effects already lost upstream. No assembly, rendered C, names or sidecars are
used as evidence.

Native stack-SSA conversion does not prove that segmented register-save areas
were removed. Retain reaching GP definitions that still read negative entry-SP
storage with authoritative native address provenance. This is conservative
retention, not proof that a value equals its entry value or permission to prune
its save. Arithmetic-only outputs are not retained by this additional guard.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, cast

from angr.ailment import Block
from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import Expression, Load, UnaryOp, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, Return, Statement
from angr.analyses.s_reaching_definitions.s_rda_view import SRDAView
from angr.analyses.s_reaching_definitions.s_reaching_definitions import SReachingDefinitions
from angr.code_location import AILCodeLocation
from angr.knowledge_plugins.key_definitions.constants import ObservationPoint, ObservationPointType

from .native_stack_anchor import native_stack_anchor_8616
from .segment_state_transfer import SEGMENT_REGISTERS


@dataclass(frozen=True, slots=True)
class NativeSegmentLiveOutReport8616:
    """Native return-use census with a separate retained stack-output count."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    stack_output_count: int = 0


class _StackLoadAnchorViewer8616:
    """Find proven negative entry-SP origins inside native memory-load addresses."""

    def __init__(self) -> None:
        """Start one source-expression inspection with no load context."""
        self._viewer: AILBlockViewer = AILBlockViewer()
        self._viewer.expr_handlers[Load] = self._handle_Load
        self._viewer.expr_handlers[UnaryOp] = self._handle_UnaryOp
        self.load_depth: int = 0
        self.has_stack_load: bool = False

    def walk_expression(self, expression: Expression) -> None:
        """Visit one expression using the native walker's complete child schema."""
        self._viewer.walk_expression(expression)

    def _handle_Load(
        self, expr_idx: int, expr: Load, stmt_idx: int,
        stmt: Statement | None, block: Block | None,
    ) -> None:
        """Restrict provenance inspection to actual native load addresses."""
        self.load_depth += 1
        try:
            self._viewer._handle_Load(expr_idx, expr, stmt_idx, stmt, block)
        finally:
            self.load_depth -= 1

    def _handle_UnaryOp(
        self, expr_idx: int, expr: UnaryOp, stmt_idx: int,
        stmt: Statement | None, block: Block | None,
    ) -> None:
        """Consume the frontend's coordinate tag, never apparent local offsets."""
        anchor = native_stack_anchor_8616(expr.tags)
        if self.load_depth and anchor is not None and anchor.entry_sp_offset < 0:
            self.has_stack_load = True
        self._viewer._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)


def _stack_output_ids_8616(analysis: SReachingDefinitions) -> frozenset[int]:
    """Find remaining stack-backed GP definitions without inventing save pairs."""
    arch = analysis.project.arch
    frame_offsets = {arch.sp_offset, arch.bp_offset, arch.ip_offset}
    offsets = {
        reg.vex_offset for reg in arch.register_list
        if reg.general_purpose and reg.vex_offset not in frame_offsets
    }
    candidates: set[int] = set()
    for block in analysis.func_graph:
        for statement in block.statements:
            if not isinstance(statement, Assignment):
                continue
            destination = statement.dst
            if not isinstance(destination, VirtualVariable):
                continue
            if destination.category != VirtualVariableCategory.REGISTER or destination.oident not in offsets:
                continue
            viewer = _StackLoadAnchorViewer8616()
            viewer.walk_expression(statement.src)
            if viewer.has_stack_load:
                candidates.add(destination.varid)
    return frozenset(candidates)


class _NativeSegmentBoundary8616(Protocol):
    """Owned report attached to the dynamic third-party analysis instance."""

    _inertia_segment_live_out_report_8616: NativeSegmentLiveOutReport8616


def preserve_native_segment_live_outs_8616(analysis: SReachingDefinitions) -> NativeSegmentLiveOutReport8616:
    """Retain reaching segments and still-unresolved stack-backed GP outputs."""
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
    stack_count = 0
    stack_outputs = _stack_output_ids_8616(analysis)
    for (_, key, _), registers in observations.items():
        block = blocks[key]
        terminal = block.statements[-1]
        location = AILCodeLocation(block.addr, block.idx, len(block.statements) - 1, terminal.tags.get("ins_addr"))
        reaching_stack_outputs = {
            variable_id for views in registers.values() for variable_id in views.values()
            if variable_id in stack_outputs
        }
        for variable_id in reaching_stack_outputs:
            if (None, location) not in analysis.model.all_vvar_uses[variable_id]:
                analysis.model.add_vvar_use(variable_id, None, location)
            count += 1
            stack_count += 1
        for name in sorted(SEGMENT_REGISTERS):
            offset, _size = analysis.project.arch.registers[name]
            # Retain every observed view: a partial or unexpected width is not
            # evidence that the architectural output can be discarded.
            for variable_id in set(registers.get(offset, {}).values()):
                if (None, location) not in analysis.model.all_vvar_uses[variable_id]:
                    analysis.model.add_vvar_use(variable_id, None, location)
                count += 1
    return NativeSegmentLiveOutReport8616(count, count, count, count, 0, stack_count)


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
