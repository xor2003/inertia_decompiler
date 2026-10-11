"""Preserve architectural segment outputs in native SSA reaching definitions.

Layer: IR/native SSA adapter.
Responsibility: publish segment return uses, retain stack-backed GP outputs
until owned Alias/Lowering can discharge their segmented restore effects, and
retain reaching register definitions at unmodeled tail exits.
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

A terminal Jump or ConditionalJump whose target has no matching graph
successor leaves the modeled control domain: the unknown destination carries
no callee or caller evidence that could prove a reaching architectural
definition dead, so every observed reaching register view stays
observable. Constant targets matching graph successors remain subject to ordinary
dead-definition analysis. A symbolic target remains unknown even with graph
edges: those edges alone do not prove exhaustive successor coverage. This is
conservative retention only — it invents no control domain, no CS value and
no ABI contract for the unknown destination.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, cast

import networkx as nx
from angr.ailment import Block
from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import (
    Const,
    Expression,
    Load,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Return, Statement
from angr.analyses.s_reaching_definitions.s_rda_view import SRDAView
from angr.analyses.s_reaching_definitions.s_reaching_definitions import SReachingDefinitions
from angr.code_location import AILCodeLocation
from angr.knowledge_plugins.key_definitions.constants import ObservationPoint, ObservationPointType

from .native_stack_anchor import native_stack_anchor_8616
from .segment_state_transfer import SEGMENT_REGISTERS


@dataclass(frozen=True, slots=True)
class NativeSegmentLiveOutReport8616:
    """Native boundary-use census split by retained output kind."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    stack_output_count: int = 0
    unknown_exit_output_count: int = 0


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
    graph = analysis.func_graph
    if graph is None:
        return frozenset()
    arch = analysis.project.arch
    frame_offsets = {arch.sp_offset, arch.bp_offset, arch.ip_offset}
    offsets = {
        reg.vex_offset for reg in arch.register_list
        if reg.general_purpose and reg.vex_offset not in frame_offsets
    }
    candidates: set[int] = set()
    for block in graph:
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


def _unmodeled_exit_8616(graph: nx.DiGraph, block: Block) -> bool:
    """Whether a terminator transition lacks a matching graph successor."""
    successors = tuple(graph.successors(block))
    if not successors or any(not successor.statements for successor in successors):
        # A missing terminal or an empty successor supplies no dead-output
        # evidence. Observe the last represented instruction before the gap.
        return True
    terminal = block.statements[-1]
    targets: tuple[tuple[Expression | None, int | None], ...]
    if isinstance(terminal, Jump):
        targets = ((terminal.target, terminal.target_idx),)
    elif isinstance(terminal, ConditionalJump):
        targets = (
            (terminal.true_target, terminal.true_target_idx),
            (terminal.false_target, terminal.false_target_idx),
        )
    else:
        # No modeled control exit: with no successor there is no callee or
        # caller evidence proving the reaching definitions dead.
        return False
    successor_keys = {(successor.addr, successor.idx) for successor in successors}
    return any(
        not isinstance(target, Const) or (target.value_int, target_idx) not in successor_keys
        for target, target_idx in targets
    )


def _return_output_ids_8616(
    analysis: SReachingDefinitions,
    registers: dict[int, dict[int, int]],
    stack_outputs: frozenset[int],
) -> tuple[set[int], int]:
    """Select existing segment and unresolved stack-backed Return outputs."""
    outputs = {
        varid for views in registers.values() for varid in views.values()
        if varid in stack_outputs
    }
    stack_count = len(outputs)
    for name in SEGMENT_REGISTERS:
        offset, _size = analysis.project.arch.registers[name]
        # Every observed width remains live; a partial view is not dead proof.
        outputs.update(registers.get(offset, {}).values())
    return outputs, stack_count


def _boundary_observation_points_8616(graph: nx.DiGraph) -> list[ObservationPoint]:
    """Observe Returns and exits without exhaustive modeled successors."""
    points: list[ObservationPoint] = []
    for block in graph:
        if not block.statements:
            continue
        if isinstance(block.statements[-1], Return) or _unmodeled_exit_8616(graph, block):
            points.append(("node", (block.addr, block.idx), ObservationPointType.OP_AFTER))
    return points


def preserve_native_segment_live_outs_8616(analysis: SReachingDefinitions) -> NativeSegmentLiveOutReport8616:
    """Retain reaching segments, stack outputs and unmodeled-exit registers."""
    graph = analysis.func_graph
    if analysis.project.arch.name != "86_16" or analysis.func is None or graph is None:
        return NativeSegmentLiveOutReport8616()
    blocks = {(block.addr, block.idx): block for block in graph}
    points = _boundary_observation_points_8616(graph)
    if not points:
        return NativeSegmentLiveOutReport8616()
    observations = SRDAView(analysis.model).observe(
        points, entry=blocks.get((analysis.func_addr, None))
    )
    count = 0
    stack_count = 0
    unknown_count = 0
    stack_outputs = _stack_output_ids_8616(analysis)
    for (_, key, _), registers in observations.items():
        block = blocks[key]
        terminal = block.statements[-1]
        location = AILCodeLocation(
            block.addr, block.idx, len(block.statements) - 1, terminal.tags.get("ins_addr")
        )
        if isinstance(terminal, Return):
            outputs, reaching_stack_count = _return_output_ids_8616(analysis, registers, stack_outputs)
            stack_count += reaching_stack_count
        else:
            outputs = {varid for views in registers.values() for varid in views.values()}
            unknown_count += len(outputs)
        for variable_id in outputs:
            if (None, location) not in analysis.model.all_vvar_uses[variable_id]:
                analysis.model.add_vvar_use(variable_id, None, location)
        count += len(outputs)
    return NativeSegmentLiveOutReport8616(count, count, count, count, 0, stack_count, unknown_count)


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
