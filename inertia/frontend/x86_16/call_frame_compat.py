# cython: language_level=3, infer_types=True
"""Consume proven machine CALL frames at the source-call boundary.

Layer: Frontend/IR adapter.
Responsibility: consume exact Semantics-owned CALL frame effects before AIL
SSA folds them into subsequent numeric SP values. A returning high-level CALL
owns its machine return frame; argument pushes remain independent. A separate
adapter then projects proven callee argument cleanup onto narrow scalar SP.
Decoded RET cleanup also prevents native ABI inference from counting a wider
machine return address as callee argument cleanup.
Missing return edges, duplicate projections and role mismatches refuse the
whole call. This is not instruction execution, stack identity recovery, or DCE.
Do not infer effects from names, source, assembly text or generated C.
"""

from __future__ import annotations
import typing
import cython

from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, cast

import networkx as nx
from angr.ailment.block import Block
from angr.ailment.expression import Call, Register
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment, SideEffectStatement, Statement, Store
from angr.analyses.calling_convention.fact_collector import FactCollector
from angr.analyses.decompiler.clinic import Clinic

from inertia.ir.stack_pointer_provenance import StackPointerProvenance8616, collect_stack_pointer_provenance_8616
from inertia.semantics.call_return_frame_effects import (
    CallReturnFrameEffectKey8616,
    CallReturnFrameEffectRole8616,
    collect_call_return_frame_effects_8616,
)
from inertia.semantics.call_return_segment import (
    ReturnFrame8616,
    ReturnSegmentFrame8616,
    collect_function_return_frames_8616,
    collect_return_segment_frames_8616,
)

from .call_cleanup_compat import CalleeCleanupReport8616, materialize_callee_cleanup_8616
import dataclasses
import operator
import builtins


@dataclasses.dataclass(frozen=True, )
class CallFrameBoundaryStats8616:
    """Call census and exact effect materialization counts for one graph."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0
    return_segment_frames: tuple[ReturnSegmentFrame8616, ...] = ()
    accepted_calls: tuple[cython.longlong, ...] = ()


@dataclasses.dataclass(frozen=True, )
class ReturnCleanupEvidence8616:
    """Closed endpoint census consumed by native argument-cleanup inference."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    frames: object
    cleanup_bytes: int | None


class _FactCollectorBoundary8616(Protocol):
    """Owned proof attached at the native fact-collector boundary."""

    _inertia_return_cleanup_evidence_8616: ReturnCleanupEvidence8616


def _effect_key_8616(statement: Statement) -> CallReturnFrameEffectKey8616 | None:
    """Read exact source identity without using an expression's apparent shape."""
    address: object
    block: object
    index: object
    address = statement.tags.get("ins_addr")
    block = statement.tags.get("vex_block_addr")
    index = statement.tags.get("vex_stmt_idx")
    if not all(isinstance(value, int) for value in iter((address, block, index))):
        return None
    return CallReturnFrameEffectKey8616(address, block, index)


def _scan_returning_calls_8616(
    graph: nx.DiGraph[Block],
) -> tuple[
    dict[cython.longlong, cython.longlong],
    dict[CallReturnFrameEffectKey8616, list[tuple[Block, Statement]]],
    cython.longlong,
]:
    """Index tagged statements and census unique CALL sites with return edges."""
    address: object
    key: object
    block: object
    statement: object
    calls: dict[cython.longlong, cython.longlong] = {}
    raw_count = 0
    occurrences: Counter[cython.longlong] = Counter()
    locations: object = defaultdict(list)
    for block in graph:
        for statement in block.statements:
            key = _effect_key_8616(statement)
            if key is not None:
                locations[key].append((block, statement))
            if not (isinstance(statement, SideEffectStatement) and isinstance(statement.expr, Call)):
                continue
            raw_count += 1
            address = statement.tags.get("ins_addr")
            if not isinstance(address, int):
                continue
            occurrences[address] += 1
            return_addr = block.addr + block.original_size
            if any(operator.eq(successor.addr, return_addr) for successor in builtins.iter(graph.successors(block))):
                calls[address] = return_addr
    unique_calls = {address: target for address, target in builtins.iter(calls.items()) if occurrences[address] == 1}
    return unique_calls, locations, raw_count


@cython.ccall
def _effect_role_matches_8616(
    role: CallReturnFrameEffectRole8616,
    statement: Statement,
    sp_offset: cython.longlong,
) -> cython.bint:
    """Return whether one uniquely located statement plays the proven role."""
    if role is CallReturnFrameEffectRole8616.STACK_STORE:
        return isinstance(statement, Store)
    return (
        role is CallReturnFrameEffectRole8616.STACK_POINTER_UPDATE
        and isinstance(statement, Assignment)
        and isinstance(statement.dst, Register)
        and operator.eq(statement.dst.reg_offset, sp_offset)
    )


@cython.ccall
def _match_segment_frame_effects_8616(
    segment_frames: object,
    locations: object,
    by_call: object,
    refused: object,
    sp_offset: cython.longlong,
) -> None:
    """Bind segment-frame effects to located statements or refuse the call."""
    matches: object
    effect: object
    frame: object
    for frame in segment_frames:
        if frame.refusal is not None or frame.callsite_addr not in by_call:
            continue
        for effect in frame.effects:
            # Native AIL tags use the effect's instruction address, not its CALL owner.
            key = CallReturnFrameEffectKey8616(effect.source_addr, effect.vex_block_addr, effect.vex_stmt_idx)
            matches = locations.get(key, [])
            if len(matches) != 1:
                refused.add(frame.callsite_addr)
                continue
            block, statement = matches[0]
            if _effect_role_matches_8616(effect.role, statement, sp_offset):
                by_call[frame.callsite_addr].append((block, statement))
            else:
                refused.add(frame.callsite_addr)


@cython.ccall
def consume_returning_call_frames_8616(
    project: object, function: object, graph: nx.DiGraph[Block], *, sp_offset: cython.longlong,
) -> CallFrameBoundaryStats8616:
    """Consume complete, uniquely projected frames for calls with return edges."""
    matches: object
    block: object
    fact: object
    calls, locations, raw_count = _scan_returning_calls_8616(graph)
    if not calls:
        return CallFrameBoundaryStats8616(raw_fact_count=raw_count, failure_count=raw_count)
    collection = collect_call_return_frame_effects_8616(project, function, calls)
    by_call: object = defaultdict(list)
    refused: set[cython.longlong] = set()
    for fact in collection.effects:
        matches = locations.get(fact.key, [])
        if len(matches) != 1:
            refused.add(fact.key.callsite_addr)
            continue
        block, statement = matches[0]
        if not _effect_role_matches_8616(fact.role, statement, sp_offset):
            refused.add(fact.key.callsite_addr)
            continue
        by_call[fact.key.callsite_addr].append((block, statement))
    segment_frames = collect_return_segment_frames_8616(project, function, calls)
    _match_segment_frame_effects_8616(segment_frames, locations, by_call, refused, sp_offset)
    accepted = {address: items for address, items in builtins.iter(by_call.items()) if address not in refused}
    removal_ids = {id(statement) for items in builtins.iter(accepted.values()) for _block, statement in iter(items)}
    for block in graph:
        block.statements = [statement for statement in iter(block.statements) if id(statement) not in removal_ids]
    return CallFrameBoundaryStats8616(
        raw_fact_count=raw_count, normalized_fact_count=len(calls),
        classified_fact_count=len(removal_ids), materialized_count=len(removal_ids),
        failure_count=raw_count - len(accepted),
        return_segment_frames=segment_frames,
        accepted_calls=tuple(sorted(accepted)),
    )


class _ArchitectureBoundary8616(Protocol):
    """Native architecture fields needed at the AIL adapter boundary."""

    name: object
    sp_offset: int | None


class _ProjectBoundary8616(Protocol):
    """Native project architecture consumed without dynamic field discovery."""

    arch: _ArchitectureBoundary8616


class _ClinicBoundary8616(Protocol):
    """Native Clinic graph and owned materialization report."""

    project: _ProjectBoundary8616
    function: object
    _ail_graph: nx.DiGraph[Block]
    _ail_manager: Manager
    _inertia_call_frame_boundary_stats_8616: CallFrameBoundaryStats8616
    _inertia_stack_pointer_provenance_8616: StackPointerProvenance8616
    _inertia_callee_cleanup_report_8616: CalleeCleanupReport8616


def apply_call_frame_compatibility_8616() -> None:
    """Install the pre-SSA consumer once, leaving other architectures unchanged."""
    _apply_return_cleanup_compatibility_8616()
    original = cast(Callable[[Clinic], None], Clinic._stage_pre_ssa_level0_fixups)
    if original.__name__ == "_pre_ssa_call_frame_boundary_8616":
        return

    def _pre_ssa_call_frame_boundary_8616(self: Clinic) -> None:
        """Consume proven source-call frames after native graph fixups."""
        original(self)
        clinic = cast(_ClinicBoundary8616, self)
        arch = clinic.project.arch
        if arch.name != "86_16" or arch.sp_offset is None:
            return
        clinic._inertia_call_frame_boundary_stats_8616 = consume_returning_call_frames_8616(
            clinic.project, clinic.function, clinic._ail_graph, sp_offset=arch.sp_offset,
        )
        clinic._inertia_callee_cleanup_report_8616 = materialize_callee_cleanup_8616(
            clinic.project, clinic._ail_graph, clinic._ail_manager,
            clinic._inertia_call_frame_boundary_stats_8616.accepted_calls, sp_offset=arch.sp_offset,
        )
        clinic._inertia_stack_pointer_provenance_8616 = collect_stack_pointer_provenance_8616(
            clinic._ail_graph, sp_offset=arch.sp_offset,
        )

    Clinic._stage_pre_ssa_level0_fixups = _pre_ssa_call_frame_boundary_8616


def _apply_return_cleanup_compatibility_8616() -> None:
    """Keep return-frame width out of native callee argument-cleanup inference."""
    original = cast(Callable[[FactCollector], int], FactCollector._analyze_endpoints_for_extrapop)
    if original.__name__ == "_return_cleanup_8616":
        return

    def _return_cleanup_8616(self: FactCollector) -> cython.longlong:
        """Use decoded RET cleanup only when all function endpoints agree."""
        selected: object
        if self.project.arch.name == "86_16":
            frames = collect_function_return_frames_8616(self.project, self.function)
            cleanup: set[cython.longlong] = {frame.cleanup_bytes for frame in iter(frames or ())}
            selected = next(iter(cleanup)) if len(cleanup) == 1 else None
            raw = len(self.function.endpoints)
            normalized = len(frames or ())
            consumed = normalized if selected is not None else 0
            cast(_FactCollectorBoundary8616, self)._inertia_return_cleanup_evidence_8616 = ReturnCleanupEvidence8616(
                raw, normalized, consumed, consumed, raw - consumed, frames or (), selected,
            )
            if selected is not None:
                return selected
        return original(self)

    FactCollector._analyze_endpoints_for_extrapop = _return_cleanup_8616
