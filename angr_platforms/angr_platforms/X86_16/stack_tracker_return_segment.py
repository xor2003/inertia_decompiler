"""Consume proven machine frames and return segments in native stack tracking.

Layer: Frontend/angr compatibility.
Responsibility: apply authoritative Semantics return-frame and cleanup proofs after
angr accounts for one architecture word of return address. Do not infer far returns
from PUSH CS alone or alter aliases, C storage, or rendered output.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

import pyvex
from angr import Project
from angr.analyses.stack_pointer_tracker import (
    Constant,
    CouldNotResolveException,
    OffsetVal,
    StackPointerTracker,
    StackPointerTrackerState,
)
from angr.calling_conventions import SimStackArg
from angr.utils.types import dereference_simtype_by_lib

from .analysis_helpers import resolve_direct_call_target_from_block
from .semantics.call_return_frame_effects import MachineCallFrame8616, decode_machine_call_frame_8616
from .semantics.call_return_segment import callee_return_evidence_8616, collect_return_segment_frames_8616
from .semantics.terminal_stack_cleanup import TerminalReturnFrameKind8616

_WORD_BITS = 16


@dataclass(frozen=True, slots=True)
class NativeMachineCallFrameResult8616:
    """Closed census for one native machine-frame reconciliation."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    frame: MachineCallFrame8616 | None
    adjustment: int | None


def apply_native_machine_call_frame_8616(
    tracker: StackPointerTracker, vex: pyvex.IRSB,
    state: StackPointerTrackerState, callsite: int | None,
) -> NativeMachineCallFrameResult8616:
    """Replace native fixed-word return popping with the encoded CALL frame.

    This accounts only for the machine frame on the existing returning-call
    transfer. It proves neither callee argument cleanup nor register preservation.
    """
    arch = tracker.project.arch
    if arch.name != "86_16" or vex.jumpkind != "Ijk_Call" or arch.sp_offset not in tracker.reg_offsets:
        return NativeMachineCallFrameResult8616(0, 0, 0, 0, 0, None, None)
    frame = None if callsite is None else decode_machine_call_frame_8616(tracker.project, callsite)
    if frame is None or frame.return_addr != vex.addr + vex.size:
        state.put(arch.sp_offset, None, force=True)
        return NativeMachineCallFrameResult8616(1, 0, 0, 0, 1, frame, None)
    adjustment = frame.frame_bytes - (arch.bytes if arch.call_pushes_ret else 0)
    try:
        current = state.get(arch.sp_offset)
    except CouldNotResolveException:
        return NativeMachineCallFrameResult8616(1, 1, 0, 0, 1, frame, adjustment)
    if not isinstance(current, (OffsetVal, Constant)):
        return NativeMachineCallFrameResult8616(1, 1, 0, 0, 1, frame, adjustment)
    if adjustment:
        state.put(arch.sp_offset, current + Constant(adjustment), force=True)
    return NativeMachineCallFrameResult8616(1, 1, 1, 1, 0, frame, adjustment)


class _ExactSliceBoundary8616(Protocol):
    """Original-image attachment identifying an exact-region project."""

    _inertia_original_project: Project


def _cleanup_target_8616(project: Project, vex: pyvex.IRSB) -> int | None:
    """Keep targets in the coordinate domain consumed by return evidence."""
    try:
        original = cast(_ExactSliceBoundary8616, project)._inertia_original_project
    except AttributeError:
        original = None
    if isinstance(original, Project) and isinstance(vex.next, pyvex.expr.Const):
        # Exact-region targets are slice-relative; return evidence rebases once.
        return int(vex.next.con.value)
    # In a full image a near VEX target is an IP, not a loaded address.
    return cast(int | None, resolve_direct_call_target_from_block(project, vex.addr))


def _native_cleanup_bytes(tracker: StackPointerTracker, node: object) -> int:
    """Mirror the installed angr cleanup projection so it is not counted twice.

    This is backend compatibility, not evidence of the binary's convention.
    angr selects the first callee with a cleanup convention and a prototype.
    """
    callees = [] if tracker._func is None else tracker._find_callees(node)
    for callee in callees:
        convention = callee.calling_convention
        prototype = callee.prototype
        if convention is None or not convention.CALLEE_CLEANUP or prototype is None:
            continue
        if callee.prototype_libname:
            prototype = dereference_simtype_by_lib(prototype, callee.prototype_libname)
        locations = convention.arg_locs(prototype)
        return int(tracker.project.arch.bytes) * sum(isinstance(location, SimStackArg) for location in locations)
    return 0


def apply_native_argument_cleanup_8616(
    tracker: StackPointerTracker, node: object, vex: pyvex.IRSB,
    state: StackPointerTrackerState,
) -> None:
    """Replace prototype-derived near cleanup with a complete binary proof."""
    if tracker.project.arch.name != "86_16" or vex.jumpkind != "Ijk_Call":
        return
    sp_offset = tracker.project.arch.sp_offset
    if sp_offset not in tracker.reg_offsets or not isinstance(vex.next, pyvex.expr.Const):
        return
    target = _cleanup_target_8616(tracker.project, vex)
    if target is None:
        return
    evidence = callee_return_evidence_8616(tracker.project, target)
    compatible_frame = (
        evidence.complete
        and evidence.consistent_return_frame_kind is TerminalReturnFrameKind8616.NEAR
        and evidence.consistent_return_operand_bits == _WORD_BITS
    )
    cleanup = evidence.consistent_cleanup
    if not compatible_frame or cleanup is None:
        return
    adjustment = cleanup - _native_cleanup_bytes(tracker, node)
    if adjustment == 0:
        return
    try:
        current = state.get(sp_offset)
    except CouldNotResolveException:
        return
    if isinstance(current, (OffsetVal, Constant)):
        state.put(sp_offset, current + Constant(adjustment), force=True)


def apply_native_return_segment_8616(
    tracker: StackPointerTracker, vex: pyvex.IRSB,
    state: StackPointerTrackerState, callsite: int | None,
) -> None:
    """Consume a proved extra CS slot without repeating return-kind inference."""
    if tracker.project.arch.name != "86_16" or vex.jumpkind != "Ijk_Call" or callsite is None:
        return
    sp_offset = tracker.project.arch.sp_offset
    if sp_offset not in tracker.reg_offsets or tracker._func is None:
        return
    frames = collect_return_segment_frames_8616(
        tracker.project, tracker._func, {callsite: vex.addr + vex.size},
        block_addr=vex.addr,
    )
    if len(frames) != 1:
        return
    adjustment = frames[0].additional_return_bytes
    if adjustment is None:
        return
    try:
        current = state.get(sp_offset)
    except CouldNotResolveException:
        return
    if isinstance(current, (OffsetVal, Constant)):
        state.put(sp_offset, current + Constant(adjustment), force=True)
