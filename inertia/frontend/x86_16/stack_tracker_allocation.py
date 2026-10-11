"""Consume proven call-frame effects in angr's native stack tracker.

Layer: Frontend/angr compatibility.
Responsibility: project authoritative Semantics allocation, argument cleanup and
separately pushed return-segment proofs into the native tracker before successor states,
propagation and variable recovery. Native function-mode tracking consumes the
originating function manager KB for callee identity, without changing variable KBs.
Do not recover storage, guess allocations, mutate C or infer helper names.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from typing import Any, Protocol, cast

import pyvex
from angr.analyses.stack_pointer_tracker import (
    StackPointerTracker,
    StackPointerTrackerState,
)
from angr.knowledge_plugins.functions.function import Function

from inertia.ir import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.semantics.call_stack_allocation import (
    binary_stack_allocation_target_8616,
    collect_call_stack_allocation_candidates_8616,
)

from .function_knowledge_base import function_knowledge_base_8616
from .stack_tracker_return_segment import (
    NativeMachineCallFrameResult8616,
    _bound_terminal_direct_call_8616,
    apply_native_argument_cleanup_8616,
    apply_native_machine_call_frame_8616,
    apply_native_return_segment_8616,
)

_PATCH_NAME = "_process_vex_allocations_8616"
type _ProcessVex8616 = Callable[[StackPointerTracker, object, pyvex.IRSB, StackPointerTrackerState], int | None]


class _NativeFrameEvidence8616(Protocol):
    """Owned frame-reconciliation census attached to a native tracker."""

    _inertia_machine_call_frames_8616: tuple[NativeMachineCallFrameResult8616, ...]


def _bind_proven_call_target_8616(
    block: IRBlock, instruction: IRInstr, target: int,
) -> IRBlock:
    """Rebind one proven CALL operand to its evidence-bound constant.

    The constant is written only after the direct-near binding proof has
    verified the retained symbolic operand DAG, its block-``next`` origin,
    the native re-lift and the mapped ``E8`` bytes, so the substitution is
    the semantic owner's own proven target — never a decoded-address guess
    or a rewrite of an unbound operand.
    """
    return replace(
        block,
        instrs=tuple(
            replace(
                entry,
                args=(IRValue(MemSpace.CONST, const=target, size=4),),
            )
            if entry is instruction
            else entry
            for entry in block.instrs
        ),
    )


def _apply_allocation(
    tracker: StackPointerTracker, vex: pyvex.IRSB,
    state: StackPointerTrackerState, callsite: int | None,
) -> None:
    """Keep guarded allocation identities from becoming scalar SP proofs.

    No authenticated guard-discharge owner currently exists. Retain the CALL
    while invalidating its scalar stack coordinate; ordinary calls stay intact.
    """
    if tracker.project.arch.name != "86_16" or vex.jumpkind != "Ijk_Call" or callsite is None:
        return
    sp_offset = tracker.project.arch.sp_offset
    if sp_offset not in tracker.reg_offsets:
        return
    bound = _bound_terminal_direct_call_8616(tracker.project, vex)
    if bound is None:
        return
    block, instruction, target = bound
    if instruction.addr != callsite:
        return
    bound_block = _bind_proven_call_target_8616(block, instruction, target)
    artifact = IRFunctionArtifact(vex.addr, (bound_block,))
    candidate = collect_call_stack_allocation_candidates_8616(tracker.project, artifact).get(callsite)
    allocating = candidate is not None or any(
        entry.op == "CALL" and entry.addr == callsite
        and binary_stack_allocation_target_8616(tracker.project, entry) is not None
        for entry in bound_block.instrs
    )
    if allocating:
        state.put(sp_offset, None, force=True)


_TRACKER_INIT_PATCHED_8616 = False


def _bind_native_stack_tracker_function_kb_8616() -> None:
    """Retain the explicit native function's KB for tracker callee lookups."""
    global _TRACKER_INIT_PATCHED_8616
    if _TRACKER_INIT_PATCHED_8616:
        return
    original = StackPointerTracker.__init__

    def _init_8616(self: StackPointerTracker, func: Function | None, *args: object, **kwargs: object) -> None:
        """Bind the originating manager before upstream analysis begins."""
        if func is not None and self.project.arch.name == "86_16":
            self.kb = function_knowledge_base_8616(self.project, func)
        cast(Any, original)(self, func, *args, **kwargs)

    cast(Any, StackPointerTracker).__init__ = _init_8616
    _TRACKER_INIT_PATCHED_8616 = True


def apply_x86_16_stack_tracker_allocations_8616() -> None:
    """Install the idempotent adapter without changing other architectures."""
    _bind_native_stack_tracker_function_kb_8616()
    original = cast(_ProcessVex8616, StackPointerTracker._process_vex_irsb)
    if original.__name__ == _PATCH_NAME:
        return

    def _process_vex_allocations_8616(
        self: StackPointerTracker, node: object, vex_block: pyvex.IRSB, state: StackPointerTrackerState,
    ) -> int | None:
        """Reconcile proven cleanup, allocation and extra slots after native transfer."""
        callsite = original(self, node, vex_block, state)
        result = apply_native_machine_call_frame_8616(self, vex_block, state, callsite)
        if result.raw_fact_count:
            surface = cast(_NativeFrameEvidence8616, self)
            try:
                prior = surface._inertia_machine_call_frames_8616
            except AttributeError:
                prior = ()
            surface._inertia_machine_call_frames_8616 = (*prior, result)
        apply_native_argument_cleanup_8616(self, node, vex_block, state)
        _apply_allocation(self, vex_block, state, callsite)
        apply_native_return_segment_8616(self, vex_block, state, callsite)
        return callsite

    StackPointerTracker._process_vex_irsb = _process_vex_allocations_8616
