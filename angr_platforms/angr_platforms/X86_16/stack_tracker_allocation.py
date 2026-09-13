"""Consume proven call-frame effects in angr's native stack tracker.

Layer: Frontend/angr compatibility.
Responsibility: project authoritative Semantics allocation, argument cleanup and
separately pushed return-segment proofs into the native tracker before successor states,
propagation and variable recovery.
Do not recover storage, guess allocations, mutate C or infer helper names.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

import pyvex
from angr.analyses.stack_pointer_tracker import (
    Constant,
    CouldNotResolveException,
    OffsetVal,
    StackPointerTracker,
    StackPointerTrackerState,
)

from .ir import IRFunctionArtifact
from .ir.vex_import import _block_to_ir
from .semantics.call_stack_allocation import (
    binary_stack_allocation_target_8616,
    collect_call_stack_allocation_proofs_8616,
)
from .stack_tracker_return_segment import apply_native_argument_cleanup_8616, apply_native_return_segment_8616

_PATCH_NAME = "_process_vex_allocations_8616"
type _ProcessVex8616 = Callable[[StackPointerTracker, object, pyvex.IRSB, StackPointerTrackerState], int | None]


@dataclass(frozen=True, slots=True)
class _NativeBlock8616:
    """Existing VEX block surface for the owned IR importer; never relift."""

    addr: int
    vex: pyvex.IRSB


def _apply_allocation(
    tracker: StackPointerTracker, vex: pyvex.IRSB,
    state: StackPointerTrackerState, callsite: int | None,
) -> None:
    """Update a returning call's native state only with a matching IR proof."""
    if tracker.project.arch.name != "86_16" or vex.jumpkind != "Ijk_Call" or callsite is None:
        return
    sp_offset = tracker.project.arch.sp_offset
    if sp_offset not in tracker.reg_offsets:
        return
    block, _transport = _block_to_ir(_NativeBlock8616(vex.addr, vex))
    artifact = IRFunctionArtifact(vex.addr, (block,))
    proof = collect_call_stack_allocation_proofs_8616(tracker.project, artifact).get(callsite)
    if proof is None:
        allocating = any(instruction.op == "CALL" and instruction.addr == callsite
                         and binary_stack_allocation_target_8616(tracker.project, instruction) is not None
                         for instruction in block.instrs)
        if allocating:
            state.put(sp_offset, None, force=True)
        return
    try:
        current = state.get(sp_offset)
    except CouldNotResolveException:
        return
    if isinstance(current, (OffsetVal, Constant)):
        state.put(sp_offset, current - Constant(proof.allocation_size), force=True)


def apply_x86_16_stack_tracker_allocations_8616() -> None:
    """Install the idempotent adapter without changing other architectures."""
    original = cast(_ProcessVex8616, StackPointerTracker._process_vex_irsb)
    if original.__name__ == _PATCH_NAME:
        return

    def _process_vex_allocations_8616(
        self: StackPointerTracker, node: object, vex_block: pyvex.IRSB, state: StackPointerTrackerState,
    ) -> int | None:
        """Reconcile proven cleanup, allocation and extra slots after native transfer."""
        callsite = original(self, node, vex_block, state)
        apply_native_argument_cleanup_8616(self, node, vex_block, state)
        _apply_allocation(self, vex_block, state, callsite)
        apply_native_return_segment_8616(self, vex_block, state, callsite)
        return callsite

    StackPointerTracker._process_vex_irsb = _process_vex_allocations_8616
