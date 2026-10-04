"""Bind a local word lifetime to registered coverage and a real near CALL.

Layer: Alias.
Responsibility: consume Frontend/IR coverage and Semantics call identity while
retaining the local storage theorem. Proves a contextual input at callee entry,
not a stable callee LOAD, complete caller census, callee effect or ABI signature.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from ..call_target_identity import normalize_x86_16_direct_call_target_8616
from ..callsite_summary import CallsiteMachineFrameKind8616
from ..ir.core import IRBlock, IRInstr, IRValue, MemSpace
from ..ir.ir_boundary_cfg import IRBoundaryCoverageResult8616
from ..ir.logical_constant_word_receipt import LogicalConstantWordStats8616
from ..semantics.direct_ret_call_effect import direct_near_call_target_is_bound_8616
from .entry_stack_pointer_snapshots import EntryStackPointerSnapshots8616
from .stack_word_call_window import StackWordCallWindowReceipt8616, stack_byte_store_coordinate_8616


class StackWordCallBindingFailure8616(StrEnum):
    """Missing authority or conflicting evidence at the contextual boundary."""

    COVERAGE_UNPROVEN = "coverage_unproven"
    SOURCE_MISMATCH = "source_mismatch"
    LIFETIME_UNPROVEN = "lifetime_unproven"
    TARGET_UNPROVEN = "target_unproven"
    FRAME_UNPROVEN = "frame_unproven"


class _Image8616(Protocol):
    """Third-party absolute image bounds for exact target projection."""

    linked_base: int
    max_addr: int


class _Loader8616(Protocol):
    """Third-party loader image boundary."""

    main_object: _Image8616


class _Project8616(Protocol):
    """Third-party project boundary used only for target address projection."""

    loader: _Loader8616


def _target_matches_8616(
    project: object, block: IRBlock, instruction: IRInstr, target_addr: int, return_addr: int,
) -> bool:
    """Consume native symbolic proof or exact constant address identity."""
    if instruction.dst is not None or len(instruction.args) != 1:
        return False
    target = instruction.args[0]
    if not isinstance(target, IRValue):
        return False
    if target.space is not MemSpace.CONST:
        if type(instruction.addr) is not int:
            return False
        from ..semantics.direct_near_call_target_binding import (
            DirectNearCallCoordinates8616,
            DirectNearCallTargetBinding8616,
            prove_direct_near_call_target_binding_at_coordinates_8616,
        )

        binding: DirectNearCallTargetBinding8616 = prove_direct_near_call_target_binding_at_coordinates_8616(
            project, block=block, instruction=instruction,
            coordinates=DirectNearCallCoordinates8616(
                instruction.addr, return_addr, target_addr,
            ),
        )
        return bool(binding.complete and binding.target_addr == target_addr)
    if type(target.const) is not int:
        return False
    plain = (target.offset == 0 and target.source_tmp is None and target.version is None
             and target.index is None and not target.index_shift and not target.expr
             and target.call_output is None and target.memory_access_size is None)
    if not plain:
        return False
    try:
        image = cast(_Project8616, project).loader.main_object
        linked_base, image_end = image.linked_base, image.max_addr + 1
    except AttributeError:
        return False
    normalized: int | None = normalize_x86_16_direct_call_target_8616(target.const, linked_base, image_end)
    return normalized == target_addr


def _near_frame_matches_8616(window: StackWordCallWindowReceipt8616) -> bool:
    """Require the exact two-byte raw CALL envelope at current SP offsets0/1."""
    blocks = tuple(block for block in window.source_ir.blocks if block.addr == window.source.access.key.block_addr)
    if len(blocks) != 1:
        return False
    snapshots = EntryStackPointerSnapshots8616()
    before_frame: int | None = None
    frame_coordinates: list[int] = []
    for index, instruction in enumerate(blocks[0].instrs):
        if instruction.addr == window.callsite_addr and before_frame is None:
            before_frame = snapshots.current_sp
        if instruction.op == "CALL" and instruction.addr == window.callsite_addr:
            stack = snapshots.current_sp
            return (stack is not None and before_frame is not None
                    and (before_frame - stack) & 0xFFFF == 2
                    and frame_coordinates == [stack, (stack + 1) & 0xFFFF])
        if instruction.op == "STORE" and instruction.addr == window.callsite_addr:
            coordinate = stack_byte_store_coordinate_8616(snapshots, instruction)
            if coordinate is None or index not in window.checked_store_indices:
                return False
            frame_coordinates.append(coordinate)
        snapshots.observe_entry_instruction(instruction, index)
    return False


def _binding_failure_8616(
    coverage: IRBoundaryCoverageResult8616, window: StackWordCallWindowReceipt8616,
    target_addr: int, return_addr: int,
) -> StackWordCallBindingFailure8616 | None:
    """Revalidate every authority before publishing a callee-entry input."""
    if not coverage.complete:
        return StackWordCallBindingFailure8616.COVERAGE_UNPROVEN
    if coverage.artifact is not window.source_ir:
        return StackWordCallBindingFailure8616.SOURCE_MISMATCH
    if not window.complete:
        return StackWordCallBindingFailure8616.LIFETIME_UNPROVEN
    project = coverage.boundary.project
    bound = direct_near_call_target_is_bound_8616(
        project, window.callsite_addr, return_addr, target_addr, CallsiteMachineFrameKind8616.NEAR,
    )
    calls = tuple((block, item) for block in coverage.artifact.blocks for item in block.instrs
                  if item.op == "CALL" and item.addr == window.callsite_addr)
    if not bound or len(calls) != 1:
        return StackWordCallBindingFailure8616.TARGET_UNPROVEN
    block, instruction = calls[0]
    if not _target_matches_8616(project, block, instruction, target_addr, return_addr):
        return StackWordCallBindingFailure8616.TARGET_UNPROVEN
    if not _near_frame_matches_8616(window):
        return StackWordCallBindingFailure8616.FRAME_UNPROVEN
    return None


@dataclass(frozen=True, slots=True)
class StackWordCallBinding8616:
    """Current binary-associated contextual input, not a global callee bound."""

    coverage: IRBoundaryCoverageResult8616
    window: StackWordCallWindowReceipt8616
    target_addr: int
    return_addr: int
    failure: StackWordCallBindingFailure8616 | None
    stats: LogicalConstantWordStats8616

    @property
    def complete(self) -> bool:
        """Require closed counts and replayed coverage, lifetime and CALL proof."""
        return (self.failure is None and self.stats.complete
                and _binding_failure_8616(self.coverage, self.window, self.target_addr, self.return_addr) is None)

    @property
    def constant(self) -> int | None:
        """Expose the contextual input only with current independent authority."""
        return self.window.constant if self.complete else None

    @property
    def callee_entry_offsets(self) -> tuple[int, int] | None:
        """Expose the byte offsets only after the actual near frame is bound."""
        return self.window.call_boundary_offsets if self.complete else None


def bind_stack_word_call_window_8616(
    coverage: IRBoundaryCoverageResult8616, window: StackWordCallWindowReceipt8616,
    target_addr: int, return_addr: int,
) -> StackWordCallBinding8616:
    """Bind one local theorem or retain a typed contextual refusal."""
    failure = _binding_failure_8616(coverage, window, target_addr, return_addr)
    accepted = int(failure is None)
    return StackWordCallBinding8616(
        coverage, window, target_addr, return_addr, failure,
        LogicalConstantWordStats8616(1, int(coverage.complete), accepted, accepted, 1 - accepted),
    )
