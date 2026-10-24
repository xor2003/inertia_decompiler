"""Layer: IR.
Responsibility: bind native caller rows while privately transferring scalar prefixes.

CALL effects remain in the ordinary census walker, after complete native binding.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .core import IRBlock, IRFunctionArtifact, IRInstr
from .real16_edge_feasibility8616 import DirectionTracker8616
from .real16_fused_callee_transfer import (
    FusedCalleeOperations8616,
    _census_level_failure_8616,
    _native_row_failure_8616,
    _nonrepeat_witness_8616,
    _row_bound_8616,
    canonical_fused_operations_match_8616,
)
from .real16_initial_memory8616 import InvocationInitialMemory8616
from .real16_path_memory8616 import PathMemory8616
from .real16_persistent_bytes8616 import canonical_known_root_8616

if TYPE_CHECKING:
    from .real16_invocation_domain import (
        Real16InvocationFailure8616,
        _NativeTermMemo8616,
        _PathCensusContext8616,
        _PathState8616,
    )


@dataclass(slots=True)
class FusedCallerPrefix8616:
    """Private scalar state resumable only after every consumed row is bound."""

    next_index: int
    registers: dict[str, int]
    memory: PathMemory8616
    direction: DirectionTracker8616
    tmps: dict[int, int]
    dirty: set[str]
    instruction_entry: dict[str, int]
    current_addr: int | None


def _eligible_caller_8616(
    ctx: _PathCensusContext8616, block: IRBlock, entry: _PathState8616,
    stop_after: int | None, operations: FusedCalleeOperations8616,
    expected: FusedCalleeOperations8616,
) -> bool:
    """Reject foreign authority and partial/repeat shapes before any callback."""
    if not canonical_fused_operations_match_8616(operations, expected):
        return False
    if type(ctx) is not expected.context_type or type(entry) is not expected.make_state:
        return False
    if type(block) is not IRBlock or type(block.instrs) is not tuple or not block.instrs:
        return False
    if type(entry.memory) is not PathMemory8616 or type(entry.registers) is not dict:
        return False
    if ((type(entry.memory.known) is not dict
         and not canonical_known_root_8616(entry.memory.known))
            or type(entry.memory.unknown) is not set):
        return False
    if ctx.initial_memory is not None and type(ctx.initial_memory) is not InvocationInitialMemory8616:
        return False
    last = block.instrs[-1]
    return (type(last) is IRInstr and last.op == "CALL" and type(last.addr) is int
            and type(ctx.callsite_addr) is int and (stop_after is None or stop_after == last.addr))


def try_fused_caller_prefix_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact, block: IRBlock,
    entry: _PathState8616, *, stop_after: int | None,
    operations: FusedCalleeOperations8616, canonical_operations: FusedCalleeOperations8616,
) -> FusedCallerPrefix8616 | Real16InvocationFailure8616 | None:
    """Fuse one prefix or fall back before effects; never execute a CALL here."""
    if not _eligible_caller_8616(ctx, block, entry, stop_after, operations, canonical_operations):
        return None
    if time.monotonic() > ctx.deadline:
        return operations.deadline_failure
    ctx.work_units += len(operations.producers) + 14
    if operations.charge(ctx):
        return operations.work_failure
    native = ctx.native_blocks.get(artifact.function_addr, {}).get(block.addr)
    if type(native) is not IRBlock:
        return None
    if type(native.instrs) is not tuple:
        return None
    memo = operations.make_memo()
    witness = _nonrepeat_witness_8616(ctx, block, native, operations, memo)
    if witness is not True:
        return None if witness is False else witness
    ctx.work_units += 1
    if operations.charge(ctx):
        return operations.work_failure
    if not operations.header_equal(native, block, memo):
        operations.refuse_block(ctx, artifact, block, None)
        return operations.native_failure
    return _bind_caller_rows_8616(ctx, artifact, block, native, entry, operations, memo)


def _new_prefix_8616(entry: _PathState8616) -> FusedCallerPrefix8616:
    """Copy the ordinary scalar initial state without publishing an exit."""
    registers = dict(entry.registers)
    return FusedCallerPrefix8616(
        0, registers, entry.memory.copy(), DirectionTracker8616(registers, entry.direction),
        {}, set(), dict(registers), None,
    )


def _transfer_prefix_row_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact, block: IRBlock,
    row: IRInstr, index: int, state: FusedCallerPrefix8616, ops: FusedCalleeOperations8616,
) -> Real16InvocationFailure8616 | None:
    """Transfer one canonical non-call effect with exact instruction-entry state."""
    if type(row.addr) is not int:
        return ops.decode_failure
    if row.addr != state.current_addr:
        state.current_addr = row.addr
        state.instruction_entry = dict(state.registers)
        state.dirty = set()
    failure = ops.transfer(ctx, artifact, block, row, state.registers, state.tmps,
                           state.instruction_entry, state.dirty, state.memory, (block.addr, index))
    if failure is None:
        state.direction.step(row, state.registers, state.tmps)
    return failure


def _bind_caller_rows_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact, block: IRBlock,
    native: IRBlock, entry: _PathState8616, ops: FusedCalleeOperations8616, memo: _NativeTermMemo8616,
) -> FusedCallerPrefix8616 | Real16InvocationFailure8616:
    """Bind the suffix before callbacks; preserve native mismatch priority."""
    state = _new_prefix_8616(entry)
    state.next_index = len(block.instrs)
    counters = ctx.checked_stores, ctx.failures, ctx.first_failure_site
    failure: Real16InvocationFailure8616 | None = None
    binding_only = False
    for index, (row, native_row) in enumerate(zip(block.instrs, native.instrs, strict=True)):
        if time.monotonic() > ctx.deadline:
            return ops.deadline_failure
        if not _row_bound_8616(row, native_row, ops, memo):
            return _native_row_failure_8616(ctx, artifact, block, counters, ops)
        if row.op == "CALL" and not binding_only:
            state.next_index = index
            binding_only = True
        if binding_only or failure is not None:
            ctx.work_units += 1
            if ops.charge(ctx):
                return ops.work_failure
            continue
        failure = _transfer_prefix_row_8616(ctx, artifact, block, row, index, state, ops)
        if _census_level_failure_8616(failure, ops):
            assert failure is not None
            return failure
    return failure if failure is not None else state


def fused_caller_prefix_producers_8616() -> tuple[object, ...]:
    """Expose every owned fusion helper for the canonical identity inventory."""
    return (
        FusedCallerPrefix8616, FusedCallerPrefix8616.__init__, _eligible_caller_8616,
        try_fused_caller_prefix_8616, _new_prefix_8616, _transfer_prefix_row_8616,
        _bind_caller_rows_8616, _census_level_failure_8616, _native_row_failure_8616,
        _nonrepeat_witness_8616, _row_bound_8616, canonical_fused_operations_match_8616,
        canonical_known_root_8616,
    )
