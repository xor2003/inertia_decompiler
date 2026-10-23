"""Layer: IR.
Responsibility: bind and transfer pure source-backed leaf rows in one walk.

Semantic operations and exact provenance comparison remain owned by the invocation
census. This synchronous transaction publishes no path state before full binding.
"""
from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from .core import IRBlock, IRFunctionArtifact, IRInstr
from .real16_edge_feasibility8616 import DirectionTracker8616
from .real16_initial_memory8616 import InvocationInitialMemory8616
from .real16_path_memory8616 import PathMemory8616
from .real16_persistent_bytes8616 import canonical_known_root_8616

if TYPE_CHECKING:
    from .real16_invocation_domain import (
        Real16InvocationFailure8616,
        Real16InvocationRefusalSite8616,
        _NativeTermMemo8616,
        _PathCensusContext8616,
        _PathState8616,
    )


@dataclass(frozen=True, slots=True)
class FusedCalleeOperations8616:
    """Exact canonical census operations, never arbitrary callback authority."""

    producers: tuple[object, ...]
    context_type: type[_PathCensusContext8616]
    make_memo: Callable[[], _NativeTermMemo8616]
    header_equal: Callable[[IRBlock, IRBlock, _NativeTermMemo8616], bool]
    row_equal: Callable[[IRInstr, IRInstr, int, _NativeTermMemo8616], bool]
    transfer: Callable[[_PathCensusContext8616, IRFunctionArtifact, IRBlock, IRInstr,
                       dict[str, int], dict[int, int], dict[str, int], set[str],
                       PathMemory8616, tuple[int, int]], Real16InvocationFailure8616 | None]
    charge: Callable[[_PathCensusContext8616], bool]
    refuse_block: Callable[[_PathCensusContext8616, IRFunctionArtifact, IRBlock, int | None], None]
    make_state: Callable[[dict[str, int], PathMemory8616, bool | None], _PathState8616]
    native_failure: Real16InvocationFailure8616
    effect_failure: Real16InvocationFailure8616
    work_failure: Real16InvocationFailure8616
    deadline_failure: Real16InvocationFailure8616
    decode_failure: Real16InvocationFailure8616
    record_site: Callable[[_PathCensusContext8616, IRFunctionArtifact, IRBlock, IRInstr], None]


@dataclass(frozen=True, slots=True)
class _FusedCalleeScope8616:
    """One authenticated callee's synchronous transaction and exact producers."""

    context: _PathCensusContext8616
    artifact: IRFunctionArtifact
    operations: FusedCalleeOperations8616


_SCOPE: ContextVar[_FusedCalleeScope8616 | None] = ContextVar("fused_callee_transfer", default=None)


@contextmanager
def source_bound_callee_transfer_8616(
    context: _PathCensusContext8616, artifact: IRFunctionArtifact,
    operations: FusedCalleeOperations8616 | None,
) -> Iterator[None]:
    """Arm only after the owner consumes fresh leaf/native closure evidence."""
    if operations is None:
        yield
        return
    token = _SCOPE.set(_FusedCalleeScope8616(context, artifact, operations))
    try:
        yield
    finally:
        _SCOPE.reset(token)


def canonical_fused_operations_match_8616(
    actual: FusedCalleeOperations8616, expected: FusedCalleeOperations8616,
) -> bool:
    """Reject mutated contracts and deceptive callable equality by identity."""
    if (type(actual) is not FusedCalleeOperations8616
            or type(expected) is not FusedCalleeOperations8616
            or type(actual.producers) is not tuple or type(expected.producers) is not tuple):
        return False
    left = (actual.context_type, actual.make_memo, actual.header_equal, actual.row_equal,
            actual.transfer, actual.charge, actual.refuse_block, actual.make_state,
            actual.native_failure, actual.effect_failure, actual.work_failure,
            actual.deadline_failure, actual.decode_failure, actual.record_site,
            *actual.producers)
    right = (expected.context_type, expected.make_memo, expected.header_equal, expected.row_equal,
             expected.transfer, expected.charge, expected.refuse_block, expected.make_state,
             expected.native_failure, expected.effect_failure, expected.work_failure,
             expected.deadline_failure, expected.decode_failure, expected.record_site,
             *expected.producers)
    return len(left) == len(right) and all(a is b for a, b in zip(left, right, strict=True))


def active_fused_callee_transfer_8616(
    context: _PathCensusContext8616, artifact: IRFunctionArtifact,
) -> bool:
    """Select only the exact callee currently authenticated by its owner."""
    scope = _SCOPE.get()
    return scope is not None and scope.context is context and scope.artifact is artifact


def _eligible_transfer_8616(
    scope: _FusedCalleeScope8616, ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact, block: IRBlock, entry: _PathState8616,
    stop_after: int | None, operations: FusedCalleeOperations8616,
) -> bool:
    """Check exact owner contracts before invoking any live operation callback."""
    if (type(operations) is not FusedCalleeOperations8616
            or type(scope.operations) is not FusedCalleeOperations8616
            or scope.context is not ctx or scope.artifact is not artifact
            or stop_after is not None):
        return False
    if not canonical_fused_operations_match_8616(scope.operations, operations):
        return False
    if type(ctx) is not operations.context_type or type(entry) is not operations.make_state:
        return False
    if type(entry.memory) is not PathMemory8616:
        return False
    if ((type(entry.memory.known) is not dict
         and not canonical_known_root_8616(entry.memory.known))
            or type(entry.memory.unknown) is not set):
        return False
    return (type(entry.registers) is dict
            and type(block) is IRBlock and type(entry.memory) is PathMemory8616
            and (ctx.initial_memory is None or type(ctx.initial_memory) is InvocationInitialMemory8616)
            and type(block.instrs) is tuple and bool(block.instrs))


def try_fused_callee_transfer_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact,
    block: IRBlock, entry: _PathState8616, *, stop_after: int | None,
    operations: FusedCalleeOperations8616,
) -> _PathState8616 | Real16InvocationFailure8616 | None:
    """Return a bound result or None to retain the ordinary callback route.

    Ledger additions are private synchronous provisional evidence: no external
    callback may observe them. A late mismatch restores scalar counters and
    invokes the original all-row refusal, revoking prior block materializations.
    Work is never rolled back. Semantic failure still binds the remaining suffix.
    """
    scope = _SCOPE.get()
    if scope is None:
        return None
    if not _eligible_transfer_8616(scope, ctx, artifact, block, entry, stop_after, operations):
        return None
    ops = scope.operations
    # Only the verified canonical callback can observe the identity-walk charge.
    ctx.work_units += len(operations.producers) + 14
    if ops.charge(ctx):
        return ops.work_failure
    native = ctx.native_blocks.get(artifact.function_addr, {}).get(block.addr)
    if type(native) is not IRBlock:
        return None
    native = native
    if type(native.instrs) is not tuple:
        return None
    memo = ops.make_memo()
    witness = _nonrepeat_witness_8616(ctx, block, native, ops, memo)
    if witness is not True:
        return None if witness is False else witness
    ctx.work_units += 1
    if ops.charge(ctx):
        return ops.work_failure
    if not ops.header_equal(native, block, memo):
        ops.refuse_block(ctx, artifact, block, None)
        return ops.native_failure
    return _transfer_bound_rows_8616(ctx, artifact, block, native, entry, ops, memo)


def _transfer_bound_rows_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact,
    block: IRBlock, native: IRBlock, entry: _PathState8616,
    ops: FusedCalleeOperations8616, memo: _NativeTermMemo8616,
) -> _PathState8616 | Real16InvocationFailure8616:
    """Transfer a private state while preserving whole-block binding priority."""
    registers = dict(entry.registers)
    memory = entry.memory.copy()
    direction = DirectionTracker8616(registers, entry.direction)
    tmps: dict[int, int] = {}
    dirty: set[str] = set()
    instruction_entry = dict(registers)
    current_addr: int | None = None
    counters = ctx.checked_stores, ctx.failures, ctx.first_failure_site
    effect_failure: Real16InvocationFailure8616 | None = None
    for index, (row, native_row) in enumerate(zip(block.instrs, native.instrs, strict=True)):
        if time.monotonic() > ctx.deadline:
            return ops.deadline_failure
        if not _row_bound_8616(row, native_row, ops, memo):
            return _native_row_failure_8616(ctx, artifact, block, counters, ops)
        if _skip_effect_8616(row, effect_failure):
            effect_failure = _bind_without_effect_8616(ctx, artifact, block, row, index, effect_failure, ops)
            if effect_failure is ops.work_failure:
                return effect_failure
            continue
        if row.addr != current_addr:
            current_addr = row.addr
            instruction_entry = dict(registers)
            dirty = set()
        effect_failure = ops.transfer(ctx, artifact, block, row, registers, tmps,
                                      instruction_entry, dirty, memory, (block.addr, index))
        if _census_level_failure_8616(effect_failure, ops):
            assert effect_failure is not None
            return effect_failure
        if effect_failure is None:
            direction.step(row, registers, tmps)
    if effect_failure is not None:
        return effect_failure
    return ops.make_state(registers, memory, direction.direction())


def _refuse_unexpected_row_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact, block: IRBlock,
    row: IRInstr, index: int, ops: FusedCalleeOperations8616,
) -> Real16InvocationFailure8616:
    """Keep malformed rows and impossible leaf calls honest without callbacks."""
    if type(row.addr) is not int:
        return ops.decode_failure
    fact = (block.addr, index)
    ctx.raw_facts.add(fact)
    ctx.normalized_facts.add(fact)
    ctx.classified_facts.add(fact)
    ctx.materialized_facts.discard(fact)
    ctx.failures += 1
    ops.record_site(ctx, artifact, block, row)
    return ops.effect_failure


def _nonrepeat_witness_8616(
    ctx: _PathCensusContext8616, block: IRBlock, native: IRBlock,
    ops: FusedCalleeOperations8616, memo: _NativeTermMemo8616,
) -> bool | Real16InvocationFailure8616:
    """Authenticate the sufficient last-row witness without invoking a decoder."""
    ctx.work_units += 1
    if ops.charge(ctx):
        return ops.work_failure
    if time.monotonic() > ctx.deadline:
        return ops.deadline_failure
    last = block.instrs[-1]
    if type(last) is not IRInstr or not native.instrs or type(native.instrs[-1]) is not IRInstr:
        return False
    return (ops.row_equal(native.instrs[-1], last, 3, memo)
            and type(last.addr) is int and last.addr != block.addr)


def _row_bound_8616(
    row: IRInstr, native_row: IRInstr, ops: FusedCalleeOperations8616,
    memo: _NativeTermMemo8616,
) -> bool:
    """Preserve exact row schema and original depth-three native comparison."""
    return (type(row) is IRInstr and type(native_row) is IRInstr
            and ops.row_equal(native_row, row, 3, memo))


def _skip_effect_8616(row: IRInstr, failure: Real16InvocationFailure8616 | None) -> bool:
    """Never invoke an unexpected call or replay effects after a first failure."""
    return failure is not None or row.op == "CALL" or type(row.addr) is not int


def _native_row_failure_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact, block: IRBlock,
    counters: tuple[int, int, Real16InvocationRefusalSite8616 | None], ops: FusedCalleeOperations8616,
) -> Real16InvocationFailure8616:
    """Rollback provisional scalar evidence before the original whole-row refusal."""
    ctx.work_units += 1
    if ops.charge(ctx):
        return ops.work_failure
    ctx.checked_stores, ctx.failures, ctx.first_failure_site = counters
    ops.refuse_block(ctx, artifact, block, None)
    return ops.native_failure


def _bind_without_effect_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact, block: IRBlock,
    row: IRInstr, index: int, failure: Real16InvocationFailure8616 | None,
    ops: FusedCalleeOperations8616,
) -> Real16InvocationFailure8616:
    """Charge suffix binding and retain the earliest scalar/decode refusal."""
    ctx.work_units += 1
    if ops.charge(ctx):
        return ops.work_failure
    if failure is not None:
        return failure
    return _refuse_unexpected_row_8616(ctx, artifact, block, row, index, ops)


def _census_level_failure_8616(
    failure: Real16InvocationFailure8616 | None, ops: FusedCalleeOperations8616,
) -> bool:
    """Distinguish budget/deadline refusal from a scalar effect to bind suffix."""
    return failure is ops.work_failure or failure is ops.deadline_failure


class FusedCalleeProducerBindings8616(Protocol):
    """Typed namespace of helper identities actually retained by this consumer.

    This metadata view grants no call authority and invokes no accessor.
    Consumers read the existing module bindings directly for cache keys.
    """

    canonical_known_root_8616: object
