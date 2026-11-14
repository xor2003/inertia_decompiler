# cython: language_level=3, infer_types=True
"""Collect instruction reachability from loaded x86-16 bytes.

Layer: Frontend.
Responsibility: decode bounded basic-block successors and publish a closed
binary reachability census without assigning higher-level semantics.
"""

from __future__ import annotations
import typing
import cython

from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Protocol, cast

from angr.errors import AngrError, SimEngineError
from pyvex.errors import PyVEXError

from .frontend_block_inventory import (
    DecodedBlockRequest8616,
    DecodedBlockStatus8616,
    collect_decoded_block_evidence_8616,
    decoded_block_instructions_8616,
)
from .frontend_block_partition import (
    FrontendBlockPartitionArtifact8616,
    partition_decoded_blocks_8616,
)
from .frontend_capstone_decode import DirectCapstoneBlock8616
from .frontend_instruction_kinds import is_x86_16_call_mnemonic_8616
import dataclasses
import operator
import builtins

__all__ = [
    "DecodedBlockRequest8616",
    "DecodedBlockStatus8616",
    "InstructionReachabilityEvidence8616",
    "collect_decoded_block_evidence_8616",
    "collect_instruction_reachability_8616",
    "decoded_block_instructions_8616",
    "x86_16_block_successors_from_capstone_8616",
]


class _OperandBoundary8616(Protocol):
    """Capstone operand fields consumed at the third-party decode boundary."""

    type: cython.longlong
    imm: object


class _DecodedInstructionBoundary8616(Protocol):
    """Capstone instruction fields consumed by bounded CFG traversal."""

    address: cython.longlong
    mnemonic: object
    operands: Sequence[_OperandBoundary8616]


class _InstructionBoundary8616(Protocol):
    """angr wrapper fields for one decoded Capstone instruction."""

    address: cython.longlong
    mnemonic: object
    insn: _DecodedInstructionBoundary8616


class _CapstoneBoundary8616(Protocol):
    """Decoded instruction sequence exposed by an angr block."""

    insns: Sequence[_InstructionBoundary8616]


class _BlockBoundary8616(Protocol):
    """angr block fields consumed by the frontend traversal."""

    addr: cython.longlong
    size: cython.longlong
    capstone: _CapstoneBoundary8616


class _ProjectBoundary8616(Protocol):
    """Dynamic angr project boundary used by frontend traversal."""

    _inertia_instruction_reachability_cache_8616: object


@dataclasses.dataclass(frozen=True, )
class ConditionalIndirectEdge8616:
    """Inventory assumption only; IR must independently prove its destination."""

    block_addr: cython.longlong
    instruction_addr: cython.longlong
    target_addr: cython.longlong


@dataclasses.dataclass(frozen=True, )
class InstructionReachabilityEvidence8616:
    """Closed census of bounded binary basic-block reachability."""

    reachable_block_addrs: object
    reachable_instruction_addrs: object
    unresolved_block_addrs: object
    successor_edges: object
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    blocks: object = dataclass_field(default=(), compare=False, repr=False)
    block_partition: FrontendBlockPartitionArtifact8616 | None = dataclass_field(
        default=None, compare=False, repr=False,
    )
    conditional_edges: tuple[ConditionalIndirectEdge8616, ...] = ()

    @property
    def complete(self) -> cython.bint:
        """Require a closed census without unproved indirect-edge assumptions."""
        return not self.conditional_edges and self.inventory_complete

    @property
    def inventory_complete(self) -> cython.bint:
        """Close decoding only; conditional edges still need semantic proof."""
        return (
            self.raw_fact_count > 0
            and operator.eq(self.raw_fact_count, self.normalized_fact_count)
            and operator.eq(self.normalized_fact_count, self.classified_fact_count)
            and operator.eq(self.classified_fact_count, self.materialized_count + self.failure_count)
            and self.failure_count == 0
            and not self.unresolved_block_addrs
        )


@cython.ccall
def _reachability_cache_8616(
    project: object,
) -> object:
    """Return immutable byte-reachability evidence cached on one project."""
    boundary = cast(_ProjectBoundary8616, project)
    try:
        cache = boundary._inertia_instruction_reachability_cache_8616
    except AttributeError:
        cache = {}
        boundary._inertia_instruction_reachability_cache_8616 = cache
    if not isinstance(cache, dict):
        raise TypeError("instruction reachability cache must be a dict")
    return cache


@cython.ccall
def _direct_target_8616(instruction: object) -> int | None:
    """Return one direct Capstone branch target, if present."""
    operand: object
    boundary = cast(_InstructionBoundary8616, instruction)
    try:
        inner = boundary.insn
    except AttributeError:
        inner = cast(_DecodedInstructionBoundary8616, instruction)
    try:
        operands = tuple(inner.operands)
    except (AttributeError, TypeError):
        return None
    for operand in operands:
        if operand.type != 2:
            continue
        target = operand.imm
        if isinstance(target, int):
            return target
    return None


@cython.ccall
def x86_16_block_successors_from_capstone_8616(
    block: object,
    region_start: cython.longlong,
    region_end: cython.longlong,
    *,
    proven_return_block_addrs: object = frozenset(),
    conditional_edges: object = (),
) -> object:
    """Return bounded successors, refusing unknown or out-of-region edges.

    Excluding an edge from this inventory does not prove a function return.
    Consumers must retain conservative liveness for every omitted edge.
    ``proven_return_block_addrs`` carries the independently proven
    near-return continuation block set from
    ``prove_near_return_continuations_8616``: an indirect ``jmp`` terminal
    in that set is a closed return edge, exactly like a decoded ``ret`` —
    never an inferred edge and never a blanket indirect-jump exemption.
    """
    boundary = cast(_BlockBoundary8616, block)
    if isinstance(block, DirectCapstoneBlock8616):
        instructions = block.instructions
    else:
        try:
            instructions = tuple(boundary.capstone.insns)
        except (AttributeError, TypeError):
            return set(), True
    if not instructions:
        return set(), True

    last = cast(_InstructionBoundary8616, instructions[-1])
    return _terminal_successors_8616(
        boundary,
        last.mnemonic.lower(),
        last,
        boundary.addr + boundary.size,
        region_start,
        region_end,
        proven_return_block_addrs,
        conditional_edges,
    )


def _terminal_successors_8616(
    boundary: _BlockBoundary8616,
    mnemonic: object,
    last: object,
    block_end: cython.longlong,
    region_start: cython.longlong,
    region_end: cython.longlong,
    proven_return_block_addrs: object,
    conditional_edges: object = (),
) -> tuple[set[cython.longlong], cython.bint]:
    """Classify the decoded terminal into bounded edges or refusals."""
    target: object
    successors: set[cython.longlong] = set()
    unresolved = False

    def add_target(target: object) -> None:
        """Record a bounded edge or preserve its missing-evidence status."""
        nonlocal unresolved
        if isinstance(target, int) and region_start <= target < region_end:
            successors.add(target)
        elif target is None and boundary.addr in proven_return_block_addrs:
            # A proven near-return continuation contributes no in-region
            # edge, exactly like a decoded ``ret``; the proven set only
            # ever names indirect ``jmp`` terminals, so conditional and
            # call fallthroughs can never borrow this discharge.
            return
        else:
            unresolved = True

    if mnemonic in {"ret", "retf", "iret", "retw", "iretq"}:
        return successors, False
    if is_x86_16_call_mnemonic_8616(mnemonic):
        add_target(block_end)
        return successors, unresolved
    if mnemonic in {"jmp", "ljmp"}:
        target = _direct_target_8616(last)
        if target is None and mnemonic == "jmp":
            terminal = cast(_InstructionBoundary8616, last)
            matches = tuple(edge for edge in iter(conditional_edges)
                            if operator.eq(edge.block_addr, boundary.addr)
                            and operator.eq(edge.instruction_addr, terminal.address))
            if len(matches) == 1:
                target = matches[0].target_addr
        add_target(target)
        return successors, unresolved
    if mnemonic.startswith("j") or mnemonic in {"loop", "loope", "loopne", "loopnz", "loopz"}:
        target = _direct_target_8616(last)
        add_target(target)
        add_target(block_end)
        return successors, unresolved
    add_target(block_end)
    return successors, unresolved


def _visit_reachable_block_8616(
    project: object,
    block_addr: cython.longlong,
    region_start: cython.longlong,
    region_end: cython.longlong,
    reachable_instructions: object,
    reachable_blocks: object,
    unresolved: object,
    successor_edges: object,
    proven_return_block_addrs: object = frozenset(),
    conditional_edges: object = (),
) -> tuple[cython.longlong, ...]:
    """Decode one block and fold its proven successors into the traversal."""
    block: object
    try:
        decoded = collect_decoded_block_evidence_8616(
            project,
            block_addr,
            opt_level=0,
        )
    except (AngrError, SimEngineError, PyVEXError, RuntimeError, ValueError, KeyError):
        # Engine decode failures are SimError, not AngrError. Preserve the
        # missing-byte obligation in the census, including cached failures.
        unresolved.add(block_addr)
        return ()
    block = decoded.block
    instructions = decoded.instructions
    if block is None or not instructions:
        unresolved.add(block_addr)
        return ()
    block_boundary = cast(_BlockBoundary8616, block)
    if block_boundary.size <= 0:
        unresolved.add(block_addr)
        return ()
    reachable_blocks[block_addr] = block
    reachable_instructions.update(
        instruction.address
        for instruction in iter(instructions)
        if region_start <= instruction.address < region_end
    )
    successors, successor_unresolved = x86_16_block_successors_from_capstone_8616(
        block_boundary,
        region_start,
        region_end,
        proven_return_block_addrs=proven_return_block_addrs,
        conditional_edges=conditional_edges,
    )
    if successor_unresolved:
        unresolved.add(block_addr)
    successor_edges.update((block_addr, successor) for successor in iter(successors))
    return tuple(sorted(successors))


def collect_instruction_reachability_8616(
    project: object,
    *,
    entry: cython.longlong,
    region_start: cython.longlong,
    region_end: cython.longlong,
    proven_return_block_addrs: object = frozenset(),
    conditional_edges: object = (),
) -> InstructionReachabilityEvidence8616:
    """Traverse binary-proven successors inside one bounded loaded image.

    ``proven_return_block_addrs`` is part of the cache identity: a
    premise-derived closed census is never served to a request that did
    not supply the same independently proven set.
    Conditional edges also belong to the cache identity; they can complete
    the decoding inventory but never make ``complete`` true.
    """
    cached: object
    successor: object
    if not (region_start <= entry < region_end):
        return InstructionReachabilityEvidence8616((), (), (), (), 0, 0, 0, 0, 0)

    cache = _reachability_cache_8616(project)
    cache_key = (entry, region_start, region_end, proven_return_block_addrs, conditional_edges)
    cached = cache.get(cache_key)
    if cached is not None:
        return cached
    queue: deque[cython.longlong] = deque((entry,))
    visited: set[cython.longlong] = set()
    reachable_instructions: set[cython.longlong] = set()
    reachable_blocks: dict[cython.longlong, object] = {}
    unresolved: set[cython.longlong] = set()
    successor_edges: set[tuple[cython.longlong, cython.longlong]] = set()
    while queue:
        block_addr = queue.popleft()
        if block_addr in visited or not (region_start <= block_addr < region_end):
            continue
        visited.add(block_addr)
        successors = _visit_reachable_block_8616(
            project,
            block_addr,
            region_start,
            region_end,
            reachable_instructions,
            reachable_blocks,
            unresolved,
            successor_edges,
            proven_return_block_addrs,
            conditional_edges,
        )
        for successor in sorted(successors):
            if successor not in visited:
                queue.append(successor)

    partition = partition_decoded_blocks_8616(
        tuple(reachable_blocks[address] for address in builtins.iter(sorted(reachable_blocks))),
        tuple(sorted(successor_edges)),
        region_start=region_start,
        region_end=region_end,
    )
    unresolved.update(fact.block_addr for fact in iter(partition.facts) if fact.failure is not None)
    if any((edge.block_addr, edge.target_addr) not in successor_edges for edge in iter(conditional_edges)):
        # An unused assumption cannot silently disappear from its inventory.
        unresolved.add(entry)
    failure_count = len(unresolved)
    classified_count = len(visited)
    evidence = InstructionReachabilityEvidence8616(
        reachable_block_addrs=tuple(sorted(visited)),
        reachable_instruction_addrs=tuple(sorted(reachable_instructions)),
        unresolved_block_addrs=tuple(sorted(unresolved)),
        successor_edges=partition.successor_edges,
        raw_fact_count=classified_count,
        normalized_fact_count=classified_count,
        classified_fact_count=classified_count,
        materialized_count=classified_count - failure_count,
        failure_count=failure_count,
        blocks=partition.blocks,
        block_partition=partition,
        conditional_edges=conditional_edges,
    )
    cache[cache_key] = evidence
    return evidence
