"""Collect instruction reachability from loaded x86-16 bytes.

Layer: Frontend.
Responsibility: decode bounded basic-block successors and publish a closed
binary reachability census without assigning higher-level semantics.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Protocol, cast

from .frontend_block_inventory import (
    DecodedBlockRequest8616,
    DecodedBlockStatus8616,
    collect_decoded_block_evidence_8616,
    decoded_block_instructions_8616,
)
from .frontend_capstone_decode import DirectCapstoneBlock8616
from .frontend_instruction_kinds import is_x86_16_call_mnemonic_8616

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

    type: int
    imm: object


class _DecodedInstructionBoundary8616(Protocol):
    """Capstone instruction fields consumed by bounded CFG traversal."""

    address: int
    mnemonic: str
    operands: Sequence[_OperandBoundary8616]


class _InstructionBoundary8616(Protocol):
    """angr wrapper fields for one decoded Capstone instruction."""

    address: int
    mnemonic: str
    insn: _DecodedInstructionBoundary8616


class _CapstoneBoundary8616(Protocol):
    """Decoded instruction sequence exposed by an angr block."""

    insns: Sequence[_InstructionBoundary8616]


class _BlockBoundary8616(Protocol):
    """angr block fields consumed by the frontend traversal."""

    addr: int
    size: int
    capstone: _CapstoneBoundary8616


class _ProjectBoundary8616(Protocol):
    """Dynamic angr project boundary used by frontend traversal."""

    _inertia_instruction_reachability_cache_8616: dict[
        tuple[int, int, int],
        InstructionReachabilityEvidence8616,
    ]


@dataclass(frozen=True, slots=True)
class InstructionReachabilityEvidence8616:
    """Closed census of bounded binary basic-block reachability."""

    reachable_block_addrs: tuple[int, ...]
    reachable_instruction_addrs: tuple[int, ...]
    unresolved_block_addrs: tuple[int, ...]
    successor_edges: tuple[tuple[int, int], ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    blocks: tuple[object, ...] = dataclass_field(default=(), compare=False, repr=False)

    @property
    def complete(self) -> bool:
        """Return whether every visited block had a resolved successor class."""
        return (
            self.raw_fact_count > 0
            and self.raw_fact_count == self.normalized_fact_count
            and self.normalized_fact_count == self.classified_fact_count
            and self.classified_fact_count == self.materialized_count + self.failure_count
            and self.failure_count == 0
            and not self.unresolved_block_addrs
        )


def _reachability_cache_8616(
    project: object,
) -> dict[tuple[int, int, int], InstructionReachabilityEvidence8616]:
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


def _direct_target_8616(instruction: object) -> int | None:
    """Return one direct Capstone branch target, if present."""
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


def x86_16_block_successors_from_capstone_8616(
    block: object,
    region_start: int,
    region_end: int,
) -> tuple[set[int], bool]:
    """Return bounded successors, refusing unknown or out-of-region edges.

    Excluding an edge from this inventory does not prove a function return.
    Consumers must retain conservative liveness for every omitted edge.
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
    mnemonic = last.mnemonic.lower()
    block_end = boundary.addr + boundary.size
    successors: set[int] = set()
    unresolved = False

    def add_target(target: int | None) -> None:
        """Record a bounded edge or preserve its missing-evidence status."""
        nonlocal unresolved
        if isinstance(target, int) and region_start <= target < region_end:
            successors.add(target)
        else:
            unresolved = True

    if mnemonic in {"ret", "retf", "iret", "retw", "iretq"}:
        return successors, False
    if is_x86_16_call_mnemonic_8616(mnemonic):
        add_target(block_end)
        return successors, unresolved
    if mnemonic in {"jmp", "ljmp"}:
        target = _direct_target_8616(last)
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
    block_addr: int,
    region_start: int,
    region_end: int,
    reachable_instructions: set[int],
    reachable_blocks: dict[int, object],
    unresolved: set[int],
    successor_edges: set[tuple[int, int]],
) -> tuple[int, ...]:
    """Decode one block and fold its proven successors into the traversal."""
    try:
        decoded = collect_decoded_block_evidence_8616(
            project,
            block_addr,
            opt_level=0,
        )
    except Exception:  # angr exposes several backend-specific decode failures.
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
        for instruction in instructions
        if region_start <= instruction.address < region_end
    )
    successors, successor_unresolved = x86_16_block_successors_from_capstone_8616(
        block_boundary,
        region_start,
        region_end,
    )
    if successor_unresolved:
        unresolved.add(block_addr)
    successor_edges.update((block_addr, successor) for successor in successors)
    return successors


def collect_instruction_reachability_8616(
    project: object,
    *,
    entry: int,
    region_start: int,
    region_end: int,
) -> InstructionReachabilityEvidence8616:
    """Traverse binary-proven successors inside one bounded loaded image."""
    if not (region_start <= entry < region_end):
        return InstructionReachabilityEvidence8616((), (), (), (), 0, 0, 0, 0, 0)

    cache = _reachability_cache_8616(project)
    cache_key = (entry, region_start, region_end)
    cached = cache.get(cache_key)
    if cached is not None:
        return cached
    queue: deque[int] = deque((entry,))
    visited: set[int] = set()
    reachable_instructions: set[int] = set()
    reachable_blocks: dict[int, object] = {}
    unresolved: set[int] = set()
    successor_edges: set[tuple[int, int]] = set()
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
        )
        for successor in sorted(successors):
            if successor not in visited:
                queue.append(successor)

    failure_count = len(unresolved)
    classified_count = len(visited)
    evidence = InstructionReachabilityEvidence8616(
        reachable_block_addrs=tuple(sorted(visited)),
        reachable_instruction_addrs=tuple(sorted(reachable_instructions)),
        unresolved_block_addrs=tuple(sorted(unresolved)),
        successor_edges=tuple(sorted(successor_edges)),
        raw_fact_count=classified_count,
        normalized_fact_count=classified_count,
        classified_fact_count=classified_count,
        materialized_count=classified_count - failure_count,
        failure_count=failure_count,
        blocks=tuple(reachable_blocks[address] for address in sorted(reachable_blocks)),
    )
    cache[cache_key] = evidence
    return evidence
