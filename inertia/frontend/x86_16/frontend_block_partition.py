"""Normalize shared decoded suffixes without erasing uncertain evidence.

Layer: Frontend.
Responsibility: assign contiguous instruction-boundary suffixes to their exact
decoded owner and retarget proven prefixes before publishing a bounded CFG.
Conflicting bytes, decode boundaries, edges or extents remain typed refusals;
their original blocks and edges are preserved for diagnostics.
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from .frontend_capstone_block import DirectCapstoneBlock8616


class _InstructionBoundary8616(Protocol):
    """Address and extent supplied by the third-party decoder."""

    address: int
    size: int


class _CapstoneBoundary8616(Protocol):
    """Instruction inventory supplied by a decoded block."""

    insns: Sequence[object]


class _BlockBoundary8616(Protocol):
    """Read-only decoded block surface used at the backend boundary."""

    addr: int
    size: int
    bytes: bytes
    capstone: _CapstoneBoundary8616


class FrontendBlockPartitionFailure8616(StrEnum):
    """Reason an exact instruction partition could not be proven."""

    BLOCK_OUTSIDE_REGION = "block_outside_region"
    DECODE_NOT_CONTIGUOUS = "decode_not_contiguous"
    MID_INSTRUCTION_ENTRY = "mid_instruction_entry"
    SUFFIX_EXTENT_CONFLICT = "suffix_extent_conflict"
    SUFFIX_DECODE_CONFLICT = "suffix_decode_conflict"
    BYTE_EVIDENCE_MISSING = "byte_evidence_missing"
    SUFFIX_BYTES_CONFLICT = "suffix_bytes_conflict"
    SUCCESSOR_CONFLICT = "successor_conflict"


@dataclass(frozen=True, slots=True)
class FrontendBlockPartitionFact8616:
    """One retained, partitioned or refused decoded block identity."""

    block_addr: int
    suffix_addr: int | None = None
    failure: FrontendBlockPartitionFailure8616 | None = None


@dataclass(frozen=True, slots=True)
class FrontendBlockPartitionArtifact8616:
    """Immutable partition result with closed per-block evidence accounting."""

    blocks: tuple[object, ...]
    successor_edges: tuple[tuple[int, int], ...]
    facts: tuple[FrontendBlockPartitionFact8616, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Return whether every collected decoded block has a proven owner."""
        return (
            self.raw_fact_count > 0
            and self.raw_fact_count == self.normalized_fact_count == self.classified_fact_count
            and self.classified_fact_count == self.materialized_count + self.failure_count
            and self.failure_count == 0
        )


@dataclass(frozen=True, slots=True)
class _DecodedBlockView8616:
    """Request-local view over immutable decoder evidence."""

    block: object
    addr: int
    end: int
    instructions: tuple[object, ...]
    instruction_extents: tuple[tuple[int, int], ...]


def _decoded_view_8616(block: object) -> _DecodedBlockView8616:
    """Read the narrow third-party block surface once per partition pass."""
    boundary = cast(_BlockBoundary8616, block)
    instructions = tuple(boundary.capstone.insns)
    return _DecodedBlockView8616(
        block, boundary.addr, boundary.addr + boundary.size, instructions,
        tuple((cast(_InstructionBoundary8616, item).address,
               cast(_InstructionBoundary8616, item).size) for item in instructions),
    )


def _extent_failure_8616(
    view: _DecodedBlockView8616, region_start: int, region_end: int,
) -> FrontendBlockPartitionFailure8616 | None:
    """Refuse region spill and missing or noncontiguous instruction extents."""
    if not region_start <= view.addr < view.end <= region_end:
        return FrontendBlockPartitionFailure8616.BLOCK_OUTSIDE_REGION
    position = view.addr
    for address, size in view.instruction_extents:
        if address != position or size <= 0:
            return FrontendBlockPartitionFailure8616.DECODE_NOT_CONTIGUOUS
        position += size
    if position != view.end:
        return FrontendBlockPartitionFailure8616.DECODE_NOT_CONTIGUOUS
    return None


def _block_bytes_8616(view: _DecodedBlockView8616) -> bytes | None:
    """Read exact bytes only when a partition actually requires byte proof."""
    try:
        code = cast(_BlockBoundary8616, view.block).bytes
    except AttributeError:
        return None
    return code if isinstance(code, bytes) and len(code) == view.end - view.addr else None


def _suffix_failure_8616(
    source: _DecodedBlockView8616,
    suffix: _DecodedBlockView8616,
    split_index: int,
    outgoing: dict[int, tuple[int, ...]],
) -> FrontendBlockPartitionFailure8616 | None:
    """Require the same decoded tail, bytes and terminal edge census."""
    if source.end != suffix.end:
        return FrontendBlockPartitionFailure8616.SUFFIX_EXTENT_CONFLICT
    if source.instruction_extents[split_index:] != suffix.instruction_extents:
        return FrontendBlockPartitionFailure8616.SUFFIX_DECODE_CONFLICT
    source_code = _block_bytes_8616(source)
    suffix_code = _block_bytes_8616(suffix)
    if source_code is None or suffix_code is None:
        return FrontendBlockPartitionFailure8616.BYTE_EVIDENCE_MISSING
    if source_code[suffix.addr - source.addr:] != suffix_code:
        return FrontendBlockPartitionFailure8616.SUFFIX_BYTES_CONFLICT
    if outgoing[source.addr] != outgoing[suffix.addr]:
        return FrontendBlockPartitionFailure8616.SUCCESSOR_CONFLICT
    return None


def _partition_one_8616(
    source: _DecodedBlockView8616,
    suffix: _DecodedBlockView8616 | None,
    outgoing: dict[int, tuple[int, ...]],
    region_start: int,
    region_end: int,
) -> tuple[object, tuple[int, ...], FrontendBlockPartitionFact8616]:
    """Retain one block or partition its prefix using a byte-proven suffix."""
    failure = _extent_failure_8616(source, region_start, region_end)
    if failure is not None:
        return source.block, outgoing[source.addr], FrontendBlockPartitionFact8616(source.addr, failure=failure)
    if suffix is None or suffix.addr >= source.end:
        return source.block, outgoing[source.addr], FrontendBlockPartitionFact8616(source.addr)
    instruction_addrs = tuple(address for address, _size in source.instruction_extents)
    if suffix.addr not in instruction_addrs:
        failure = FrontendBlockPartitionFailure8616.MID_INSTRUCTION_ENTRY
    else:
        split_index = instruction_addrs.index(suffix.addr)
        failure = _suffix_failure_8616(source, suffix, split_index, outgoing)
    if failure is not None:
        return source.block, outgoing[source.addr], FrontendBlockPartitionFact8616(source.addr, suffix.addr, failure)
    code = _block_bytes_8616(source)
    assert code is not None, "proven suffix lost exact source bytes"
    prefix_size = suffix.addr - source.addr
    prefix = DirectCapstoneBlock8616(
        source.addr, prefix_size, code[:prefix_size], source.instructions[:split_index],
    )
    return prefix, (suffix.addr,), FrontendBlockPartitionFact8616(source.addr, suffix.addr)


def partition_decoded_blocks_8616(
    blocks: tuple[object, ...],
    successor_edges: tuple[tuple[int, int], ...],
    *,
    region_start: int,
    region_end: int,
) -> FrontendBlockPartitionArtifact8616:
    """Normalize aligned shared tails, retaining every unproven block and edge.

    Discovery may visit a prefix before discovering an entry into its tail.
    This publication pass uses the final entry census, not traversal order.
    It does not re-decode blocks or alter the request-local decode cache.
    """
    views = tuple(sorted((_decoded_view_8616(block) for block in blocks), key=lambda view: view.addr))
    addresses = tuple(view.addr for view in views)
    views_by_addr = {view.addr: view for view in views}
    if len(views_by_addr) != len(views):
        raise ValueError("decoded block partition requires unique block entries")
    outgoing = {
        address: tuple(sorted(target for source, target in successor_edges if source == address))
        for address in addresses
    }
    normalized_blocks: list[object] = []
    normalized_edges: set[tuple[int, int]] = set(successor_edges)
    facts: list[FrontendBlockPartitionFact8616] = []
    for view in views:
        next_index = bisect_right(addresses, view.addr)
        suffix = views[next_index] if next_index < len(views) else None
        block, targets, fact = _partition_one_8616(view, suffix, outgoing, region_start, region_end)
        normalized_blocks.append(block)
        facts.append(fact)
        if fact.suffix_addr is not None and fact.failure is None:
            normalized_edges.difference_update((view.addr, target) for target in outgoing[view.addr])
            normalized_edges.update((view.addr, target) for target in targets)
    count = len(views)
    failures = sum(fact.failure is not None for fact in facts)
    return FrontendBlockPartitionArtifact8616(
        tuple(normalized_blocks), tuple(sorted(normalized_edges)), tuple(facts),
        count, count, count, count - failures, failures,
    )
