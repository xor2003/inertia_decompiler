"""Canonicalize exact stack-memory ranges into disjoint byte cells.

Layer: IR.
Responsibility: derive deterministic byte-range partitions and overlap geometry
from proven ``SS:BP+offset`` accesses before memory SSA assigns versions.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, replace
from enum import StrEnum

from .core import AddressStatus, IRAddress, IRInstr, MemSpace
from .ssa import SSABlock
from .ssa_memory_contracts import (
    MemoryRangeKey8616,
    SSAMemoryOverlap8616,
    SSAMemoryOverlapRelation8616,
)

type StackMemoryAccessInput8616 = tuple[int, int, IRAddress]


class StackCoordinateAgreement8616(StrEnum):
    """A contradiction census, not proof of frame lifetime or cross-block equality."""

    NO_CONFLICT_OBSERVED = "no_conflict_observed"
    CONFLICT = "conflicting_stack_coordinates"


def stack_coordinate_agreement_8616(blocks: tuple[SSABlock, ...]) -> StackCoordinateAgreement8616:
    """Refuse shared BP geometry when one block observes different BP definitions.

    Scalar versions are block-local: comparing version numbers from different
    blocks would invent equality or conflict. Missing legacy provenance is not
    a contradiction proof. Separate VEX snapshots of the same BP version agree.
    Rebased coordinates require an explicit normalization proof before ranges
    can be compared; different textual offsets do not establish disjointness.
    """
    for block in blocks:
        versions: set[int] = set()
        for instruction in block.instrs:
            address = stack_memory_access_8616(instruction)
            if address is None or address.base != ("bp",):
                continue
            versions.update(
                value.version for value in address.base_values
                if value.space is MemSpace.REG and value.name == "bp" and value.version is not None
            )
        if len(versions) > 1:
            return StackCoordinateAgreement8616.CONFLICT
    return StackCoordinateAgreement8616.NO_CONFLICT_OBSERVED


@dataclass(frozen=True, slots=True)
class StackMemoryRangeCells8616:
    """One observed exact range and its canonical disjoint byte cells."""

    key: MemoryRangeKey8616
    address: IRAddress
    cells: tuple[IRAddress, ...]

    @property
    def complete(self) -> bool:
        """Return whether ordered cells cover the original range exactly once."""
        expected_offset = self.address.offset
        for cell in self.cells:
            if (
                cell.space is not self.address.space
                or cell.base != self.address.base
                or cell.offset != expected_offset
                or cell.size <= 0
            ):
                return False
            expected_offset += cell.size
        return bool(self.cells and expected_offset == self.address.offset + self.address.size)


@dataclass(frozen=True, slots=True)
class StackMemoryCellLayout8616:
    """Canonical cell layout shared by every exact stack access in a function."""

    ranges: tuple[StackMemoryRangeCells8616, ...] = ()
    cells: tuple[IRAddress, ...] = ()
    overlaps: tuple[SSAMemoryOverlap8616, ...] = ()

    @property
    def complete(self) -> bool:
        """Return whether every observed range has one exact cell covering."""
        return all(item.complete for item in self.ranges)


def memory_range_key_8616(address: IRAddress) -> MemoryRangeKey8616 | None:
    """Return one versionable exact ``SS:BP`` range identity."""
    if (
        address.space is not MemSpace.SS
        or address.status is not AddressStatus.STABLE
        or address.base != ("bp",)
        or address.size <= 0
    ):
        return None
    return (address.space.value, address.base, address.offset, address.size)


def close_refused_stack_ranges_8616(
    refused_ranges: set[MemoryRangeKey8616],
    cells_by_range: dict[MemoryRangeKey8616, tuple[MemoryRangeKey8616, ...]],
) -> frozenset[MemoryRangeKey8616]:
    """Refuse every stack range sharing a canonical cell with a refusal."""
    closed = set(refused_ranges)
    while True:
        refused_cells = {cell for key in closed for cell in cells_by_range[key]}
        expanded = {
            key
            for key, cells in cells_by_range.items()
            if any(cell in refused_cells for cell in cells)
        }
        if expanded <= closed:
            return frozenset(closed)
        closed.update(expanded)


def versioned_memory_address_8616(address: IRAddress, version: int) -> IRAddress:
    """Preserve all address evidence while assigning one SSA version."""
    return replace(address, version=version)


def stack_memory_access_8616(instruction: IRInstr) -> IRAddress | None:
    """Return the memory operand for one typed stack LOAD or STORE."""
    if instruction.op not in {"LOAD", "STORE"} or not instruction.args:
        return None
    address = instruction.args[0]
    return address if isinstance(address, IRAddress) and address.space is MemSpace.SS else None


def collect_stack_memory_accesses_8616(
    blocks: tuple[SSABlock, ...],
) -> tuple[StackMemoryAccessInput8616, ...]:
    """Collect stack accesses in deterministic instruction order."""
    return tuple(
        (block.addr, index, address)
        for block in sorted(blocks, key=lambda item: item.addr)
        for index, instruction in enumerate(block.instrs)
        if (address := stack_memory_access_8616(instruction)) is not None
    )


def memory_overlap_8616(left: IRAddress, right: IRAddress) -> SSAMemoryOverlap8616 | None:
    """Return the exact intersection of two canonical non-identical ranges."""
    if left.space is not right.space or left.base != right.base:
        return None
    start = max(left.offset, right.offset)
    end = min(left.offset + left.size, right.offset + right.size)
    if start >= end:
        return None
    left_contains = left.offset <= right.offset and right.offset + right.size <= left.offset + left.size
    right_contains = right.offset <= left.offset and left.offset + left.size <= right.offset + right.size
    if left_contains:
        relation = SSAMemoryOverlapRelation8616.LEFT_CONTAINS_RIGHT
    elif right_contains:
        relation = SSAMemoryOverlapRelation8616.RIGHT_CONTAINS_LEFT
    else:
        relation = SSAMemoryOverlapRelation8616.PARTIAL
    intersection = IRAddress(
        left.space,
        left.base,
        start,
        end - start,
        left.status,
        left.segment_origin,
    )
    return SSAMemoryOverlap8616(left, right, intersection, relation)


def build_stack_memory_cell_layout_8616(
    accesses: tuple[StackMemoryAccessInput8616, ...],
) -> StackMemoryCellLayout8616:
    """Partition all proven ranges at every observed byte boundary."""
    representatives: dict[MemoryRangeKey8616, IRAddress] = {}
    boundaries: dict[tuple[str, tuple[str, ...]], set[int]] = {}
    for _block_addr, _instr_index, address in accesses:
        key = memory_range_key_8616(address)
        if key is None:
            continue
        representatives.setdefault(key, address)
        boundaries.setdefault((key[0], key[1]), set()).update(
            (address.offset, address.offset + address.size)
        )

    canonical_cells: dict[MemoryRangeKey8616, IRAddress] = {}
    ranges: list[StackMemoryRangeCells8616] = []
    for key, address in sorted(representatives.items()):
        points = (
            address.offset,
            *sorted(
                point
                for point in boundaries[(key[0], key[1])]
                if address.offset < point < address.offset + address.size
            ),
            address.offset + address.size,
        )
        cells: list[IRAddress] = []
        for start, end in itertools.pairwise(points):
            cell_key = (key[0], key[1], start, end - start)
            cell = canonical_cells.setdefault(
                cell_key,
                IRAddress(
                    address.space,
                    address.base,
                    start,
                    end - start,
                    address.status,
                    address.segment_origin,
                ),
            )
            cells.append(cell)
        ranges.append(StackMemoryRangeCells8616(key, address, tuple(cells)))

    ordered_ranges = tuple(ranges)
    overlaps = tuple(
        overlap
        for index, left in enumerate(ordered_ranges)
        for right in ordered_ranges[index + 1 :]
        if (overlap := memory_overlap_8616(left.address, right.address)) is not None
    )
    return StackMemoryCellLayout8616(
        ranges=ordered_ranges,
        cells=tuple(canonical_cells[key] for key in sorted(canonical_cells)),
        overlaps=overlaps,
    )


__all__ = [
    "StackMemoryAccessInput8616",
    "StackMemoryCellLayout8616",
    "StackMemoryRangeCells8616",
    "build_stack_memory_cell_layout_8616",
    "close_refused_stack_ranges_8616",
    "collect_stack_memory_accesses_8616",
    "memory_overlap_8616",
    "memory_range_key_8616",
    "stack_memory_access_8616",
    "versioned_memory_address_8616",
]
