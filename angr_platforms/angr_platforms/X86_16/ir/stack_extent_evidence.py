"""Collect matched block-local stack allocation and release coordinates.

Layer: IR.
Responsibility: publish exact SSA SP/BP arithmetic spans, not private storage
or dead-store permission.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
Read/escape closure and complete function lifetime remain separate obligations.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .core import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace, SegmentOrigin
from .scalar_value_projection import (
    ScalarProjectionKind8616,
    scalar_produced_decoration_8616,
    scalar_read_projection_8616,
)
from .ssa import SSABlock

_WORD_BYTES = 2
_OFFSET_MODULUS = 1 << 16
type _RegisterKey = tuple[str, int]
type _CapturedCoordinates = dict[int, tuple[IRInstr, int | None]]


class StackExtentRefusal8616(StrEnum):
    """Why block-local coordinate evidence cannot be published."""

    NONE = "none"
    UNKNOWN_COORDINATE = "unknown_coordinate"
    WRAP_SIZED_MOVEMENT = "wrap_sized_movement"
    PARTIAL_RELEASE = "partial_release"
    UNRELEASED_ALLOCATION = "unreleased_allocation"


@dataclass(frozen=True, slots=True)
class ReleasedStackExtent8616:
    """One allocation released in the same straight-line SSA block.

    Offsets are relative to that block's incoming SP, not function entry or
    BP. A saved-register PUSH can also form an extent: this is not local
    storage classification and must never be consumed as DCE permission.
    """

    block_addr: int
    allocation_index: int
    release_index: int
    lower_offset: int
    upper_offset: int

    def to_dict(self) -> dict[str, int]:
        """Serialize source positions and block-relative byte coordinates."""
        return {
            "block_addr": self.block_addr,
            "allocation_index": self.allocation_index,
            "release_index": self.release_index,
            "lower_offset": self.lower_offset,
            "upper_offset": self.upper_offset,
        }


@dataclass(frozen=True, slots=True)
class StackRegisterCoordinate8616:
    """One exact register definition relative to this block's incoming SP."""

    name: str
    version: int
    definition_index: int
    entry_offset: int

    def to_dict(self) -> dict[str, object]:
        """Serialize identity separately from its affine displacement."""
        return {"name": self.name, "version": self.version,
                "definition_index": self.definition_index, "entry_offset": self.entry_offset}


@dataclass(frozen=True, slots=True)
class StackExtentEvidence8616:
    """One block's coordinate census, explicitly separate from DCE proof.

    Census units are analyzed blocks, not bytes, extents, or deleted writes.
    A successful empty result means no matched allocation in this block;
    unknown results must never be interpreted as absence of allocations.
    """

    block_addr: int
    extents: tuple[ReleasedStackExtent8616, ...] = ()
    refusal: StackExtentRefusal8616 = StackExtentRefusal8616.NONE
    coordinates: tuple[StackRegisterCoordinate8616, ...] = ()

    @property
    def complete(self) -> bool:
        """Report coordinate-analysis completion, not private frame lifetime."""
        return self.refusal is StackExtentRefusal8616.NONE

    def address_entry_offset(self, block_addr: int, instruction_index: int, address: IRAddress) -> int | None:
        """Resolve an exact SS access in this block without granting ownership.

        An SSA definition must precede the access. A matching register name
        alone, a different block, or a missing source version is insufficient.
        Returned displacements retain their unwrapped coordinate; consumers
        must still account for circular byte overlap and the access width.
        """
        if not self.complete or block_addr != self.block_addr:
            return None
        if address.space is not MemSpace.SS or address.status is not AddressStatus.STABLE:
            return None
        if address.segment_origin is not SegmentOrigin.PROVEN or address.size <= 0:
            return None
        if address.base not in {("sp",), ("bp",)} or len(address.base_values) != 1:
            return None
        base = address.base_values[0]
        plain_base = base.index is None and base.expr in {None, ()} and base.offset == 0
        if not plain_base or _register_key(base) is None or base.name != address.base[0]:
            return None
        for coordinate in self.coordinates:
            if (coordinate.name, coordinate.version) == (base.name, base.version):
                if coordinate.definition_index < instruction_index:
                    return int(coordinate.entry_offset + address.offset)
                return None
        return None

    def to_dict(self) -> dict[str, object]:
        """Serialize the verdict and a closed block-analysis census."""
        accepted = int(self.complete)
        normalized = int(self.refusal is not StackExtentRefusal8616.UNKNOWN_COORDINATE)
        return {
            "block_addr": self.block_addr,
            "extents": [extent.to_dict() for extent in self.extents],
            "coordinates": [coordinate.to_dict() for coordinate in self.coordinates],
            "refusal": self.refusal.value,
            "complete": self.complete,
            "stats": {
                "raw_fact_count": 1,
                "normalized_fact_count": normalized,
                "classified_fact_count": accepted,
                "materialized_count": accepted,
                "failure_count": 1 - accepted,
            },
        }


def _register_key(value: IRValue) -> _RegisterKey | None:
    """Require a whole word register with an exact SSA definition identity."""
    if value.space is not MemSpace.REG or value.name not in {"sp", "bp"}:
        return None
    if value.size != _WORD_BYTES or value.version is None:
        return None
    return value.name, value.version


def _value_coordinate(
    source: IRValue, coordinates: dict[_RegisterKey, int], captures: _CapturedCoordinates,
) -> int | None:
    """Resolve a captured result before considering a bare register descriptor."""
    if source.active_unary is not None or source.index is not None or source.size != _WORD_BYTES:
        return None
    if source.source_tmp is not None:
        captured = captures.get(source.source_tmp)
        if captured is None or source.offset != 0:
            return None
        producer, coordinate = captured
        projection = scalar_read_projection_8616(
            read_expr=source.expr, read_bits=16,
            produced=scalar_produced_decoration_8616(producer), produced_bits=producer.size * 8,
        )
        if projection is None or projection.kind is ScalarProjectionKind8616.CONVERSION:
            return None
        return coordinate
    key = _register_key(source)
    if key is None or key not in coordinates:
        return None
    if source.expr not in {None, (), ("Iop_Add16",), ("Iop_Sub16",)}:
        return None
    return int(coordinates[key] + source.offset)


def _source_coordinate(
    instruction: IRInstr, coordinates: dict[_RegisterKey, int], captures: _CapturedCoordinates,
) -> int | None:
    """Evaluate exact word copies and literal displacement arithmetic."""
    if instruction.size != _WORD_BYTES or not instruction.args:
        return None
    source = instruction.args[0]
    if not isinstance(source, IRValue):
        return None
    coordinate = _value_coordinate(source, coordinates, captures)
    if instruction.op == "MOV" and len(instruction.args) == 1:
        return coordinate
    if coordinate is None or instruction.op not in {"Iop_Add16", "Iop_Sub16"} or len(instruction.args) != 2:
        return None
    displacement = instruction.args[1]
    if not isinstance(displacement, IRValue):
        return None
    plain_literal = (
        displacement.space is MemSpace.CONST and displacement.size == _WORD_BYTES
        and displacement.source_tmp is None and displacement.active_unary is None
        and displacement.index is None and displacement.offset == 0
        and displacement.expr in {None, ()}
    )
    if not plain_literal or not isinstance(displacement.const, int) or not 0 <= displacement.const < 0x8000:
        return None
    delta = displacement.const if instruction.op == "Iop_Add16" else -displacement.const
    return coordinate + delta


def _record_capture(
    instruction: IRInstr, coordinates: dict[_RegisterKey, int], captures: _CapturedCoordinates,
) -> None:
    """Retain one producer per capture; ambiguous and nonword results stay unknown."""
    destination = instruction.dst
    if destination is None or destination.source_tmp is None:
        return
    number = destination.source_tmp
    coordinate = None
    if number not in captures and destination.size == _WORD_BYTES and destination.active_unary is None:
        coordinate = _source_coordinate(instruction, coordinates, captures)
    captures[number] = (instruction, coordinate)


def _release_extents(
    pending: list[tuple[int, int, int]], block_addr: int, index: int, before: int, after: int,
) -> tuple[list[tuple[int, int, int]], list[ReleasedStackExtent8616]] | None:
    """Consume complete releases, refusing partial byte-lifetime splitting."""
    remaining = []
    released = []
    for allocation_index, lower, upper in pending:
        if before <= lower and after >= upper:
            released.append(ReleasedStackExtent8616(block_addr, allocation_index, index, lower, upper))
        elif after > lower:
            return None
        else:
            remaining.append((allocation_index, lower, upper))
    return remaining, released


def _stack_coordinates(
    block: SSABlock,
) -> tuple[list[tuple[int, int]], tuple[StackRegisterCoordinate8616, ...]] | None:
    """Resolve whole-word SP writes through exact block-local SSA copies."""
    if block.refusals:
        return None
    coordinates: dict[_RegisterKey, int] = {("sp", 0): 0}
    captures: _CapturedCoordinates = {}
    definitions = set(coordinates)
    writes = []
    records = [StackRegisterCoordinate8616("sp", 0, -1, 0)]
    for index, instruction in enumerate(block.instrs):
        if instruction.op in {"CALL", "BRANCH", "CBRANCH", "JUMP", "CJUMP", "JMP", "CJMP"}:
            return None
        _record_capture(instruction, coordinates, captures)
        destination = instruction.dst
        if destination is None or destination.space is not MemSpace.REG or destination.name not in {"sp", "bp", "esp", "ebp"}:
            continue
        key = _register_key(destination)
        coordinate = _source_coordinate(instruction, coordinates, captures)
        if key is None or key in definitions:
            return None
        definitions.add(key)
        if coordinate is not None:
            coordinates[key] = coordinate
            records.append(StackRegisterCoordinate8616(key[0], key[1], index, coordinate))
        if destination.name != "sp":
            continue
        if coordinate is None:
            return None
        writes.append((index, coordinate))
    return writes, tuple(records)


def build_stack_extent_evidence_8616(block: SSABlock) -> StackExtentEvidence8616:
    """Match bounded downward SP movements with later upward movements.

    Unknown SP, calls, branches, duplicate SSA definitions and wrap-sized
    movements refuse the block. Unknown restored BP is harmless unless used
    to compute SP. Block-local input versions cannot prove relationships
    across CFG edges. No read, escape or private-storage claim is made.
    """
    trace = _stack_coordinates(block)
    if trace is None:
        return StackExtentEvidence8616(block.addr, refusal=StackExtentRefusal8616.UNKNOWN_COORDINATE)
    writes, coordinates = trace
    current_sp = 0
    pending: list[tuple[int, int, int]] = []
    released: list[ReleasedStackExtent8616] = []
    for index, coordinate in writes:
        if abs(coordinate - current_sp) >= _OFFSET_MODULUS:
            return StackExtentEvidence8616(block.addr, refusal=StackExtentRefusal8616.WRAP_SIZED_MOVEMENT)
        if coordinate < current_sp:
            pending.append((index, coordinate, current_sp))
        elif coordinate > current_sp:
            result = _release_extents(pending, block.addr, index, current_sp, coordinate)
            if result is None:
                return StackExtentEvidence8616(block.addr, refusal=StackExtentRefusal8616.PARTIAL_RELEASE)
            pending, matched = result
            released.extend(matched)
        current_sp = coordinate
    if pending:
        return StackExtentEvidence8616(block.addr, refusal=StackExtentRefusal8616.UNRELEASED_ALLOCATION)
    return StackExtentEvidence8616(
        block.addr, tuple(sorted(released, key=lambda extent: extent.allocation_index)), coordinates=coordinates,
    )


def collect_released_stack_extents_8616(block: SSABlock) -> tuple[ReleasedStackExtent8616, ...]:
    """Compatibility projection; an empty tuple does not establish completeness."""
    return build_stack_extent_evidence_8616(block).extents
