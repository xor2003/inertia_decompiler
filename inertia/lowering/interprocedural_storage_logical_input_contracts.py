# cython: language_level=3, infer_types=True
"""Retain proven physical PUSH values and bind their slices to input trials.

Layer: Types/Lowering.
Responsibility: carry producer-owned SSA roots without reconstructing them in
consumers, and check exact caller/callee/call/argument/slice identity. Value
transport does not prove pointer type, pointee, segment equivalence, or storage
widening; original callee address provenance is preserved unchanged.
Consumes alias, widening, and typed facts. No codegen or text-based recovery.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from inertia.ir.core import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace, SegmentOrigin
from inertia.ir.ssa import SSABlock
import dataclasses
import operator
StorageReachingDefinition8616 = typing.TypeVar("StorageReachingDefinition8616")
StorageUseEvidence8616 = typing.TypeVar("StorageUseEvidence8616")

if TYPE_CHECKING:
    from .interprocedural_storage_contracts import StorageReachingDefinition8616, StorageUseEvidence8616


@dataclasses.dataclass(frozen=True, )
class SSAInstructionSite8616:
    """One typed SSA instruction with stable block/index coordinates."""

    block: SSABlock
    instr_index: cython.longlong
    instr: IRInstr


@dataclasses.dataclass(frozen=True, )
class PhysicalPushStoreSlice8616:
    """One exact outgoing stack-store slice of a logical pushed value."""

    site: SSAInstructionSite8616
    address: IRAddress
    value: IRValue
    source_offset: cython.longlong

    @property
    def complete(self) -> cython.bint:
        """Return whether this slice retains exact stack and value identity."""
        return bool(
            self.source_offset >= 0
            and self.address.space is MemSpace.SS
            and self.address.base == ("sp",)
            and self.address.size == self.value.size > 0
            and self.address.status is AddressStatus.STABLE
            and self.address.segment_origin is SegmentOrigin.PROVEN
        )

    def matches_definition(self, definition: StorageReachingDefinition8616) -> cython.bint:
        """Match the actual byte producer, including VEX identity excluded by IR equality."""
        value = definition.value
        return bool(
            operator.eq(self.site.block.addr, definition.block_addr)
            and operator.eq(self.site.instr_index, definition.instr_index)
            and operator.eq(self.site.instr.addr, definition.instr_addr)
            and operator.eq(self.value, value)
            and operator.eq(self.value.source_tmp, value.source_tmp)
            and operator.eq(self.value.memory_access_insn, value.memory_access_insn)
        )


@dataclasses.dataclass(frozen=True, )
class LogicalPushValue8616:
    """One reconstructed logical value and all physical outgoing slices."""

    root: IRValue
    width: cython.longlong
    slices: object

    @property
    def complete(self) -> cython.bint:
        """Return whether every byte belongs to one exact logical root."""
        return bool(
            self.width > 0
            and operator.eq(self.root.size, self.width)
            and self.slices
            and all(item.complete for item in iter(self.slices))
            and operator.eq(sum(item.address.size for item in iter(self.slices)), self.width)
            and operator.eq(tuple(item.source_offset for item in iter(self.slices)), tuple(
                sum(previous.address.size for previous in iter(self.slices[:index]))
                for index in range(len(self.slices))
            ))
        )

    @property
    def evidence_key(self) -> tuple[object, ...]:
        """Keep SSA/VEX identity and physical coordinates without mutable CFG equality."""
        return (
            self.root, self.root.source_tmp, self.root.memory_access_insn, self.width,
            tuple(
                (item.site.block.addr, item.site.instr_index, item.site.instr.addr,
                 item.address, item.value, item.value.source_tmp,
                 item.value.memory_access_insn, item.source_offset)
                for item in iter(self.slices)
            ),
        )

    def definition_slice(
        self, definition: StorageReachingDefinition8616,
    ) -> PhysicalPushStoreSlice8616 | None:
        """Return one exact slice, never an ambiguous or incomplete byte match."""
        if not self.complete:
            return None
        matches = tuple(item for item in iter(self.slices) if item.matches_definition(definition))
        return matches[0] if len(matches) == 1 else None


@dataclasses.dataclass(frozen=True, )
class LogicalInputRootBinding8616:
    """One retained PUSH slice bound to an exact logical input and CALL use.

    A multi-push argument may retain several smaller roots. Only
    ``covers_logical_argument`` identifies a root covering the entire input;
    neither that property nor ``complete`` proves a native pointer binding.
    """

    callee_addr: cython.longlong
    caller_addr: cython.longlong
    callsite_addr: cython.longlong
    logical_index: cython.longlong
    piece_index: cython.longlong
    piece_count: cython.longlong
    push_addr: cython.longlong
    source_offset: cython.longlong
    argument_offset: cython.longlong
    byte_width: cython.longlong
    argument_storage: IRAddress
    logical_push: LogicalPushValue8616
    call_use: StorageUseEvidence8616

    @property
    def root(self) -> IRValue:
        """Consume the original producer root, not a competing reconstruction."""
        return self.logical_push.root

    @property
    def width(self) -> cython.longlong:
        """Return the width of this physical PUSH root, not the whole argument."""
        return self.logical_push.width

    @property
    def slices(self) -> object:
        """Expose the original exact store witnesses without changing their origins."""
        return self.logical_push.slices

    @property
    def push_argument_offset(self) -> cython.longlong:
        """Locate this PUSH root within a possibly multi-push logical argument."""
        return self.argument_offset - self.source_offset

    @property
    def covers_logical_argument(self) -> cython.bint:
        """Return whether one bound producer root covers the complete input."""
        return self.complete and self.push_argument_offset == 0 and operator.eq(self.width, self.argument_storage.size)

    @property
    def complete(self) -> cython.bint:
        """Require exact scope, CALL coordinates, PUSH site and byte coverage."""
        scope_complete = (
            self.callee_addr >= 0 and self.caller_addr >= 0 and self.logical_index >= 0
            and 0 <= self.piece_index < self.piece_count
        )
        call_complete = (
            self.call_use.is_complete
            and self.callsite_addr == self.call_use.callsite_addr == self.call_use.instr_addr
        )
        storage_complete = (
            self.argument_storage.space is MemSpace.SS
            and self.argument_storage.base == ("bp",)
            and self.argument_storage.status is AddressStatus.STABLE
            and self.byte_width > 0 and self.push_argument_offset >= 0
            and self.push_argument_offset + self.width <= self.argument_storage.size
        )
        slices_complete = (
            self.logical_push.complete
            and all(operator.eq(item.site.instr.addr, self.push_addr) for item in iter(self.slices))
            and sum(
                operator.eq(item.source_offset, self.source_offset) and operator.eq(item.address.size, self.byte_width)
                for item in iter(self.slices)
            ) == 1
        )
        return scope_complete and call_complete and storage_complete and slices_complete

    @property
    def callee_piece_address(self) -> IRAddress:
        """Derive the byte piece while retaining all original address provenance."""
        return replace(
            self.argument_storage, offset=self.argument_storage.offset + self.argument_offset,
            size=self.byte_width,
        )

    def matches_definition(self, definition: StorageReachingDefinition8616) -> cython.bint:
        """Reject a foreign root or a sibling slice, even with equal scalar values."""
        item: object
        proof: object
        proof = definition.logical_push
        if proof is None or operator.ne(proof.evidence_key, self.logical_push.evidence_key):
            return False
        item = self.logical_push.definition_slice(definition)
        return bool(
            self.complete and item is not None
            and operator.eq(item.source_offset, self.source_offset)
            and operator.eq(item.address.size, self.byte_width)
        )
