"""Typed contracts for logical segmented-memory accesses and execution slices.

Layer: IR.
Responsibility: own one machine memory operand, its durable instruction identity,
exact byte execution slices, typed refusals, and closed evidence accounting.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .core import IRAddress, MemSpace


class IRMemoryAccessKind8616(StrEnum):
    """Typed operation represented by one captured machine memory operand."""

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    UNKNOWN = "unknown"


def logical_memory_byte_offset_8616(
    address: IRAddress,
    source_byte_offset: int,
    address_bits: int,
) -> int:
    """Return one byte displacement with direct segment-offset wrap."""
    offset = int(address.offset) + source_byte_offset
    if address.base:
        return offset
    return offset & ((1 << address_bits) - 1)


def logical_memory_execution_address_matches_8616(
    actual: IRAddress,
    logical: IRAddress,
    source_byte_offset: int,
    address_bits: int,
) -> bool:
    """Match one raw execution address to its logical segmented byte."""
    return bool(
        actual.space is logical.space
        and actual.base == logical.base
        and logical_memory_byte_offset_8616(actual, 0, address_bits)
        == logical_memory_byte_offset_8616(
            logical,
            source_byte_offset,
            address_bits,
        )
        and actual.status is logical.status
        and actual.segment_origin is logical.segment_origin
    )


class IRLogicalMemoryFailureKind8616(StrEnum):
    """Stable reason a captured operand cannot become one logical IR access."""

    INVALID_ADDRESS = "invalid_address"
    UNSUPPORTED_MODE = "unsupported_mode"
    MISSING_BLOCK_ADDR = "missing_block_addr"
    MISSING_INSN_ADDR = "missing_insn_addr"
    MISSING_ADDRESS_WIDTH = "missing_address_width"
    DUPLICATE_CAPTURE_KEY = "duplicate_capture_key"
    MISSING_EXECUTION_SLICES = "missing_execution_slices"
    AMBIGUOUS_EXECUTION_SLICES = "ambiguous_execution_slices"
    ACCESS_KIND_CONFLICT = "access_kind_conflict"
    SEGMENT_CONFLICT = "segment_conflict"
    BYTE_COVERAGE_CONFLICT = "byte_coverage_conflict"


@dataclass(frozen=True, slots=True)
class IRLogicalMemoryAccessKey8616:
    """Durable identity of one memory operand independent of mutable IR indexes."""

    function_addr: int
    block_addr: int
    insn_addr: int
    access_ordinal: int

    @property
    def complete(self) -> bool:
        """Return whether every stable identity component is available."""
        return bool(
            self.function_addr >= 0
            and self.block_addr >= 0
            and self.insn_addr >= 0
            and self.access_ordinal >= 0
        )

    def to_dict(self) -> dict[str, int]:
        """Return a deterministic JSON-friendly identity record."""
        return {
            "function_addr": self.function_addr,
            "block_addr": self.block_addr,
            "insn_addr": self.insn_addr,
            "access_ordinal": self.access_ordinal,
        }


@dataclass(frozen=True, slots=True)
class IRMemoryExecutionSlice8616:
    """One exact byte operation that executes part of a logical memory access."""

    block_addr: int
    instr_index: int
    insn_addr: int
    source_byte_offset: int
    address: IRAddress

    @property
    def complete(self) -> bool:
        """Return whether this slice has exact site and one-byte address identity."""
        return bool(
            self.block_addr >= 0
            and self.instr_index >= 0
            and self.insn_addr >= 0
            and self.source_byte_offset >= 0
            and self.address.size == 1
            and self.address.space in {MemSpace.DS, MemSpace.ES, MemSpace.SS}
        )

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly execution-slice record."""
        return {
            "block_addr": self.block_addr,
            "instr_index": self.instr_index,
            "insn_addr": self.insn_addr,
            "source_byte_offset": self.source_byte_offset,
            "address": self.address.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class IRLogicalMemoryAccess8616:
    """One typed machine operand retained across byte-oriented execution IR."""

    key: IRLogicalMemoryAccessKey8616
    kind: IRMemoryAccessKind8616
    address: IRAddress
    address_bits: int
    execution_slices: tuple[IRMemoryExecutionSlice8616, ...]

    @property
    def complete(self) -> bool:
        """Return whether logical width and exact execution-byte coverage agree."""
        offsets = tuple(item.source_byte_offset for item in self.execution_slices)
        return bool(
            self.key.complete
            and self.kind in {IRMemoryAccessKind8616.READ, IRMemoryAccessKind8616.WRITE}
            and self.address.space in {MemSpace.DS, MemSpace.ES, MemSpace.SS}
            and self.address.size > 0
            and self.address_bits in {16, 32}
            and len(self.execution_slices) == self.address.size
            and offsets == tuple(range(self.address.size))
            and all(item.complete for item in self.execution_slices)
            and all(item.block_addr == self.key.block_addr for item in self.execution_slices)
            and all(item.insn_addr == self.key.insn_addr for item in self.execution_slices)
            and all(
                logical_memory_execution_address_matches_8616(
                    item.address,
                    self.address,
                    item.source_byte_offset,
                    self.address_bits,
                )
                for item in self.execution_slices
            )
        )

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly logical-access record."""
        return {
            "key": self.key.to_dict(),
            "kind": self.kind.value,
            "address": self.address.to_dict(),
            "address_bits": self.address_bits,
            "execution_slices": [item.to_dict() for item in self.execution_slices],
        }


@dataclass(frozen=True, slots=True)
class IRLogicalMemoryRefusal8616:
    """One captured operand and its typed non-materialization outcome."""

    function_addr: int
    block_addr: int | None
    insn_addr: int | None
    access_ordinal: int | None
    failure: IRLogicalMemoryFailureKind8616
    detail: str

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly refusal record."""
        return {
            "function_addr": self.function_addr,
            "block_addr": self.block_addr,
            "insn_addr": self.insn_addr,
            "access_ordinal": self.access_ordinal,
            "failure": self.failure.value,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class IRLogicalMemoryStats8616:
    """Closed accounting for captured logical-memory candidates."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def closed(self) -> bool:
        """Return whether every raw candidate became one access or refusal."""
        return bool(
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count + self.failure_count
        )

    def to_dict(self) -> dict[str, int]:
        """Return deterministic evidence counters for diagnostics."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


@dataclass(frozen=True, slots=True)
class IRLogicalMemoryArtifact8616:
    """Function-wide accepted logical accesses and explicit typed refusals."""

    function_addr: int
    accesses: tuple[IRLogicalMemoryAccess8616, ...]
    refusals: tuple[IRLogicalMemoryRefusal8616, ...]
    stats: IRLogicalMemoryStats8616

    @property
    def closed(self) -> bool:
        """Return whether outcomes, counters, and accepted contracts agree."""
        return bool(
            self.stats.closed
            and len(self.accesses) == self.stats.materialized_count
            and len(self.refusals) == self.stats.failure_count
            and all(item.complete for item in self.accesses)
        )

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly function artifact."""
        return {
            "function_addr": self.function_addr,
            "accesses": [item.to_dict() for item in self.accesses],
            "refusals": [item.to_dict() for item in self.refusals],
            "stats": self.stats.to_dict(),
            "closed": self.closed,
        }


def empty_ir_logical_memory_artifact_8616(function_addr: int) -> IRLogicalMemoryArtifact8616:
    """Return a closed empty artifact for a function with no captured operands."""
    return IRLogicalMemoryArtifact8616(function_addr, (), (), IRLogicalMemoryStats8616())


__all__ = [
    "IRLogicalMemoryAccess8616",
    "IRLogicalMemoryAccessKey8616",
    "IRLogicalMemoryArtifact8616",
    "IRLogicalMemoryFailureKind8616",
    "IRLogicalMemoryRefusal8616",
    "IRLogicalMemoryStats8616",
    "IRMemoryAccessKind8616",
    "IRMemoryExecutionSlice8616",
    "empty_ir_logical_memory_artifact_8616",
    "logical_memory_byte_offset_8616",
    "logical_memory_execution_address_matches_8616",
]
