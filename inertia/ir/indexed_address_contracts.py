"""Typed contracts for versioned indexed segmented-memory accesses.

Layer: IR.
Responsibility: retain exact indexed address terms, their SSA definition path,
stack-origin evidence, typed refusals, and closed evidence accounting. This
module does not trace definitions, infer aliases or bounds, widen objects,
choose C types, mutate codegen, or render C.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .core import AddressStatus, IRAddress, IRValue, MemSpace, SegmentOrigin


class IndexedAddressAccessKind8616(StrEnum):
    """Machine memory effect represented by one indexed address fact."""

    LOAD = "load"
    STORE = "store"


class IndexedAddressFailureKind8616(StrEnum):
    """Stable reasons an indexed address candidate cannot be proven."""

    ADDRESS_UNPROVEN = "address_unproven"
    ACCESS_WIDTH_CONFLICT = "access_width_conflict"
    ACCESS_MICRO_OP_CONFLICT = "access_micro_op_conflict"
    MULTIPLE_DYNAMIC_TERMS = "multiple_dynamic_terms"
    INDEX_VALUE_UNVERSIONED = "index_value_unversioned"
    INDEX_DEFINITION_MISSING = "index_definition_missing"
    INDEX_DEFINITION_CONFLICT = "index_definition_conflict"
    INDEX_EXPRESSION_UNSUPPORTED = "index_expression_unsupported"
    INDEX_SHIFT_UNSUPPORTED = "index_shift_unsupported"
    INDEX_SOURCE_UNPROVEN = "index_source_unproven"


@dataclass(frozen=True, slots=True)
class IndexedAddressDefinitionSite8616:
    """One exact SSA instruction on the index reaching-definition path."""

    block_addr: int
    instr_index: int
    instr_addr: int
    op: str

    @property
    def complete(self) -> bool:
        """Return whether this path site has exact machine and SSA identity."""
        return bool(
            self.block_addr >= 0
            and self.instr_index >= 0
            and self.instr_addr >= 0
            and self.op
        )


@dataclass(frozen=True, slots=True)
class IndexedAddressFact8616:
    """One indexed DS/ES access with exact versioned stack index provenance."""

    function_addr: int
    block_addr: int
    instr_index: int
    instr_addr: int
    kind: IndexedAddressAccessKind8616
    address: IRAddress
    index_value: IRValue
    index_source: IRAddress
    index_shift: int
    definition_path: tuple[IndexedAddressDefinitionSite8616, ...]

    @property
    def complete(self) -> bool:
        """Return whether address, index, source, width, and path agree."""
        return bool(
            self.function_addr >= 0
            and self.block_addr >= 0
            and self.instr_index >= 0
            and self.instr_addr >= 0
            and self.address.space in {MemSpace.DS, MemSpace.ES}
            and self.address.status is AddressStatus.STABLE
            and self.address.segment_origin is SegmentOrigin.PROVEN
            and self.address.size > 0
            and len(self.address.base) == len(self.address.base_values) == 1
            and self.address.base == (self.index_value.name,)
            and self.address.base_values == (self.index_value,)
            and self.index_value.space is MemSpace.REG
            and self.index_value.name is not None
            and self.index_value.version is not None
            and self.index_source.space is MemSpace.SS
            and self.index_source.base == ("bp",)
            and self.index_source.status is AddressStatus.STABLE
            and self.index_source.segment_origin is SegmentOrigin.PROVEN
            and self.index_source.size == self.index_value.size
            and 0 <= self.index_shift <= 4
            and self.definition_path
            and all(site.complete for site in self.definition_path)
            and self.definition_path[-1].op == "LOAD"
        )


@dataclass(frozen=True, slots=True)
class IndexedAddressRefusal8616:
    """One exact candidate and its typed non-materialization reason."""

    function_addr: int
    block_addr: int
    instr_index: int
    instr_addr: int
    address: IRAddress
    failure: IndexedAddressFailureKind8616


@dataclass(frozen=True, slots=True)
class IndexedAddressStats8616:
    """Closed accounting for all indexed segmented-memory candidates."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    coalesced_fact_count: int = 0

    @property
    def closed(self) -> bool:
        """Return whether every raw candidate has one fact or refusal."""
        return bool(
            self.raw_fact_count
            == self.normalized_fact_count + self.coalesced_fact_count
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count + self.failure_count
        )


@dataclass(frozen=True, slots=True)
class IndexedAddressEvidence8616:
    """Function-wide accepted indexed accesses and explicit refusals."""

    function_addr: int
    facts: tuple[IndexedAddressFact8616, ...]
    refusals: tuple[IndexedAddressRefusal8616, ...]
    stats: IndexedAddressStats8616

    @property
    def closed(self) -> bool:
        """Return whether all retained outcomes are coherent and accounted."""
        return bool(
            self.stats.closed
            and len(self.facts) == self.stats.materialized_count
            and len(self.refusals) == self.stats.failure_count
            and all(fact.complete for fact in self.facts)
        )


__all__ = [
    "IndexedAddressAccessKind8616",
    "IndexedAddressDefinitionSite8616",
    "IndexedAddressEvidence8616",
    "IndexedAddressFact8616",
    "IndexedAddressFailureKind8616",
    "IndexedAddressRefusal8616",
    "IndexedAddressStats8616",
]
