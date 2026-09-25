"""Typed contracts for exact indexed LOAD-to-STORE value copies.

Layer: IR.
Responsibility: retain the exact SSA definition paths proving that one indexed
STORE receives every byte of one indexed LOAD unchanged. These contracts do
not infer aliases, aggregate families, bounds, arrays, C types, or names.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .core import IRValue, MemSpace
from .indexed_address_contracts import (
    IndexedAddressAccessKind8616,
    IndexedAddressEvidence8616,
    IndexedAddressFact8616,
)
from .logical_memory_value_trace import LogicalMemoryValueTrace8616
from .scalar_definitions import scalar_definition_key_8616


class IndexedAddressCopyLane8616(StrEnum):
    """Byte lane represented by one exact destination value path."""

    DIRECT = "direct"
    LOW_BYTE = "low_byte"
    HIGH_BYTE = "high_byte"


class IndexedAddressCopyStepKind8616(StrEnum):
    """Supported value-preserving operation on one backward SSA path."""

    MOVE = "move"
    LOW_BYTE_EXTRACT = "low_byte_extract"
    HIGH_BYTE_SHIFT = "high_byte_shift"


class IndexedAddressCopyFailureKind8616(StrEnum):
    """Stable reason one indexed STORE has no exact indexed LOAD source."""

    NORMALIZED_STORE_MISSING = "normalized_store_missing"
    NORMALIZED_STORE_CONFLICT = "normalized_store_conflict"
    STORE_VALUE_UNSUPPORTED = "store_value_unsupported"
    VALUE_DEFINITION_MISSING = "value_definition_missing"
    VALUE_DEFINITION_CONFLICT = "value_definition_conflict"
    VALUE_OPERATION_UNSUPPORTED = "value_operation_unsupported"
    VALUE_WIDTH_CONFLICT = "value_width_conflict"
    SPLIT_LANE_CONFLICT = "split_lane_conflict"
    SOURCE_LOAD_NOT_INDEXED = "source_load_not_indexed"
    SOURCE_LOAD_CONFLICT = "source_load_conflict"
    LOGICAL_MEMORY_EVIDENCE_UNPROVEN = "logical_memory_evidence_unproven"
    LOGICAL_MEMORY_EVIDENCE_CONFLICT = "logical_memory_evidence_conflict"


@dataclass(frozen=True, slots=True)
class IndexedAddressCopyStep8616:
    """One exact backward SSA edge from a definition to its source."""

    block_addr: int
    instr_index: int
    instr_addr: int
    op: str
    kind: IndexedAddressCopyStepKind8616
    defined_value: IRValue
    source_expression: IRValue
    source_definition: IRValue
    constant: int | None = None

    @property
    def complete(self) -> bool:
        """Return whether the operation proves its declared value relation."""
        identity_matches = (
            scalar_definition_key_8616(self.source_expression)
            == scalar_definition_key_8616(self.source_definition)
        )
        common = bool(
            self.block_addr >= 0
            and self.instr_index >= 0
            and self.instr_addr >= 0
            and self.defined_value.space not in {MemSpace.CONST, MemSpace.UNKNOWN}
            and self.source_definition.space not in {MemSpace.CONST, MemSpace.UNKNOWN}
            and identity_matches
        )
        if self.kind is IndexedAddressCopyStepKind8616.MOVE:
            relation = (
                self.op == "MOV"
                and self.constant is None
                and self.defined_value.size == self.source_definition.size > 0
            )
        elif self.kind is IndexedAddressCopyStepKind8616.LOW_BYTE_EXTRACT:
            relation = (
                self.op == "MOV"
                and self.constant is None
                and self.defined_value.size == 1
                and self.source_definition.size == 2
                and self.source_expression.expr == ("Iop_16to8",)
            )
        else:
            relation = (
                self.op == "Iop_Shr16"
                and self.constant == 8
                and self.defined_value.size == self.source_definition.size == 2
            )
        return bool(common and relation)


@dataclass(frozen=True, slots=True)
class IndexedAddressCopyValuePath8616:
    """One destination byte lane traced backward to an exact source value."""

    store_instr_index: int
    load_block_addr: int
    load_instr_index: int
    load_instr_addr: int
    lane: IndexedAddressCopyLane8616
    store_value: IRValue
    load_value: IRValue
    steps: tuple[IndexedAddressCopyStep8616, ...]
    logical_source: LogicalMemoryValueTrace8616 | None = None

    def _indices_ordered_8616(self) -> bool:
        """Return whether the recorded store/load positions are sane."""
        return (
            self.store_instr_index >= 0
            and self.load_block_addr >= 0
            and self.load_instr_index >= 0
            and self.load_instr_addr >= 0
            and self.load_instr_index < self.store_instr_index
        )

    def _logical_source_proven_8616(self) -> bool:
        """Return whether the optional logical source is complete."""
        if self.logical_source is None:
            return True
        logical_loads = tuple(
            site
            for site in self.logical_source.definition_path
            if site.op == "LOAD"
        )
        source = self.logical_source.source
        return bool(
            self.logical_source.complete
            and source is not None
            and source.size == self.load_value.size
            and len(logical_loads) == 2
        )

    @property
    def complete(self) -> bool:
        """Return whether the path is contiguous and lane-preserving."""
        if not self._indices_ordered_8616():
            return False
        if not all(step.complete for step in self.steps):
            return False
        if not self._logical_source_proven_8616():
            return False
        if self.steps:
            if (
                scalar_definition_key_8616(self.store_value)
                != scalar_definition_key_8616(self.steps[0].defined_value)
                or scalar_definition_key_8616(self.steps[-1].source_definition)
                != scalar_definition_key_8616(self.load_value)
            ):
                return False
            if any(
                scalar_definition_key_8616(left.source_definition)
                != scalar_definition_key_8616(right.defined_value)
                for left, right in zip(self.steps, self.steps[1:], strict=False)
            ):
                return False
            indices = tuple(step.instr_index for step in self.steps)
            if indices != tuple(sorted(indices, reverse=True)) or len(indices) != len(set(indices)):
                return False
        elif scalar_definition_key_8616(self.store_value) != scalar_definition_key_8616(
            self.load_value
        ):
            return False
        semantic_steps = tuple(
            step.kind
            for step in self.steps
            if step.kind is not IndexedAddressCopyStepKind8616.MOVE
        )
        expected = {
            IndexedAddressCopyLane8616.DIRECT: (),
            IndexedAddressCopyLane8616.LOW_BYTE: (
                IndexedAddressCopyStepKind8616.LOW_BYTE_EXTRACT,
            ),
            IndexedAddressCopyLane8616.HIGH_BYTE: (
                IndexedAddressCopyStepKind8616.LOW_BYTE_EXTRACT,
                IndexedAddressCopyStepKind8616.HIGH_BYTE_SHIFT,
            ),
        }[self.lane]
        return semantic_steps == expected

    def matches_source(self, source: IndexedAddressFact8616) -> bool:
        """Return whether this path proves one exact indexed LOAD owner."""
        if self.logical_source is None:
            return (
                self.load_block_addr,
                self.load_instr_index,
                self.load_instr_addr,
            ) == (source.block_addr, source.instr_index, source.instr_addr)
        logical_address = self.logical_source.source
        logical_loads = tuple(
            site for site in self.logical_source.definition_path if site.op == "LOAD"
        )
        if logical_address is None or len(logical_loads) != 2:
            return False
        low_load = logical_loads[0]
        return bool(
            (low_load.block_addr, low_load.instr_index, low_load.instr_addr)
            == (source.block_addr, source.instr_index, source.instr_addr)
            and logical_address.space is source.address.space
            and logical_address.base == source.address.base
            and logical_address.offset == source.address.offset
            and logical_address.size == source.address.size
            and logical_address.status is source.address.status
            and logical_address.segment_origin is source.address.segment_origin
        )


@dataclass(frozen=True, slots=True)
class IndexedAddressCopyFact8616:
    """One indexed destination receiving an unchanged indexed source value."""

    source: IndexedAddressFact8616
    destination: IndexedAddressFact8616
    member_instr_indices: tuple[int, ...]
    value_paths: tuple[IndexedAddressCopyValuePath8616, ...]

    @property
    def complete(self) -> bool:
        """Return whether both endpoint and every byte-lane proof agree."""
        expected_lanes = (
            (IndexedAddressCopyLane8616.DIRECT,)
            if len(self.member_instr_indices) == 1
            else (
                IndexedAddressCopyLane8616.LOW_BYTE,
                IndexedAddressCopyLane8616.HIGH_BYTE,
            )
        )
        return bool(
            self.source.complete
            and self.destination.complete
            and self.source.kind is IndexedAddressAccessKind8616.LOAD
            and self.destination.kind is IndexedAddressAccessKind8616.STORE
            and self.source.function_addr == self.destination.function_addr
            and self.source.block_addr == self.destination.block_addr
            and self.source.instr_index < self.destination.instr_index
            and self.source.address.size == self.destination.address.size > 0
            and len(self.member_instr_indices) in {1, 2}
            and self.member_instr_indices
            == tuple(path.store_instr_index for path in self.value_paths)
            and tuple(path.lane for path in self.value_paths) == expected_lanes
            and all(path.complete for path in self.value_paths)
            and all(path.matches_source(self.source) for path in self.value_paths)
            and all(
                scalar_definition_key_8616(path.load_value)
                == scalar_definition_key_8616(self.value_paths[0].load_value)
                for path in self.value_paths
            )
            and all(
                path.logical_source == self.value_paths[0].logical_source
                for path in self.value_paths
            )
        )


@dataclass(frozen=True, slots=True)
class IndexedAddressCopyRefusal8616:
    """One retained indexed STORE and its value-copy refusal reason."""

    destination: IndexedAddressFact8616
    failure: IndexedAddressCopyFailureKind8616
    detail: str

    @property
    def complete(self) -> bool:
        """Return whether this refusal owns one exact STORE candidate."""
        return bool(
            self.destination.complete
            and self.destination.kind is IndexedAddressAccessKind8616.STORE
            and self.detail
        )


@dataclass(frozen=True, slots=True)
class IndexedAddressCopyStats8616:
    """Closed accounting for indexed STORE value-path classification."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def closed(self) -> bool:
        """Return whether every STORE became one copy or refusal."""
        return bool(
            self.raw_fact_count == self.materialized_count + self.failure_count
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )


@dataclass(frozen=True, slots=True)
class IndexedAddressCopyEvidence8616:
    """Function-wide exact indexed copies with every STORE refusal retained."""

    function_addr: int
    facts: tuple[IndexedAddressCopyFact8616, ...]
    refusals: tuple[IndexedAddressCopyRefusal8616, ...]
    stats: IndexedAddressCopyStats8616
    source: IndexedAddressEvidence8616

    @property
    def closed(self) -> bool:
        """Return whether source STORE accounting closes without loss."""
        destinations = tuple(fact.destination for fact in self.facts) + tuple(
            refusal.destination for refusal in self.refusals
        )
        source_stores = tuple(
            fact
            for fact in self.source.facts
            if fact.kind is IndexedAddressAccessKind8616.STORE
        )
        return bool(
            self.source.closed
            and self.function_addr == self.source.function_addr
            and self.stats.raw_fact_count == len(source_stores)
            and len(self.facts) == self.stats.materialized_count
            and len(self.refusals) == self.stats.failure_count
            and self.stats.closed
            and all(fact.complete for fact in self.facts)
            and all(refusal.complete for refusal in self.refusals)
            and len(destinations) == len(source_stores)
            and all(destinations.count(source) == 1 for source in source_stores)
        )


__all__ = [
    "IndexedAddressCopyEvidence8616",
    "IndexedAddressCopyFact8616",
    "IndexedAddressCopyFailureKind8616",
    "IndexedAddressCopyLane8616",
    "IndexedAddressCopyRefusal8616",
    "IndexedAddressCopyStats8616",
    "IndexedAddressCopyStep8616",
    "IndexedAddressCopyStepKind8616",
    "IndexedAddressCopyValuePath8616",
]
