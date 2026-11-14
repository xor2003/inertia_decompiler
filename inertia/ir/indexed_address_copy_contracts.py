# cython: language_level=3, infer_types=True
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
import typing
import cython

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
from .scalar_value_projection import scalar_active_unary_projection_8616
import dataclasses
import operator
import builtins


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


@cython.ccall
def indexed_copy_source_operand_8616(value: IRValue) -> IRValue | None:
    """Return the exact source operand of an allowed copy-lane expression.

    A pending word extraction has its own result view, not the captured source
    identity. Authenticate its operation and widths before exposing the operand;
    all other pending computations refuse rather than impersonate a definition.
    """
    projection: object
    unary: object
    unary = value.active_unary
    if unary is None:
        return value
    projection = scalar_active_unary_projection_8616(value)
    if projection is None or (projection.source_bits, projection.target_bits) != (16, 8):
        return None
    return unary.operand


@dataclasses.dataclass(frozen=True, )
class IndexedAddressCopyStep8616:
    """One exact backward SSA edge from a definition to its source."""

    block_addr: cython.longlong
    instr_index: cython.longlong
    instr_addr: cython.longlong
    op: object
    kind: IndexedAddressCopyStepKind8616
    defined_value: IRValue
    source_expression: IRValue
    source_definition: IRValue
    constant: int | None = None

    @property
    def complete(self) -> cython.bint:
        """Return whether the operation proves its declared value relation."""
        source_operand: object
        source_operand = indexed_copy_source_operand_8616(self.source_expression)
        identity_matches = (
            source_operand is not None
            and operator.eq(scalar_definition_key_8616(source_operand), scalar_definition_key_8616(self.source_definition))
        )
        projection_widths_match = self.source_expression.active_unary is None or (
            operator.eq(self.defined_value.size, self.source_expression.size)
            and source_operand is not None
            and operator.eq(source_operand.size, self.source_definition.size)
        )
        common = bool(
            self.block_addr >= 0
            and self.instr_index >= 0
            and self.instr_addr >= 0
            and self.defined_value.space not in {MemSpace.CONST, MemSpace.UNKNOWN}
            and self.source_definition.space not in {MemSpace.CONST, MemSpace.UNKNOWN}
            and identity_matches
            and projection_widths_match
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
                and (self.source_expression.active_unary is not None
                     or self.source_expression.expr == ("Iop_16to8",))
            )
        else:
            relation = (
                self.op == "Iop_Shr16"
                and self.constant == 8
                and self.defined_value.size == self.source_definition.size == 2
            )
        return bool(common and relation)


@dataclasses.dataclass(frozen=True, )
class IndexedAddressCopyValuePath8616:
    """One destination byte lane traced backward to an exact source value."""

    store_instr_index: cython.longlong
    load_block_addr: cython.longlong
    load_instr_index: cython.longlong
    load_instr_addr: cython.longlong
    lane: IndexedAddressCopyLane8616
    store_value: IRValue
    load_value: IRValue
    steps: object
    logical_source: LogicalMemoryValueTrace8616 | None = None

    def _indices_ordered_8616(self) -> cython.bint:
        """Return whether the recorded store/load positions are sane."""
        return (
            self.store_instr_index >= 0
            and self.load_block_addr >= 0
            and self.load_instr_index >= 0
            and self.load_instr_addr >= 0
            and self.load_instr_index < self.store_instr_index
        )

    def _logical_source_proven_8616(self) -> cython.bint:
        """Return whether the optional logical source is complete."""
        source: object
        if self.logical_source is None:
            return True
        logical_loads = tuple(
            site
            for site in iter(self.logical_source.definition_path)
            if site.op == "LOAD"
        )
        source = self.logical_source.source
        return bool(
            self.logical_source.complete
            and source is not None
            and operator.eq(source.size, self.load_value.size)
            and len(logical_loads) == 2
        )

    @property
    def complete(self) -> cython.bint:
        """Return whether the path is contiguous and lane-preserving."""
        if not self._indices_ordered_8616():
            return False
        if not all(step.complete for step in iter(self.steps)):
            return False
        if not self._logical_source_proven_8616():
            return False
        if self.steps:
            if (
                operator.ne(scalar_definition_key_8616(self.store_value), scalar_definition_key_8616(self.steps[0].defined_value))
                or operator.ne(scalar_definition_key_8616(self.steps[-1].source_definition), scalar_definition_key_8616(self.load_value))
            ):
                return False
            if any(
                operator.ne(scalar_definition_key_8616(left.source_definition), scalar_definition_key_8616(right.defined_value))
                for left, right in builtins.iter(zip(self.steps, self.steps[1:], strict=False))
            ):
                return False
            indices = tuple(step.instr_index for step in iter(self.steps))
            if operator.ne(indices, tuple(sorted(indices, reverse=True))) or operator.ne(len(indices), len(set(indices))):
                return False
        elif operator.ne(scalar_definition_key_8616(self.store_value), scalar_definition_key_8616(
            self.load_value
        )):
            return False
        semantic_steps = tuple(
            step.kind
            for step in iter(self.steps)
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

    def matches_source(self, source: IndexedAddressFact8616) -> cython.bint:
        """Return whether this path proves one exact indexed LOAD owner."""
        logical_address: object
        if self.logical_source is None:
            return (
                self.load_block_addr,
                self.load_instr_index,
                self.load_instr_addr,
            ) == (source.block_addr, source.instr_index, source.instr_addr)
        logical_address = self.logical_source.source
        logical_loads = tuple(
            site for site in iter(self.logical_source.definition_path) if site.op == "LOAD"
        )
        if logical_address is None or len(logical_loads) != 2:
            return False
        low_load = logical_loads[0]
        return bool(
            (low_load.block_addr, low_load.instr_index, low_load.instr_addr)
            == (source.block_addr, source.instr_index, source.instr_addr)
            and logical_address.space is source.address.space
            and operator.eq(logical_address.base, source.address.base)
            and operator.eq(logical_address.offset, source.address.offset)
            and operator.eq(logical_address.size, source.address.size)
            and logical_address.status is source.address.status
            and logical_address.segment_origin is source.address.segment_origin
        )


@dataclasses.dataclass(frozen=True, )
class IndexedAddressCopyFact8616:
    """One indexed destination receiving an unchanged indexed source value."""

    source: IndexedAddressFact8616
    destination: IndexedAddressFact8616
    member_instr_indices: object
    value_paths: object

    @property
    def complete(self) -> cython.bint:
        """Return whether both endpoint and every byte-lane proof agree."""
        expected_lanes = (
            tuple((IndexedAddressCopyLane8616.DIRECT,))
            if len(self.member_instr_indices) == 1
            else tuple((
                IndexedAddressCopyLane8616.LOW_BYTE,
                IndexedAddressCopyLane8616.HIGH_BYTE,
            ))
        )
        return bool(
            self.source.complete
            and self.destination.complete
            and self.source.kind is IndexedAddressAccessKind8616.LOAD
            and self.destination.kind is IndexedAddressAccessKind8616.STORE
            and operator.eq(self.source.function_addr, self.destination.function_addr)
            and operator.eq(self.source.block_addr, self.destination.block_addr)
            and self.source.instr_index < self.destination.instr_index
            and self.source.address.size == self.destination.address.size > 0
            and len(self.member_instr_indices) in {1, 2}
            and operator.eq(self.member_instr_indices, tuple(path.store_instr_index for path in iter(self.value_paths)))
            and operator.eq(tuple(path.lane for path in iter(self.value_paths)), expected_lanes)
            and all(path.complete for path in iter(self.value_paths))
            and all(path.matches_source(self.source) for path in iter(self.value_paths))
            and all(
                operator.eq(scalar_definition_key_8616(path.load_value), scalar_definition_key_8616(self.value_paths[0].load_value))
                for path in iter(self.value_paths)
            )
            and all(
                operator.eq(path.logical_source, self.value_paths[0].logical_source)
                for path in iter(self.value_paths)
            )
        )


@dataclasses.dataclass(frozen=True, )
class IndexedAddressCopyRefusal8616:
    """One retained indexed STORE and its value-copy refusal reason."""

    destination: IndexedAddressFact8616
    failure: IndexedAddressCopyFailureKind8616
    detail: object

    @property
    def complete(self) -> cython.bint:
        """Return whether this refusal owns one exact STORE candidate."""
        return bool(
            self.destination.complete
            and self.destination.kind is IndexedAddressAccessKind8616.STORE
            and self.detail
        )


@dataclasses.dataclass(frozen=True, )
class IndexedAddressCopyStats8616:
    """Closed accounting for indexed STORE value-path classification."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0

    @property
    def closed(self) -> cython.bint:
        """Return whether every STORE became one copy or refusal."""
        return bool(
            operator.eq(self.raw_fact_count, self.materialized_count + self.failure_count)
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )


@dataclasses.dataclass(frozen=True, )
class IndexedAddressCopyEvidence8616:
    """Function-wide exact indexed copies with every STORE refusal retained."""

    function_addr: cython.longlong
    facts: object
    refusals: object
    stats: IndexedAddressCopyStats8616
    source: IndexedAddressEvidence8616

    @property
    def closed(self) -> cython.bint:
        """Return whether source STORE accounting closes without loss."""
        destinations = tuple(fact.destination for fact in iter(self.facts)) + tuple(
            refusal.destination for refusal in iter(self.refusals)
        )
        source_stores = tuple(
            fact
            for fact in iter(self.source.facts)
            if fact.kind is IndexedAddressAccessKind8616.STORE
        )
        return bool(
            self.source.closed
            and operator.eq(self.function_addr, self.source.function_addr)
            and operator.eq(self.stats.raw_fact_count, len(source_stores))
            and operator.eq(len(self.facts), self.stats.materialized_count)
            and operator.eq(len(self.refusals), self.stats.failure_count)
            and self.stats.closed
            and all(fact.complete for fact in iter(self.facts))
            and all(refusal.complete for refusal in iter(self.refusals))
            and operator.eq(len(destinations), len(source_stores))
            and all(destinations.count(source) == 1 for source in iter(source_stores))
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
