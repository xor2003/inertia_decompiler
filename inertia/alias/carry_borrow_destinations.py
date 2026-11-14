# cython: language_level=3, infer_types=True
"""Bind carry-linked register results to exact Alias-proven stack stores.

Layer: Alias.
Responsibility: prove direct function-SSA value flow from both result registers
to one adjacent pair of stack-memory Alias facts. This module does not join the
pair, infer a C type, mutate codegen, or inspect rendered C/assembly text.
Owns storage identity and exact definition-to-store carrier identity.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.core import IRAddress, IRInstr, IRValue, MemSpace
from inertia.ir.logical_memory_contracts import IRMemoryAccessKind8616
from inertia.ir.scalar_value_projection import (
    ScalarProjectionKind8616,
    scalar_active_unary_projection_8616,
    scalar_produced_decoration_8616,
    scalar_read_projection_8616,
)
from inertia.ir.ssa_function import SSAFunctionArtifact

from .carry_borrow_projection import (
    CarryBorrowAliasEvidence8616,
    CarryBorrowAliasFact8616,
)
from .domains import DomainKey, register_domain_for_name
from .logical_stack_memory_projection import LogicalStackMemoryAliasAccess8616
from .stack_memory_ssa_contracts import (
    StackMemorySSAAliasArtifact8616,
)
import dataclasses
import operator
import builtins


class CarryBorrowDestinationAliasVerdict8616(StrEnum):
    """Stable Alias outcome for one observed destination-store candidate."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class CarryBorrowDestinationAliasFailure8616(StrEnum):
    """Stable reason a result-store pair lacks exact Alias proof."""

    AMBIGUOUS_STORE = "ambiguous_store"
    CROSS_BLOCK_FLOW = "cross_block_flow"
    DESTINATION_ALIAS_MISMATCH = "destination_alias_mismatch"
    DESTINATION_RANGE_MISMATCH = "destination_range_mismatch"
    FUNCTION_IDENTITY_MISMATCH = "function_identity_mismatch"
    LOGICAL_ALIAS_REFUSED = "logical_alias_refused"
    MISSING_LOGICAL_STORE = "missing_logical_store"
    MISSING_RESULT_VALUE = "missing_result_value"
    PARTIAL_STORE = "partial_store"
    STACK_ALIAS_MISSING = "stack_alias_missing"
    STORE_ORDER_MISMATCH = "store_order_mismatch"
    VALUE_FLOW_MISMATCH = "value_flow_mismatch"


@dataclasses.dataclass(frozen=True, )
class CarryBorrowDestinationAliasFact8616:
    """Exact low/high result stores retaining source carry and stack Alias facts."""

    carry: CarryBorrowAliasFact8616
    low_store: LogicalStackMemoryAliasAccess8616
    high_store: LogicalStackMemoryAliasAccess8616


@dataclasses.dataclass(frozen=True, )
class CarryBorrowDestinationAliasResolution8616:
    """Proven destination pair or typed refusal for one observed store flow."""

    carry: CarryBorrowAliasFact8616
    verdict: CarryBorrowDestinationAliasVerdict8616
    fact: CarryBorrowDestinationAliasFact8616 | None = None
    failure: CarryBorrowDestinationAliasFailure8616 | None = None


@dataclasses.dataclass(frozen=True, )
class CarryBorrowDestinationAliasStats8616:
    """Closed accounting for observed destination-store candidates."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0

    @property
    def complete(self) -> cython.bint:
        """Return whether every observed candidate has one retained outcome."""
        return (
            operator.eq(self.raw_fact_count, self.normalized_fact_count)
            and operator.eq(self.raw_fact_count, self.materialized_count + self.failure_count)
            and operator.eq(self.classified_fact_count, self.materialized_count)
        )


@dataclasses.dataclass(frozen=True, )
class CarryBorrowDestinationAliasEvidence8616:
    """Function-level destination pairs and explicit refusals."""

    function_addr: cython.longlong
    resolutions: object
    stats: CarryBorrowDestinationAliasStats8616

    @property
    def facts(self) -> tuple[CarryBorrowDestinationAliasFact8616, ...]:
        """Return proven destination pairs in deterministic order."""
        return tuple(item.fact for item in iter(self.resolutions) if item.fact is not None)

    @property
    def complete(self) -> cython.bint:
        """Return whether result count and evidence accounting are closed."""
        return self.stats.complete and operator.eq(len(self.resolutions), self.stats.raw_fact_count)


@cython.ccall
def _captured_lane_read_matches_8616(value: IRValue, definition: IRInstr) -> cython.bint:
    """Require a width-preserving read of the exact retained producer."""
    destination: object
    projection: object
    destination = definition.dst
    if destination is None or destination.active_unary is not None:
        return False
    if operator.ne(value.size, destination.size) or operator.ne(definition.size, value.size):
        return False
    if value.offset != 0 or value.index is not None:
        return False
    projection = scalar_read_projection_8616(
        read_expr=value.expr, read_bits=value.size * 8,
        produced=scalar_produced_decoration_8616(definition), produced_bits=definition.size * 8,
    )
    return projection is not None and projection.kind is not ScalarProjectionKind8616.CONVERSION


def _value_reaches_result_lane(
    instructions: object,
    before_index: cython.longlong,
    value: IRValue,
    expected: IRValue,
    expected_domain: DomainKey,
    required_shift: cython.longlong,
    visited: object = frozenset(),
) -> cython.bint:
    """Trace one byte value to an exact register version and byte lane."""
    projection: object
    source_tmp: object
    step_value: object
    unary: object
    unary = value.active_unary
    if unary is not None:
        projection = scalar_active_unary_projection_8616(value)
        if projection is None or (projection.source_bits, projection.target_bits) != (16, 8):
            return False
        return _value_reaches_result_lane(
            instructions, before_index, unary.operand, expected,
            expected_domain, required_shift, visited,
        )
    plain_register = (
        value.source_tmp is None
        and operator.eq(value.size, expected.size)
        and value.offset == 0
        and value.index is None
        and value.expr in {None, ()}
    )
    if (
        plain_register and
        value.space is MemSpace.REG
        and operator.eq(register_domain_for_name(value.name), expected_domain)
        and operator.eq(value.version, expected.version)
    ):
        return required_shift == 0
    source_tmp = value.source_tmp
    if source_tmp is None or source_tmp in visited:
        return False
    definitions = tuple(
        (index, instruction)
        for index, instruction in builtins.iter(enumerate(instructions[:before_index]))
        if instruction.dst is not None and operator.eq(instruction.dst.source_tmp, source_tmp)
    )
    if len(definitions) != 1:
        return False
    definition_index, definition = definitions[0]
    if not _captured_lane_read_matches_8616(value, definition):
        return False
    next_visited = visited | {source_tmp}
    if definition.op == "MOV" and len(definition.args) == 1 and isinstance(definition.args[0], IRValue):
        return _value_reaches_result_lane(
            instructions,
            definition_index,
            definition.args[0],
            expected,
            expected_domain,
            required_shift,
            next_visited,
        )
    step_value = _shr8_step_value_8616(definition, required_shift)
    if step_value is not None:
        return _value_reaches_result_lane(
            instructions,
            definition_index,
            step_value,
            expected,
            expected_domain,
            required_shift - 8,
            next_visited,
        )
    return False


@cython.ccall
def _shr16_by_8_shape_8616(definition: IRInstr) -> cython.bint:
    """Return True when ``definition`` is exactly ``Shr16(x, 8)``."""
    return (
        definition.op == "Iop_Shr16"
        and len(definition.args) == 2
        and isinstance(definition.args[0], IRValue)
        and isinstance(definition.args[1], IRValue)
        and definition.args[1].const == 8
    )


@cython.ccall
def _shr8_step_value_8616(definition: IRInstr, required_shift: cython.longlong) -> IRValue | None:
    """Return the Shr16-by-8 source when the step consumes 8 bits."""
    if (
        not _shr16_by_8_shape_8616(definition)
        or required_shift < 8
        or not isinstance(definition.args[0], IRValue)
    ):
        return None
    return definition.args[0]


@cython.ccall
def _logical_store_value_paths(
    instructions: object,
    owner: LogicalStackMemoryAliasAccess8616,
    expected: IRValue,
    expected_domain: DomainKey,
) -> tuple[cython.bint, ...]:
    """Return exact low/high byte-path verdicts for one logical WRITE owner."""
    item: object
    paths: list[cython.bint] = []
    for item in owner.slices:
        index = item.raw_access.instr_index
        instruction = instructions[index]
        data = instruction.args[1] if instruction.op == "STORE" and len(instruction.args) == 2 else None
        paths.append(
            isinstance(data, IRValue)
            and _value_reaches_result_lane(
                instructions,
                index,
                data,
                expected,
                expected_domain,
                item.source.source_byte_offset * 8,
            )
        )
    return tuple(paths)


@cython.ccall
def _stores_for_result(
    function_ssa: SSAFunctionArtifact,
    stack_aliases: StackMemorySSAAliasArtifact8616,
    result: IRValue,
    domain: DomainKey,
) -> tuple[tuple[LogicalStackMemoryAliasAccess8616, ...], cython.bint]:
    """Return exact logical word stores plus whether a partial path exists."""
    block: object
    owner: object
    blocks = {block.addr: block for block in iter(function_ssa.blocks)}
    stores: list[LogicalStackMemoryAliasAccess8616] = []
    partial = False
    for owner in stack_aliases.logical_accesses:
        block = blocks.get(owner.block_addr)
        if (
            owner.source.kind is not IRMemoryAccessKind8616.WRITE
            or owner.address.size != 2
            or block is None
        ):
            continue
        paths = _logical_store_value_paths(block.instrs, owner, result, domain)
        if paths and all(paths):
            stores.append(owner)
        elif any(paths):
            partial = True
    return tuple(stores), partial


@cython.ccall
def _refusal(
    carry: CarryBorrowAliasFact8616,
    failure: CarryBorrowDestinationAliasFailure8616,
) -> CarryBorrowDestinationAliasResolution8616:
    return CarryBorrowDestinationAliasResolution8616(
        carry=carry,
        verdict=CarryBorrowDestinationAliasVerdict8616.UNKNOWN_REFUSE,
        failure=failure,
    )


@cython.ccall
def _adjacent_word_lanes_8616(low_address: IRAddress, high_address: IRAddress) -> cython.bint:
    """Return whether two addresses are adjacent word lanes of one object."""
    if (
        low_address.space is not high_address.space
        or operator.ne(low_address.base, high_address.base)
        or operator.ne(low_address.size, high_address.size)
        or low_address.size != 2
    ):
        return False
    return (
        operator.eq(high_address.offset, low_address.offset + low_address.size)
        and low_address.status is high_address.status
        and low_address.segment_origin is high_address.segment_origin
    )


def _resolve_destination(
    function_ssa: SSAFunctionArtifact,
    stack_aliases: StackMemorySSAAliasArtifact8616,
    carry: CarryBorrowAliasFact8616,
) -> CarryBorrowDestinationAliasResolution8616:
    high_result: object
    low_result: object
    link = carry.link
    low_result = link.low_result_write.instruction.dst
    high_result = link.high_result_write.instruction.dst
    if low_result is None or high_result is None:
        return _refusal(carry, CarryBorrowDestinationAliasFailure8616.MISSING_RESULT_VALUE)
    low_stores, low_partial = _stores_for_result(
        function_ssa, stack_aliases, low_result, carry.low_result_domain
    )
    high_stores, high_partial = _stores_for_result(
        function_ssa, stack_aliases, high_result, carry.high_result_domain
    )
    if not low_stores and not high_stores:
        failure = (
            CarryBorrowDestinationAliasFailure8616.VALUE_FLOW_MISMATCH
            if low_partial or high_partial
            else CarryBorrowDestinationAliasFailure8616.LOGICAL_ALIAS_REFUSED
            if stack_aliases.logical_refusals
            else CarryBorrowDestinationAliasFailure8616.MISSING_LOGICAL_STORE
        )
        return _refusal(carry, failure)
    if not low_stores or not high_stores:
        return _refusal(
            carry,
            CarryBorrowDestinationAliasFailure8616.VALUE_FLOW_MISMATCH
            if low_partial or high_partial
            else CarryBorrowDestinationAliasFailure8616.PARTIAL_STORE,
        )
    if len(low_stores) != 1 or len(high_stores) != 1:
        return _refusal(carry, CarryBorrowDestinationAliasFailure8616.AMBIGUOUS_STORE)
    low_store, high_store = low_stores[0], high_stores[0]
    if operator.ne(low_store.block_addr, high_store.block_addr) or operator.ne(low_store.block_addr, link.high_result_write.block_addr):
        return _refusal(carry, CarryBorrowDestinationAliasFailure8616.CROSS_BLOCK_FLOW)
    low_index = max(item.raw_access.instr_index for item in iter(low_store.slices))
    high_index = min(item.raw_access.instr_index for item in iter(high_store.slices))
    if (
        low_index <= link.high_result_write.instr_index
        or high_index <= low_index
    ):
        return _refusal(carry, CarryBorrowDestinationAliasFailure8616.STORE_ORDER_MISMATCH)
    low_address = low_store.address
    high_address = high_store.address
    if not _adjacent_word_lanes_8616(low_address, high_address):
        return _refusal(
            carry,
            CarryBorrowDestinationAliasFailure8616.DESTINATION_RANGE_MISMATCH,
        )
    if not low_store.storage.can_join(high_store.storage):
        return _refusal(carry, CarryBorrowDestinationAliasFailure8616.DESTINATION_ALIAS_MISMATCH)
    return CarryBorrowDestinationAliasResolution8616(
        carry=carry,
        verdict=CarryBorrowDestinationAliasVerdict8616.PROVEN,
        fact=CarryBorrowDestinationAliasFact8616(carry, low_store, high_store),
    )


def project_carry_borrow_destination_aliases_8616(
    function_ssa: SSAFunctionArtifact,
    carry_aliases: CarryBorrowAliasEvidence8616,
    stack_aliases: object,
) -> CarryBorrowDestinationAliasEvidence8616:
    """Project observed direct result stores onto exact stack Alias pairs."""
    if stack_aliases is None:
        resolutions = tuple(
            _refusal(fact, CarryBorrowDestinationAliasFailure8616.STACK_ALIAS_MISSING)
            for fact in iter(carry_aliases.facts)
        )
    elif (
        operator.ne(function_ssa.function_addr, carry_aliases.function_addr)
        or operator.ne(function_ssa.function_addr, stack_aliases.function_addr)
    ):
        resolutions = tuple(
            _refusal(fact, CarryBorrowDestinationAliasFailure8616.FUNCTION_IDENTITY_MISMATCH)
            for fact in iter(carry_aliases.facts)
        )
    else:
        resolutions = tuple(
            _resolve_destination(function_ssa, stack_aliases, fact)
            for fact in iter(carry_aliases.facts)
        )
    materialized = sum(item.fact is not None for item in iter(resolutions))
    return CarryBorrowDestinationAliasEvidence8616(
        function_addr=function_ssa.function_addr,
        resolutions=resolutions,
        stats=CarryBorrowDestinationAliasStats8616(
            raw_fact_count=len(resolutions),
            normalized_fact_count=len(resolutions),
            classified_fact_count=materialized,
            materialized_count=materialized,
            failure_count=len(resolutions) - materialized,
        ),
    )


__all__ = [
    "CarryBorrowDestinationAliasEvidence8616",
    "CarryBorrowDestinationAliasFact8616",
    "CarryBorrowDestinationAliasFailure8616",
    "CarryBorrowDestinationAliasResolution8616",
    "CarryBorrowDestinationAliasStats8616",
    "CarryBorrowDestinationAliasVerdict8616",
    "project_carry_borrow_destination_aliases_8616",
]
