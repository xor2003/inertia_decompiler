"""Layer: Frontend/angr compatibility.

Responsibility: preserve numeric stack values, instruction ordering, and exact
widths at angr's address propagation boundary. A pre-instruction SP/BP fact
cannot replace an SSA value defined later within that same instruction.
Forbidden: stack variable recovery, alias ownership, or rewrite-stage stack repair.
"""

from __future__ import annotations

from collections.abc import Callable, MutableMapping
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.ailment.block import Block
from angr.ailment.expression import (
    Convert,
    Expression,
    Phi,
    StackBaseOffset,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment, Statement
from angr.analyses.s_propagator import SPropagator
from angr.code_location import AILCodeLocation
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions

from .load_propagation import LoadPropagationStats8616, refuse_reordered_loads_8616
from .stack_tracker_allocation import apply_x86_16_stack_tracker_allocations_8616
from .stack_value_use import StackValueUse8616, classify_stack_value_use_8616

__all__ = [
    "StackPointerPropagationNormalization8616",
    "StackPointerPropagationStats8616",
    "StackPointerPropagationVerdict8616",
    "StackValueUse8616",
    "apply_x86_16_stack_compatibility",
    "classify_stack_value_use_8616",
    "normalize_stack_pointer_replacement_8616",
]

_PATCHED_STACK_OFFSET_TO_ADDR_NAME = "_stack_offset_to_stack_addr_8616"
_PATCHED_SPROP_ANALYZE_NAME = "_analyze_8616"
_WORD_BITS8616 = 16
_StackOffsetToAddr = Callable[[LiveDefinitions, int], int]
_SPropAnalyze = Callable[[SPropagator], None]


class StackPointerPropagationVerdict8616(Enum):
    """Classify one typed stack-pointer replacement at the angr boundary."""

    NOT_APPLICABLE = "not_applicable"
    ALREADY_TYPED = "already_typed"
    MATERIALIZED_NARROWING = "materialized_narrowing"
    REFUSED_WIDENING = "refused_widening"
    MATERIALIZED_UPDATED_VALUE = "materialized_updated_value"
    REFUSED_INSTRUCTION_ORDER = "refused_instruction_order"


@dataclass(frozen=True, slots=True)
class StackPointerPropagationStats8616:
    """Record the closed evidence loop for stack-pointer replacement widths."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    def merged(self, other: StackPointerPropagationStats8616) -> StackPointerPropagationStats8616:
        """Return the component-wise sum of two normalization reports."""
        return StackPointerPropagationStats8616(
            raw_fact_count=self.raw_fact_count + other.raw_fact_count,
            normalized_fact_count=self.normalized_fact_count + other.normalized_fact_count,
            classified_fact_count=self.classified_fact_count + other.classified_fact_count,
            materialized_count=self.materialized_count + other.materialized_count,
            failure_count=self.failure_count + other.failure_count,
        )


@dataclass(frozen=True, slots=True)
class StackPointerPropagationNormalization8616:
    """Carry one normalized AIL replacement and its evidence counters."""

    replacement: Expression
    verdict: StackPointerPropagationVerdict8616
    stats: StackPointerPropagationStats8616


class _NamedStackOffsetToAddr(Protocol):
    """Expose the patch marker independently of the callable signature."""

    __name__: str


class _SPropagatorModelLike(Protocol):
    """Describe angr replacements and the Inertia metadata published beside them."""

    replacements: MutableMapping[AILCodeLocation, MutableMapping[Expression, Expression]]
    _inertia_stack_pointer_propagation_stats_8616: StackPointerPropagationStats8616
    _inertia_load_propagation_stats_8616: LoadPropagationStats8616


class _NamedSPropAnalyze(Protocol):
    """Name-only patch detection; invocation is typed separately by _SPropAnalyze."""

    __name__: str


class _StackTracker8616(Protocol):
    """Instruction-boundary facts exposed by the native stack tracker."""

    def offset_after(self, addr: int, reg: int) -> int | None:
        """Return a proven final register offset, or unknown."""
        ...


def normalize_stack_pointer_use_order_8616(
    replaced: VirtualVariable,
    replacement: Expression,
    *,
    block: Block | None,
    location: AILCodeLocation,
    tracker: _StackTracker8616 | None,
) -> StackPointerPropagationNormalization8616:
    """Use final instruction facts only for its last dominating machine write."""
    unchanged = StackPointerPropagationNormalization8616(
        replacement, StackPointerPropagationVerdict8616.NOT_APPLICABLE,
        StackPointerPropagationStats8616(),
    )
    if block is None or location.ins_addr is None:
        return unchanged
    # A block-entry Phi carries the first instruction's address but selects
    # predecessor values; it does not execute that instruction's register write.
    writes = [
        (index, statement.dst)
        for index, statement in enumerate(block.statements)
        if isinstance(statement, Assignment)
        and not isinstance(statement.src, Phi)
        and isinstance(statement.dst, VirtualVariable)
        and statement.dst.category is VirtualVariableCategory.REGISTER
        and statement.dst.oident == replaced.oident
        and statement.tags.get("ins_addr") == location.ins_addr
    ]
    definition = next((index for index, value in writes if value.varid == replaced.varid), None)
    if definition is None:
        return unchanged
    final_dominating_write = (
        location.stmt_idx is not None and definition < location.stmt_idx
        and writes[-1][1].varid == replaced.varid
    )
    offset = (
        tracker.offset_after(location.ins_addr, replaced.oident)
        if final_dominating_write and tracker is not None and isinstance(replaced.oident, int)
        else None
    )
    if offset is None:
        return StackPointerPropagationNormalization8616(
            replacement, StackPointerPropagationVerdict8616.REFUSED_INSTRUCTION_ORDER,
            StackPointerPropagationStats8616(raw_fact_count=1, normalized_fact_count=1, failure_count=1),
        )
    return StackPointerPropagationNormalization8616(
        StackBaseOffset(replacement.idx, replacement.bits, offset, **replacement.tags),
        StackPointerPropagationVerdict8616.MATERIALIZED_UPDATED_VALUE,
        StackPointerPropagationStats8616(
            raw_fact_count=1, normalized_fact_count=1, classified_fact_count=1, materialized_count=1,
        ),
    )


def normalize_stack_pointer_replacement_8616(
    replaced: Expression,
    replacement: Expression,
    *,
    stack_register_offsets: frozenset[int],
    ail_manager: Manager,
) -> StackPointerPropagationNormalization8616:
    """Keep a propagated x86-16 SP/BP value at its exact register width."""
    if not (
        isinstance(replaced, VirtualVariable)
        and replaced.category is VirtualVariableCategory.REGISTER
        and isinstance(replaced.oident, int)
        and replaced.oident in stack_register_offsets
        and isinstance(replacement, StackBaseOffset)
    ):
        return StackPointerPropagationNormalization8616(
            replacement,
            StackPointerPropagationVerdict8616.NOT_APPLICABLE,
            StackPointerPropagationStats8616(),
        )

    source_bits = replacement.bits
    target_bits = replaced.bits
    if source_bits == target_bits:
        return StackPointerPropagationNormalization8616(
            replacement,
            StackPointerPropagationVerdict8616.ALREADY_TYPED,
            StackPointerPropagationStats8616(raw_fact_count=1, normalized_fact_count=1),
        )
    if source_bits < target_bits:
        return StackPointerPropagationNormalization8616(
            replacement,
            StackPointerPropagationVerdict8616.REFUSED_WIDENING,
            StackPointerPropagationStats8616(
                raw_fact_count=1,
                normalized_fact_count=1,
                failure_count=1,
            ),
        )

    converted = Convert(
        ail_manager.next_atom(),
        source_bits,
        target_bits,
        False,
        replacement,
        **replacement.tags,
    )
    return StackPointerPropagationNormalization8616(
        converted,
        StackPointerPropagationVerdict8616.MATERIALIZED_NARROWING,
        StackPointerPropagationStats8616(
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
        ),
    )


def _native_stack_blocks_8616(analysis: SPropagator) -> dict[tuple[int, int | None], Block]:
    """Index the native subject without assuming whole-function propagation."""
    if analysis.func_graph is not None:
        return {(block.addr, block.idx): block for block in analysis.func_graph if isinstance(block, Block)}
    block = analysis.block
    return {(block.addr, block.idx): block} if isinstance(block, Block) else {}


def _normalize_native_stack_model_8616(analysis: SPropagator) -> None:
    """Apply instruction-order, numeric-use, and width contracts to native facts."""
    model = cast(_SPropagatorModelLike, analysis.model)
    aggregate = StackPointerPropagationStats8616()
    sp_offset = analysis.project.arch.sp_offset
    bp_offset = analysis.project.arch.bp_offset
    if sp_offset is None or bp_offset is None:
        raise ValueError("86_16 stack propagation requires registered SP and BP offsets")
    stack_register_offsets = frozenset((sp_offset, bp_offset))
    blocks = _native_stack_blocks_8616(analysis)
    model._inertia_load_propagation_stats_8616 = refuse_reordered_loads_8616(blocks, model.replacements)
    for location, replacements_at_location in model.replacements.items():
        block = blocks.get((location.block_addr, location.block_idx))
        statement = _native_statement_at_8616(block, location)
        for replaced, replacement in tuple(replacements_at_location.items()):
            scalar = replacement
            while isinstance(scalar, Convert):
                scalar = scalar.operand
            if isinstance(scalar, StackBaseOffset) and isinstance(replaced, VirtualVariable):
                ordering = normalize_stack_pointer_use_order_8616(
                    replaced, replacement, block=block, location=location,
                    tracker=cast(_StackTracker8616 | None, analysis._sp_tracker),
                )
                aggregate = aggregate.merged(ordering.stats)
                if ordering.verdict is StackPointerPropagationVerdict8616.REFUSED_INSTRUCTION_ORDER:
                    del replacements_at_location[replaced]
                    continue
                replacement = ordering.replacement
                replacements_at_location[replaced] = replacement
                use = classify_stack_value_use_8616(statement, replaced.varid)
                if use is not StackValueUse8616.ADDRESS_ONLY:
                    del replacements_at_location[replaced]
                    aggregate = aggregate.merged(StackPointerPropagationStats8616(
                        raw_fact_count=1, normalized_fact_count=1, failure_count=1,
                    ))
                    continue
            result = normalize_stack_pointer_replacement_8616(
                replaced,
                replacement,
                stack_register_offsets=stack_register_offsets,
                ail_manager=analysis._ail_manager,
            )
            aggregate = aggregate.merged(result.stats)
            if result.verdict is StackPointerPropagationVerdict8616.REFUSED_WIDENING:
                del replacements_at_location[replaced]
            elif result.stats.materialized_count:
                replacements_at_location[replaced] = result.replacement
    model._inertia_stack_pointer_propagation_stats_8616 = aggregate


def _native_statement_at_8616(block: Block | None, location: AILCodeLocation) -> Statement | None:
    """Resolve an exact use statement, refusing absent or stale locations."""
    if block is None or location.stmt_idx is None or not 0 <= location.stmt_idx < len(block.statements):
        return None
    return cast(Statement, block.statements[location.stmt_idx])


def apply_x86_16_stack_compatibility() -> None:
    """Patch angr stack offsets and propagated SP/BP values to remain word-sized."""
    apply_x86_16_stack_tracker_allocations_8616()
    original_stack_offset_to_stack_addr = cast(_StackOffsetToAddr, LiveDefinitions.stack_offset_to_stack_addr)

    def _stack_offset_to_stack_addr_8616(self: LiveDefinitions, offset: int) -> int:
        """Wrap word-sized stack offsets and delegate other architectures unchanged."""
        if self.arch.bits == _WORD_BITS8616:
            return (0x7FFE + offset) & 0xFFFF
        return original_stack_offset_to_stack_addr(self, offset)

    current_stack_offset_to_stack_addr = cast(_NamedStackOffsetToAddr, LiveDefinitions.stack_offset_to_stack_addr)
    if current_stack_offset_to_stack_addr.__name__ != _PATCHED_STACK_OFFSET_TO_ADDR_NAME:
        LiveDefinitions.stack_offset_to_stack_addr = _stack_offset_to_stack_addr_8616

    current_sprop_analyze = cast(_NamedSPropAnalyze, SPropagator._analyze)
    if current_sprop_analyze.__name__ == _PATCHED_SPROP_ANALYZE_NAME:
        return
    original_sprop_analyze = cast(_SPropAnalyze, SPropagator._analyze)

    def _analyze_8616(self: SPropagator) -> None:
        """Normalize completed native propagation without changing other engines."""
        original_sprop_analyze(self)
        if self.project.arch.name == "86_16":
            _normalize_native_stack_model_8616(self)
        else:
            model = cast(_SPropagatorModelLike, self.model)
            model._inertia_stack_pointer_propagation_stats_8616 = StackPointerPropagationStats8616()

    SPropagator._analyze = _analyze_8616
