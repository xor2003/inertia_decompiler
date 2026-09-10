"""Layer: Frontend/angr compatibility.

Responsibility: preserve numeric stack values and exact widths at angr's address propagation boundary.
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
    StackBaseOffset,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.manager import Manager
from angr.analyses.s_propagator import SPropagator
from angr.code_location import AILCodeLocation
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions

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
_StackOffsetToAddr = Callable[[LiveDefinitions, int], int]
_SPropAnalyze = Callable[[SPropagator], None]


class StackPointerPropagationVerdict8616(Enum):
    """Classify one typed stack-pointer replacement at the angr boundary."""

    NOT_APPLICABLE = "not_applicable"
    ALREADY_TYPED = "already_typed"
    MATERIALIZED_NARROWING = "materialized_narrowing"
    REFUSED_WIDENING = "refused_widening"


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


class _NamedSPropAnalyze(Protocol):
    """Name-only patch detection; invocation is typed separately by _SPropAnalyze."""

    __name__: str


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


def apply_x86_16_stack_compatibility() -> None:
    """Patch angr stack offsets and propagated SP/BP values to remain word-sized."""
    original_stack_offset_to_stack_addr = cast(_StackOffsetToAddr, LiveDefinitions.stack_offset_to_stack_addr)

    def _stack_offset_to_stack_addr_8616(self: LiveDefinitions, offset: int) -> int:
        """Wrap word-sized stack offsets and delegate other architectures unchanged."""
        if self.arch.bits == 16:
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
        """Publish proven replacements and remove width or numeric-use refusals."""
        original_sprop_analyze(self)
        model = cast(_SPropagatorModelLike, self.model)
        aggregate = StackPointerPropagationStats8616()
        if self.project.arch.name != "86_16":
            model._inertia_stack_pointer_propagation_stats_8616 = aggregate
            return

        sp_offset = self.project.arch.sp_offset
        bp_offset = self.project.arch.bp_offset
        if sp_offset is None or bp_offset is None:
            raise ValueError("86_16 stack propagation requires registered SP and BP offsets")
        stack_register_offsets = frozenset((sp_offset, bp_offset))
        blocks: dict[tuple[int, int | None], Block] = {}
        subject_block = self.block
        if self.func_graph is not None:
            blocks = {(block.addr, block.idx): block for block in self.func_graph if isinstance(block, Block)}
        elif isinstance(subject_block, Block):
            native_block = cast(Block, subject_block)
            blocks[(native_block.addr, native_block.idx)] = native_block
        for location, replacements_at_location in model.replacements.items():
            block = blocks.get((location.block_addr, location.block_idx))
            statement = (
                block.statements[location.stmt_idx]
                if block is not None and location.stmt_idx is not None
                and 0 <= location.stmt_idx < len(block.statements) else None
            )
            for replaced, replacement in tuple(replacements_at_location.items()):
                scalar = replacement
                while isinstance(scalar, Convert):
                    scalar = scalar.operand
                if isinstance(scalar, StackBaseOffset) and isinstance(replaced, VirtualVariable):
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
                    ail_manager=self._ail_manager,
                )
                aggregate = aggregate.merged(result.stats)
                if result.verdict is StackPointerPropagationVerdict8616.REFUSED_WIDENING:
                    del replacements_at_location[replaced]
                elif result.stats.materialized_count:
                    replacements_at_location[replaced] = result.replacement
        model._inertia_stack_pointer_propagation_stats_8616 = aggregate

    SPropagator._analyze = _analyze_8616
