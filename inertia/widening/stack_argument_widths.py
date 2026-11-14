# cython: language_level=3, infer_types=True
"""Prove logical wide stack arguments from typed word-operation facts.

Layer: Widening.
Responsibility: join adjacent BP word operands only when carry-linked arithmetic
or register-linked high-word comparison proves one logical parameter.
Consumes alias-proven storage identity and typed frontend instruction facts.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations
import typing
import cython

import itertools
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from enum import Enum
import dataclasses
import operator
import builtins

__all__ = [
    "StackWordArithmeticFact8616",
    "StackWordRegisterRole8616",
    "WideStackArgumentWidthEvidence8616",
    "analyze_wide_stack_argument_widths_8616",
    "project_logical_stack_argument_widths_8616",
]


class StackWordRegisterRole8616(Enum):
    """Semantic ABI role of one instruction destination register."""

    OTHER = "other"
    AX_LOW_RETURN = "ax_low_return"
    DX_HIGH_RETURN = "dx_high_return"


@dataclasses.dataclass(frozen=True, )
class StackWordArithmeticFact8616:
    """Typed frontend fact for one instruction operating on a BP word."""

    mnemonic: object
    destination_register: int | None
    source_bp_offset: int | None
    compared_register: int | None = None
    destination_role: StackWordRegisterRole8616 = StackWordRegisterRole8616.OTHER


@dataclasses.dataclass(frozen=True, )
class WideStackArgumentWidthEvidence8616:
    """Closed evidence census for proven logical wide stack arguments."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_offsets: object
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0
    terminal_return_offsets: tuple[cython.longlong, ...] = ()

    @property
    def classified_fact_count(self) -> cython.longlong:
        """Return the number of distinct proven wide argument offsets."""
        return len(self.classified_offsets)

    @property
    def closes_classification(self) -> cython.bint:
        """Return whether every observed wide-value fact was classified."""
        return (
            self.raw_fact_count > 0
            and operator.eq(self.raw_fact_count, self.normalized_fact_count)
            and self.classified_fact_count > 0
            and self.failure_count == 0
        )

    def with_materialized_count(self, count: cython.longlong) -> WideStackArgumentWidthEvidence8616:
        """Return this evidence with its lowering materialization count."""
        return replace(self, materialized_count=count)


def project_logical_stack_argument_widths_8616(
    physical_push_widths: object,
    wide_stack_offsets: object,
) -> object:
    """Join physical pushes into source-order arguments at proven BP offsets.

    Physical widths arrive in execution push order. After reversing them, each
    slot maps contiguously from ``BP+4``. A Widening-owned four-byte offset may
    consume either one four-byte push or two adjacent word pushes. Any gap,
    overlap, unsupported width, or unconsumed proof is refused.
    """
    if not physical_push_widths or any(width not in {2, 4} for width in iter(physical_push_widths)):
        return None
    proven_offsets = tuple(sorted(tuple(set(wide_stack_offsets))))
    if (
        operator.ne(len(proven_offsets), len(wide_stack_offsets))
        or any(offset < 4 or offset % 2 for offset in iter(proven_offsets))
        or any(right < left + 4 for left, right in builtins.iter(itertools.pairwise(proven_offsets)))
    ):
        return None

    source_widths = tuple(reversed(physical_push_widths))
    logical_widths: list[cython.longlong] = []
    consumed_offsets: set[cython.longlong] = set()
    source_index = 0
    stack_offset = 4
    while source_index < len(source_widths):
        if stack_offset not in proven_offsets:
            width = source_widths[source_index]
            if any(stack_offset < wide_offset < stack_offset + width for wide_offset in iter(proven_offsets)):
                return None
            logical_widths.append(width)
            source_index += 1
            stack_offset += width
            continue

        grouped_width = 0
        while source_index < len(source_widths) and grouped_width < 4:
            grouped_width += source_widths[source_index]
            source_index += 1
        if grouped_width != 4:
            return None
        logical_widths.append(4)
        consumed_offsets.add(stack_offset)
        stack_offset += 4

    if operator.ne(consumed_offsets, set(proven_offsets)):
        return None
    return tuple(logical_widths)


@cython.dataclasses.dataclass
class _WidthEvidenceTally8616:
    """Accumulate the closed evidence counters for wide-argument widths."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    failure_count: cython.longlong = 0
    classified_offsets: object = field(default_factory=set)
    terminal_return_offsets: object = field(default_factory=set)


def _mov_return_pairs_8616(
    instructions: object,
    tally: _WidthEvidenceTally8616,
    carry_mnemonic: object,
) -> None:
    """Census adjacent mov pairs returning AX:DX from adjacent BP words."""
    high: object
    index: object
    low: object
    for index, (low, high) in enumerate(itertools.pairwise(instructions)):
        if (
            low.mnemonic.lower() != "mov"
            or high.mnemonic.lower() != "mov"
            or low.destination_role is not StackWordRegisterRole8616.AX_LOW_RETURN
            or high.destination_role is not StackWordRegisterRole8616.DX_HIGH_RETURN
        ):
            continue
        # A complete four-instruction carry chain owns these movs as its seed,
        # not as a failed terminal AX:DX passthrough return.
        if _exact_carry_seed_at_8616(instructions, index, carry_mnemonic):
            continue
        tally.raw_fact_count += 1
        if low.source_bp_offset is None or high.source_bp_offset is None:
            tally.failure_count += 1
            continue
        tally.normalized_fact_count += 1
        later_return_write = any(
            fact.destination_role
            in {
                StackWordRegisterRole8616.AX_LOW_RETURN,
                StackWordRegisterRole8616.DX_HIGH_RETURN,
            }
            for fact in iter(instructions[index + 2 :])
        )
        if operator.ne(high.source_bp_offset, low.source_bp_offset + 2) or later_return_write:
            tally.failure_count += 1
            continue
        tally.classified_offsets.add(low.source_bp_offset)
        tally.terminal_return_offsets.add(low.source_bp_offset)


@cython.ccall
def _exact_carry_seed_at_8616(
    instructions: object,
    index: cython.longlong,
    carry_mnemonic: object,
) -> cython.bint:
    """Identify only a fully matched mov/mov/add/adc or mov/mov/sub/sbb seed."""
    if index + 4 > len(instructions):
        return False
    seed_low, seed_high, low, high = tuple(instructions[index : index + 4])
    if (
        seed_low.mnemonic.lower() != "mov"
        or seed_high.mnemonic.lower() != "mov"
        or operator.ne(carry_mnemonic.get(low.mnemonic.lower()), high.mnemonic.lower())
    ):
        return False
    if (
        seed_low.source_bp_offset is None
        or operator.ne(seed_high.source_bp_offset, seed_low.source_bp_offset + 2)
        or low.source_bp_offset is None
        or operator.ne(high.source_bp_offset, low.source_bp_offset + 2)
    ):
        return False
    return (
        low.destination_register is not None
        and high.destination_register is not None
        and operator.ne(low.destination_register, high.destination_register)
        and operator.eq(seed_low.destination_register, low.destination_register)
        and operator.eq(seed_high.destination_register, high.destination_register)
    )


@cython.ccall
def _carry_pairs_8616(
    instructions: object,
    tally: _WidthEvidenceTally8616,
    carry_mnemonic: object,
) -> None:
    """Census carry-linked arithmetic pairs and their seeding mov pair."""
    high: object
    index: object
    low: object
    for index, (low, high) in enumerate(itertools.pairwise(instructions)):
        if operator.ne(carry_mnemonic.get(low.mnemonic.lower()), high.mnemonic.lower()):
            continue
        tally.raw_fact_count += 1
        if low.source_bp_offset is None or high.source_bp_offset is None:
            tally.failure_count += 1
            continue
        tally.normalized_fact_count += 1
        if (
            operator.ne(high.source_bp_offset, low.source_bp_offset + 2)
            or low.destination_register is None
            or high.destination_register is None
            or operator.eq(low.destination_register, high.destination_register)
        ):
            tally.failure_count += 1
            continue
        tally.classified_offsets.add(low.source_bp_offset)
        if index < 2:
            continue
        seed_low, seed_high = tuple(instructions[index - 2 : index])
        if seed_low.mnemonic.lower() != "mov" or seed_high.mnemonic.lower() != "mov":
            continue
        tally.raw_fact_count += 1
        if seed_low.source_bp_offset is None or seed_high.source_bp_offset is None:
            tally.failure_count += 1
            continue
        tally.normalized_fact_count += 1
        if (
            operator.ne(seed_high.source_bp_offset, seed_low.source_bp_offset + 2)
            or operator.ne(seed_low.destination_register, low.destination_register)
            or operator.ne(seed_high.destination_register, high.destination_register)
        ):
            tally.failure_count += 1
            continue
        tally.classified_offsets.add(seed_low.source_bp_offset)


@cython.ccall
def _seeded_high_compare_8616(
    seed_low: StackWordArithmeticFact8616,
    seed_high: StackWordArithmeticFact8616,
    high_compare: StackWordArithmeticFact8616,
    compared_low_offset: cython.longlong,
) -> cython.bint:
    """Prove a mov pair seeds a high-word compare on the adjacent word."""
    assert seed_low.source_bp_offset is not None
    return not (
        operator.ne(seed_high.source_bp_offset, seed_low.source_bp_offset + 2)
        or compared_low_offset < 4
        or seed_low.destination_register is None
        or seed_high.destination_register is None
        or operator.eq(seed_low.destination_register, seed_high.destination_register)
        or operator.ne(high_compare.compared_register, seed_high.destination_register)
    )


@cython.ccall
def _cmp_seed_triples_8616(
    instructions: object,
    tally: _WidthEvidenceTally8616,
) -> None:
    """Census mov/mov/cmp triples proving a wide logical argument."""
    high_compare: object
    seed_high: object
    seed_low: object
    for seed_low, seed_high, high_compare in zip(
        instructions,
        instructions[1:],
        instructions[2:], strict=False,
    ):
        if (
            seed_low.mnemonic.lower() != "mov"
            or seed_high.mnemonic.lower() != "mov"
            or high_compare.mnemonic.lower() != "cmp"
        ):
            continue
        tally.raw_fact_count += 1
        if (
            seed_low.source_bp_offset is None
            or seed_high.source_bp_offset is None
            or high_compare.source_bp_offset is None
        ):
            tally.failure_count += 1
            continue
        tally.normalized_fact_count += 1
        compared_low_offset = high_compare.source_bp_offset - 2
        if not _seeded_high_compare_8616(
            seed_low, seed_high, high_compare, compared_low_offset,
        ):
            tally.failure_count += 1
            continue
        tally.classified_offsets.add(seed_low.source_bp_offset)
        tally.classified_offsets.add(compared_low_offset)


@cython.ccall
def analyze_wide_stack_argument_widths_8616(
    instruction_groups: Iterable[Iterable[StackWordArithmeticFact8616]],
) -> WideStackArgumentWidthEvidence8616:
    """Classify adjacent BP words joined by carry or high-word comparison."""
    instruction_group: object
    tally = _WidthEvidenceTally8616()
    carry_mnemonic = {"add": "adc", "sub": "sbb"}
    for instruction_group in instruction_groups:
        instructions = tuple(instruction_group)
        _mov_return_pairs_8616(instructions, tally, carry_mnemonic)
        _carry_pairs_8616(instructions, tally, carry_mnemonic)
        _cmp_seed_triples_8616(instructions, tally)
    return WideStackArgumentWidthEvidence8616(
        raw_fact_count=tally.raw_fact_count,
        normalized_fact_count=tally.normalized_fact_count,
        classified_offsets=tuple(sorted(tally.classified_offsets)),
        failure_count=tally.failure_count,
        terminal_return_offsets=tuple(sorted(tally.terminal_return_offsets)),
    )
