"""Prove logical wide stack arguments from typed word-operation facts.

Layer: Widening.
Responsibility: join adjacent BP word operands only when carry-linked arithmetic
or register-linked high-word comparison proves one logical parameter.
Consumes alias-proven storage identity and typed frontend instruction facts.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from enum import Enum

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


@dataclass(frozen=True, slots=True)
class StackWordArithmeticFact8616:
    """Typed frontend fact for one instruction operating on a BP word."""

    mnemonic: str
    destination_register: int | None
    source_bp_offset: int | None
    compared_register: int | None = None
    destination_role: StackWordRegisterRole8616 = StackWordRegisterRole8616.OTHER


@dataclass(frozen=True, slots=True)
class WideStackArgumentWidthEvidence8616:
    """Closed evidence census for proven logical wide stack arguments."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_offsets: tuple[int, ...]
    materialized_count: int = 0
    failure_count: int = 0
    terminal_return_offsets: tuple[int, ...] = ()

    @property
    def classified_fact_count(self) -> int:
        """Return the number of distinct proven wide argument offsets."""
        return len(self.classified_offsets)

    @property
    def closes_classification(self) -> bool:
        """Return whether every observed wide-value fact was classified."""
        return (
            self.raw_fact_count > 0
            and self.raw_fact_count == self.normalized_fact_count
            and self.classified_fact_count > 0
            and self.failure_count == 0
        )

    def with_materialized_count(self, count: int) -> WideStackArgumentWidthEvidence8616:
        """Return this evidence with its lowering materialization count."""
        return replace(self, materialized_count=count)


def project_logical_stack_argument_widths_8616(
    physical_push_widths: tuple[int, ...],
    wide_stack_offsets: tuple[int, ...],
) -> tuple[int, ...] | None:
    """Join physical pushes into source-order arguments at proven BP offsets.

    Physical widths arrive in execution push order. After reversing them, each
    slot maps contiguously from ``BP+4``. A Widening-owned four-byte offset may
    consume either one four-byte push or two adjacent word pushes. Any gap,
    overlap, unsupported width, or unconsumed proof is refused.
    """
    if not physical_push_widths or any(width not in {2, 4} for width in physical_push_widths):
        return None
    proven_offsets = tuple(sorted(set(wide_stack_offsets)))
    if (
        len(proven_offsets) != len(wide_stack_offsets)
        or any(offset < 4 or offset % 2 for offset in proven_offsets)
        or any(right < left + 4 for left, right in itertools.pairwise(proven_offsets))
    ):
        return None

    source_widths = tuple(reversed(physical_push_widths))
    logical_widths: list[int] = []
    consumed_offsets: set[int] = set()
    source_index = 0
    stack_offset = 4
    while source_index < len(source_widths):
        if stack_offset not in proven_offsets:
            width = source_widths[source_index]
            if any(stack_offset < wide_offset < stack_offset + width for wide_offset in proven_offsets):
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

    if consumed_offsets != set(proven_offsets):
        return None
    return tuple(logical_widths)


@dataclass
class _WidthEvidenceTally8616:
    """Accumulate the closed evidence counters for wide-argument widths."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    failure_count: int = 0
    classified_offsets: set[int] = field(default_factory=set)
    terminal_return_offsets: set[int] = field(default_factory=set)


def _mov_return_pairs_8616(
    instructions: tuple[StackWordArithmeticFact8616, ...],
    tally: _WidthEvidenceTally8616,
) -> None:
    """Census adjacent mov pairs returning AX:DX from adjacent BP words."""
    for index, (low, high) in enumerate(itertools.pairwise(instructions)):
        if (
            low.mnemonic.lower() != "mov"
            or high.mnemonic.lower() != "mov"
            or low.destination_role is not StackWordRegisterRole8616.AX_LOW_RETURN
            or high.destination_role is not StackWordRegisterRole8616.DX_HIGH_RETURN
        ):
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
            for fact in instructions[index + 2 :]
        )
        if high.source_bp_offset != low.source_bp_offset + 2 or later_return_write:
            tally.failure_count += 1
            continue
        tally.classified_offsets.add(low.source_bp_offset)
        tally.terminal_return_offsets.add(low.source_bp_offset)


def _carry_pairs_8616(
    instructions: tuple[StackWordArithmeticFact8616, ...],
    tally: _WidthEvidenceTally8616,
    carry_mnemonic: dict[str, str],
) -> None:
    """Census carry-linked arithmetic pairs and their seeding mov pair."""
    for index, (low, high) in enumerate(itertools.pairwise(instructions)):
        if carry_mnemonic.get(low.mnemonic.lower()) != high.mnemonic.lower():
            continue
        tally.raw_fact_count += 1
        if low.source_bp_offset is None or high.source_bp_offset is None:
            tally.failure_count += 1
            continue
        tally.normalized_fact_count += 1
        if (
            high.source_bp_offset != low.source_bp_offset + 2
            or low.destination_register is None
            or high.destination_register is None
            or low.destination_register == high.destination_register
        ):
            tally.failure_count += 1
            continue
        tally.classified_offsets.add(low.source_bp_offset)
        if index < 2:
            continue
        seed_low, seed_high = instructions[index - 2 : index]
        if seed_low.mnemonic.lower() != "mov" or seed_high.mnemonic.lower() != "mov":
            continue
        tally.raw_fact_count += 1
        if seed_low.source_bp_offset is None or seed_high.source_bp_offset is None:
            tally.failure_count += 1
            continue
        tally.normalized_fact_count += 1
        if (
            seed_high.source_bp_offset != seed_low.source_bp_offset + 2
            or seed_low.destination_register != low.destination_register
            or seed_high.destination_register != high.destination_register
        ):
            tally.failure_count += 1
            continue
        tally.classified_offsets.add(seed_low.source_bp_offset)


def _seeded_high_compare_8616(
    seed_low: StackWordArithmeticFact8616,
    seed_high: StackWordArithmeticFact8616,
    high_compare: StackWordArithmeticFact8616,
    compared_low_offset: int,
) -> bool:
    """Prove a mov pair seeds a high-word compare on the adjacent word."""
    assert seed_low.source_bp_offset is not None
    return not (
        seed_high.source_bp_offset != seed_low.source_bp_offset + 2
        or compared_low_offset < 4
        or seed_low.destination_register is None
        or seed_high.destination_register is None
        or seed_low.destination_register == seed_high.destination_register
        or high_compare.compared_register != seed_high.destination_register
    )


def _cmp_seed_triples_8616(
    instructions: tuple[StackWordArithmeticFact8616, ...],
    tally: _WidthEvidenceTally8616,
) -> None:
    """Census mov/mov/cmp triples proving a wide logical argument."""
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


def analyze_wide_stack_argument_widths_8616(
    instruction_groups: Iterable[Iterable[StackWordArithmeticFact8616]],
) -> WideStackArgumentWidthEvidence8616:
    """Classify adjacent BP words joined by carry or high-word comparison."""
    tally = _WidthEvidenceTally8616()
    carry_mnemonic = {"add": "adc", "sub": "sbb"}
    for instruction_group in instruction_groups:
        instructions = tuple(instruction_group)
        _mov_return_pairs_8616(instructions, tally)
        _carry_pairs_8616(instructions, tally, carry_mnemonic)
        _cmp_seed_triples_8616(instructions, tally)
    return WideStackArgumentWidthEvidence8616(
        raw_fact_count=tally.raw_fact_count,
        normalized_fact_count=tally.normalized_fact_count,
        classified_offsets=tuple(sorted(tally.classified_offsets)),
        failure_count=tally.failure_count,
        terminal_return_offsets=tuple(sorted(tally.terminal_return_offsets)),
    )
