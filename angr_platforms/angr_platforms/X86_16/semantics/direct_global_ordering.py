"""Recover signedness facts from direct global ordering branches.

Layer: Semantics.
Responsibility: classify exact DS word comparisons followed by signed or
unsigned conditional branches. This module emits typed condition facts only;
Types/Lowering must join them to an independently proven wide object.
Do not infer signedness from names, sidecars, assembly text, or rendered C.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from capstone.x86_const import (
    X86_INS_CMP,
    X86_INS_JA,
    X86_INS_JAE,
    X86_INS_JB,
    X86_INS_JBE,
    X86_INS_JG,
    X86_INS_JGE,
    X86_INS_JL,
    X86_INS_JLE,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_REG_DS,
)

from .direct_call_result_storage import (
    DirectCallResultInstructionView8616,
    DirectCallResultOperandView8616,
)


class DirectGlobalOrdering8616(Enum):
    """Ordering interpretation proven by one conditional branch."""

    SIGNED = "signed"
    UNSIGNED = "unsigned"


@dataclass(frozen=True, slots=True)
class DirectGlobalOrderingFact8616:
    """One exact DS word comparison and its branch ordering semantics."""

    offset: int
    width: int
    ordering: DirectGlobalOrdering8616
    compare_ins_addr: int
    branch_ins_addr: int


_SIGNED_BRANCH_IDS_8616 = frozenset({X86_INS_JG, X86_INS_JGE, X86_INS_JL, X86_INS_JLE})
_UNSIGNED_BRANCH_IDS_8616 = frozenset({X86_INS_JA, X86_INS_JAE, X86_INS_JB, X86_INS_JBE})


def _direct_ds_word_compare_offset_8616(
    instruction: DirectCallResultInstructionView8616,
) -> int | None:
    """Return the DS offset for an exact direct word-to-immediate comparison."""
    if instruction.instruction_id != X86_INS_CMP or len(instruction.operands) < 2:
        return None
    memory_operand, constant_operand = instruction.operands[:2]
    memory = memory_operand.memory
    if not _direct_ds_word_memory_8616(memory_operand) or memory is None:
        return None
    assert isinstance(memory.displacement, int)
    if (
        constant_operand.kind != X86_OP_IMM
        or not isinstance(constant_operand.immediate, int)
    ):
        return None
    return memory.displacement & 0xFFFF


def _direct_ds_word_memory_8616(operand: DirectCallResultOperandView8616) -> bool:
    """Return whether one operand is a direct DS word memory reference."""
    memory = operand.memory
    return (
        operand.kind == X86_OP_MEM
        and operand.size == 2
        and memory is not None
        and memory.segment in {None, 0, X86_REG_DS}
        and memory.base in {None, 0}
        and memory.index in {None, 0}
        and isinstance(memory.displacement, int)
    )


def _branch_ordering_8616(instruction_id: int | None) -> DirectGlobalOrdering8616 | None:
    """Return the ordering family encoded by one conditional branch ID."""
    if instruction_id in _SIGNED_BRANCH_IDS_8616:
        return DirectGlobalOrdering8616.SIGNED
    if instruction_id in _UNSIGNED_BRANCH_IDS_8616:
        return DirectGlobalOrdering8616.UNSIGNED
    return None


def recover_direct_global_ordering_facts_8616(
    instructions: Iterable[DirectCallResultInstructionView8616],
) -> tuple[DirectGlobalOrderingFact8616, ...]:
    """Classify adjacent direct DS word CMP and ordering-JCC instructions."""
    ordered = tuple(instructions)
    facts: list[DirectGlobalOrderingFact8616] = []
    for compare, branch in itertools.pairwise(ordered):
        offset = _direct_ds_word_compare_offset_8616(compare)
        ordering = _branch_ordering_8616(branch.instruction_id)
        if (
            offset is None
            or ordering is None
            or not isinstance(compare.address, int)
            or not isinstance(branch.address, int)
            or compare.address >= branch.address
        ):
            continue
        facts.append(
            DirectGlobalOrderingFact8616(
                offset=offset,
                width=2,
                ordering=ordering,
                compare_ins_addr=compare.address,
                branch_ins_addr=branch.address,
            )
        )
    return tuple(dict.fromkeys(facts))


__all__ = [
    "DirectGlobalOrdering8616",
    "DirectGlobalOrderingFact8616",
    "recover_direct_global_ordering_facts_8616",
]
