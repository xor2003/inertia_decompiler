"""Classify exact paired callee-saved PUSH/POP instruction evidence.

Layer: Types/Lowering.
Responsibility: normalize decoded Capstone instruction facts into exact
callee-saved frame pairs consumed by structured stack-carrier lowering.
Forbidden: assembly-text matching, source/COD recovery, or cleanup guesses.
Consumes alias, widening, and typed facts from decoded instruction evidence.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterable, Set
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from capstone.x86_const import X86_INS_CALL, X86_INS_POP, X86_INS_PUSH, X86_INS_RET, X86_OP_REG


class _CapstoneOperand8616(Protocol):
    """Capstone operand fields consumed by frame-pair classification."""

    type: int
    reg: int


class _CapstoneInstruction8616(Protocol):
    """Capstone instruction fields consumed by frame-pair classification."""

    address: int
    id: int
    operands: tuple[_CapstoneOperand8616, ...]

    def reg_name(self, reg_id: int) -> str:
        """Return the architecture register name for one Capstone id."""
        ...


@dataclass(frozen=True, slots=True)
class CalleeSavedFramePair8616:
    """Pair one exact frame PUSH with its epilogue POP."""

    register_name: str
    push_addr: int
    pop_addr: int

    @property
    def instruction_addresses(self) -> frozenset[int]:
        """Return both machine instruction addresses in the pair."""
        return frozenset((self.push_addr, self.pop_addr))


class CalleeSavedFrameInstructionRole8616(Enum):
    """Machine instruction role for one pruned frame carrier."""

    PUSH = "push"
    POP = "pop"


class CalleeSavedFrameCarrierKind8616(Enum):
    """Observable storage class of one pruned frame carrier."""

    SEGMENTED_STACK_WRITE = "segmented_stack_write"
    STACK_SLOT_WRITE = "stack_slot_write"
    FRAME_BOOKKEEPING = "frame_bookkeeping"


class CalleeSavedFramePairSemantics8616(Enum):
    """Semantic role of an exact register PUSH/POP frame pair."""

    PRESERVED = "preserved"
    RESTORED_BEFORE_UPDATE = "restored_before_update"


@dataclass(frozen=True, slots=True)
class CalleeSavedFramePruneFact8616:
    """Describe one AST assignment pruned through an exact PUSH/POP pair."""

    function_addr: int
    register_name: str
    push_addr: int
    pop_addr: int
    instruction_addr: int
    carrier_ordinal: int
    instruction_role: CalleeSavedFrameInstructionRole8616
    carrier_kind: CalleeSavedFrameCarrierKind8616
    stack_displacement: int | None
    access_width: int | None
    pair_semantics: CalleeSavedFramePairSemantics8616 = (
        CalleeSavedFramePairSemantics8616.PRESERVED
    )


@dataclass(frozen=True, slots=True)
class CalleeSavedFramePruneRecord8616:
    """Closed evidence census for callee-saved frame-carrier pruning."""

    evidence: tuple[CalleeSavedFramePruneFact8616, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @classmethod
    def closed(
        cls,
        evidence: Iterable[CalleeSavedFramePruneFact8616],
    ) -> CalleeSavedFramePruneRecord8616:
        """Build a deterministic closed record from materialized prune facts."""
        unique = tuple(dict.fromkeys(evidence))
        count = len(unique)
        return cls(
            evidence=unique,
            raw_fact_count=count,
            normalized_fact_count=count,
            classified_fact_count=count,
            materialized_count=count,
            failure_count=0,
        )

    @property
    def closes_evidence(self) -> bool:
        """Return whether every classified fact was materialized without loss."""
        count = len(self.evidence)
        return bool(
            count > 0
            and self.raw_fact_count == count
            and self.normalized_fact_count == count
            and self.classified_fact_count == count
            and self.materialized_count == count
            and self.failure_count == 0
        )

    @property
    def segmented_stack_write_evidence(
        self,
    ) -> tuple[CalleeSavedFramePruneFact8616, ...]:
        """Return exact pruned carriers visible as segmented stack writes."""
        return tuple(
            fact
            for fact in self.evidence
            if fact.carrier_kind is CalleeSavedFrameCarrierKind8616.SEGMENTED_STACK_WRITE
        )

    @property
    def frame_stack_store_evidence(
        self,
    ) -> tuple[CalleeSavedFramePruneFact8616, ...]:
        """Return one preferred store fact for each exact frame PUSH pair."""
        stores: dict[tuple[int, int, int, str], CalleeSavedFramePruneFact8616] = {}
        for fact in self.evidence:
            if fact.carrier_kind not in {
                CalleeSavedFrameCarrierKind8616.SEGMENTED_STACK_WRITE,
                CalleeSavedFrameCarrierKind8616.STACK_SLOT_WRITE,
            }:
                continue
            key = (
                fact.function_addr,
                fact.push_addr,
                fact.pop_addr,
                fact.register_name,
            )
            previous = stores.get(key)
            if (
                previous is None
                or fact.carrier_kind
                is CalleeSavedFrameCarrierKind8616.SEGMENTED_STACK_WRITE
            ):
                stores[key] = fact
        return tuple(stores.values())


def _decoded_register_name_8616(instruction: object, instruction_id: int) -> str | None:
    """Return one decoded register operand at the Capstone boundary."""
    instruction_surface = cast(_CapstoneInstruction8616, instruction)
    try:
        if instruction_surface.id != instruction_id:
            return None
        operand = instruction_surface.operands[0]
        if operand.type != X86_OP_REG:
            return None
        register_name = instruction_surface.reg_name(operand.reg)
    except (AttributeError, IndexError, TypeError):
        return None
    return register_name.lower() if isinstance(register_name, str) else None


def callee_saved_frame_pairs_8616(
    instructions: Iterable[object],
    saved_registers: Set[str],
) -> tuple[CalleeSavedFramePair8616, ...]:
    """Return sequential register-save pairs not owned by a following call.

    A register PUSH immediately followed by CALL is typed call-argument
    evidence.  Its eventual POP is caller cleanup and must not be consumed as
    a callee-saved frame restoration merely because the register is otherwise
    eligible for preservation.
    """
    normalized_saved = frozenset(name.lower() for name in saved_registers)
    pending_pushes: dict[str, int] = {}
    pairs: list[CalleeSavedFramePair8616] = []
    seen_addresses: set[tuple[int, int]] = set()
    decoded_instructions = tuple(instructions)
    for instruction_index, instruction in enumerate(decoded_instructions):
        instruction_surface = cast(_CapstoneInstruction8616, instruction)
        try:
            address = instruction_surface.address
            instruction_id = instruction_surface.id
        except AttributeError:
            continue
        if not isinstance(address, int) or not isinstance(instruction_id, int):
            continue
        key = (address, instruction_id)
        if key in seen_addresses:
            continue
        seen_addresses.add(key)
        _track_saved_push_8616(
            instruction_index,
            instruction_surface,
            address,
            decoded_instructions,
            normalized_saved,
            pending_pushes,
        )
        _match_saved_pop_8616(
            instruction_surface,
            address,
            normalized_saved,
            pending_pushes,
            pairs,
        )
        if instruction_id == X86_INS_RET:
            break
    return tuple(sorted(pairs, key=lambda pair: (pair.push_addr, pair.pop_addr, pair.register_name)))


def _track_saved_push_8616(
    instruction_index: int,
    instruction_surface: _CapstoneInstruction8616,
    address: int,
    decoded_instructions: tuple[object, ...],
    normalized_saved: frozenset[str],
    pending_pushes: dict[str, int],
) -> None:
    """Record one saved-register PUSH not immediately consumed by a CALL."""
    register_name = _decoded_register_name_8616(instruction_surface, X86_INS_PUSH)
    if register_name is None or register_name not in normalized_saved:
        return
    next_instruction_id = None
    if instruction_index + 1 < len(decoded_instructions):
        with contextlib.suppress(AttributeError):
            next_instruction_id = cast(
                _CapstoneInstruction8616,
                decoded_instructions[instruction_index + 1],
            ).id
    if next_instruction_id != X86_INS_CALL:
        pending_pushes.setdefault(register_name, address)


def _match_saved_pop_8616(
    instruction_surface: _CapstoneInstruction8616,
    address: int,
    normalized_saved: frozenset[str],
    pending_pushes: dict[str, int],
    pairs: list[CalleeSavedFramePair8616],
) -> None:
    """Pair one saved-register POP with its pending PUSH."""
    register_name = _decoded_register_name_8616(instruction_surface, X86_INS_POP)
    if register_name is None or register_name not in normalized_saved:
        return
    push_addr = pending_pushes.pop(register_name, None)
    if push_addr is not None:
        pairs.append(
            CalleeSavedFramePair8616(
                register_name=register_name,
                push_addr=push_addr,
                pop_addr=address,
            )
        )


__all__ = [
    "CalleeSavedFrameCarrierKind8616",
    "CalleeSavedFrameInstructionRole8616",
    "CalleeSavedFramePair8616",
    "CalleeSavedFramePairSemantics8616",
    "CalleeSavedFramePruneFact8616",
    "CalleeSavedFramePruneRecord8616",
    "callee_saved_frame_pairs_8616",
]
