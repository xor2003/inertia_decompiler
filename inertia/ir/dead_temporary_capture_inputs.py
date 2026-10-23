"""Select retained capture roots for block-local temporary normalization.

Layer: IR.
Responsibility: bind owned metadata payloads to exact producer blocks, refusing
unbounded or malformed capture evidence without interpreting TMP dependencies.
The normalization owner alone reads dependencies from these preserved payloads.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TypeGuard

from inertia.frontend.x86_16.relative_control_edge import DecodedRelativeEdge

from .condition_ir import (
    ConditionIR,
    ConditionRegisterBindingIR,
    ConditionRegisterUpdateIR,
    ConditionSource,
)
from .condition_lift_capture import ConditionLiftCaptureSession8616
from .core import IRAddress, IRBinaryValue, IRBlock, IRRefusal, IRValue
from .logical_memory_capture import IRLogicalMemoryCaptureRecord8616
from .logical_memory_contracts import IRMemoryAccessKind8616
from .vex_terminal_jump import (
    TerminalJumpEvidence8616,
    TerminalJumpEvidenceStats8616,
    TerminalJumpRefusalReason8616,
)


class DeadTemporaryCaptureStatus8616(StrEnum):
    """Whether all retained metadata can be assigned to exact producers."""

    COMPLETE = "complete"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class DeadTemporaryBlockCaptureInputs8616:
    """Payload roots and conservative refusal for one original block."""

    block_addr: int
    payloads: tuple[object, ...]
    status: DeadTemporaryCaptureStatus8616


@dataclass(frozen=True, slots=True)
class DeadTemporaryCaptureInputs8616:
    """Deterministic metadata selection; completeness is not deletion proof."""

    blocks: tuple[DeadTemporaryBlockCaptureInputs8616, ...]
    status: DeadTemporaryCaptureStatus8616


@dataclass(slots=True)
class _Selection:
    """Accumulate producer ownership without walking value dependencies."""

    payloads: dict[int, list[object]]
    instruction_owners: dict[int, set[int]]
    refused: set[int] = field(default_factory=set)
    unbounded: bool = False

    def owners(self, block_addr: object, insn_addr: object) -> set[int]:
        """Intersect supplied coordinates, refusing ambiguous or foreign sites."""
        explicit = {block_addr} if _valid_coordinate(block_addr) and block_addr in self.payloads else set()
        by_instruction = self.instruction_owners.get(insn_addr, set()) if _valid_coordinate(insn_addr) else set()
        if block_addr is not None:
            if not explicit:
                self.unbounded = True
                return set()
            if insn_addr is not None and explicit != by_instruction:
                self.refused.update(explicit | by_instruction)
                return set()
            return explicit
        if len(by_instruction) != 1:
            self.refuse(by_instruction)
            return set()
        return by_instruction

    def refuse(self, owners: set[int]) -> None:
        """Retain a bounded affected set, or the whole surface if unbounded."""
        if owners:
            self.refused.update(owners)
        else:
            self.unbounded = True

    def retain(self, owners: set[int], roots: tuple[object, ...], valid: bool) -> None:
        """Preserve root identity even when its containing metadata is refused."""
        for owner in sorted(owners):
            self.payloads[owner].extend(roots)
        if not valid:
            self.refuse(owners)


def _valid_coordinate(value: object) -> TypeGuard[int]:
    """Require exact nonnegative integer identity; Boolean aliases are invalid."""
    return type(value) is int and value >= 0


def _update_metadata_valid(update: ConditionRegisterUpdateIR) -> bool:
    """Validate owned update fields; only rhs carries value dependencies."""
    return (
        type(update.rhs) in (IRValue, IRBinaryValue)
        and _valid_coordinate(update.instruction_addr)
        and type(update.target_register) is str
        and type(update.op) is str
    )


def _binding_roots(bindings: object) -> tuple[tuple[object, ...], bool]:
    """Extract exact binding payloads without interpreting their values."""
    if type(bindings) is not tuple:
        return (), False
    roots: list[object] = []
    valid = True
    for binding in bindings:
        if type(binding) is not ConditionRegisterBindingIR:
            valid = False
            continue
        roots.append(binding.value)
        if type(binding.value) not in (IRValue, IRBinaryValue) or type(binding.register_name) is not str:
            valid = False
        if binding.update is not None:
            if type(binding.update) is ConditionRegisterUpdateIR:
                roots.append(binding.update.rhs)
                if not _update_metadata_valid(binding.update):
                    valid = False
            else:
                valid = False
    return tuple(roots), valid


def _condition_roots(condition: ConditionIR | ConditionSource) -> tuple[tuple[object, ...], bool]:
    """Expose retained operands and semantics exactly as captured."""
    bindings, valid = _binding_roots(condition.register_bindings)
    roots: tuple[object, ...]
    if isinstance(condition, ConditionIR):
        roots = (condition.lhs, condition.rhs, condition.producer_semantics)
        semantics = condition.producer_semantics
    else:
        roots = (
            condition.lhs, condition.rhs, condition.normalized_lhs,
            condition.normalized_rhs, condition.semantics,
        )
        semantics = condition.semantics
    return roots + bindings, valid and (semantics is None or type(semantics) is tuple)


def _terminal_metadata_valid(evidence: object) -> bool:
    """Validate the exact owned terminal contract, which carries no TMP roots."""
    if type(evidence) is not TerminalJumpEvidence8616:
        return False
    typed_evidence = evidence
    scalar_fields_valid = (
        type(typed_evidence.retain) is bool
        and (typed_evidence.proven_target is None or type(typed_evidence.proven_target) is int)
        and (typed_evidence.failure is None or type(typed_evidence.failure) is TerminalJumpRefusalReason8616)
    )
    if not scalar_fields_valid or type(typed_evidence.stats) is not TerminalJumpEvidenceStats8616:
        return False
    counts = (
        typed_evidence.stats.raw_fact_count, typed_evidence.stats.normalized_fact_count,
        typed_evidence.stats.classified_fact_count, typed_evidence.stats.materialized_count,
        typed_evidence.stats.failure_count,
    )
    if not all(type(count) is int and count >= 0 for count in counts):
        return False
    if type(typed_evidence.refusals) is not tuple:
        return False
    for refusal in typed_evidence.refusals:
        if type(refusal) is not IRRefusal:
            return False
        if type(refusal.kind) is not str or type(refusal.detail) is not str:
            return False
        if refusal.block_addr is not None and type(refusal.block_addr) is not int:
            return False
    if typed_evidence.decoded is None:
        return True
    return (
        type(typed_evidence.decoded) is DecodedRelativeEdge
        and (typed_evidence.decoded.source is None or type(typed_evidence.decoded.source) is str)
    )


def _select_cached_conditions(
    selection: _Selection, capture: ConditionLiftCaptureSession8616,
) -> None:
    """Assign complete cached condition roots by exact producer instruction."""
    for consumer, conditions in capture.condition_cache.items():
        if not _valid_coordinate(consumer):
            selection.refuse(set())
        if type(conditions) is not list:
            selection.refuse({consumer} if _valid_coordinate(consumer) and consumer in selection.payloads else set())
            continue
        for condition in conditions:
            if type(condition) is not ConditionIR:
                selection.refuse({consumer} if _valid_coordinate(consumer) and consumer in selection.payloads else set())
                continue
            producer = condition.producer_insn
            if producer is None:
                producer = condition.src_insn
            owners = selection.owners(None, producer)
            roots, valid = _condition_roots(condition)
            selection.retain(owners, roots, valid)


def _select_conditions(selection: _Selection, capture: ConditionLiftCaptureSession8616) -> None:
    """Use producer coordinates; cache and pending keys identify consumers."""
    if type(capture.condition_cache) is not dict or type(capture.pending_sources) is not dict:
        selection.refuse(set())
        return
    _select_cached_conditions(selection, capture)
    for successor, source in capture.pending_sources.items():
        if not _valid_coordinate(successor):
            selection.refuse(set())
        if type(source) is not ConditionSource:
            selection.refuse(set())
            continue
        owners = selection.owners(source.block_addr, source.addr)
        roots, valid = _condition_roots(source)
        selection.retain(owners, roots, valid)


def _select_accesses(
    selection: _Selection,
    captured_accesses: tuple[IRLogicalMemoryCaptureRecord8616, ...],
) -> None:
    """Preserve exact address roots and refuse incomplete logical accesses."""
    if type(captured_accesses) is not tuple:
        selection.refuse(set())
        return
    for access in captured_accesses:
        if type(access) is not IRLogicalMemoryCaptureRecord8616:
            selection.refuse(set())
            continue
        owners = selection.owners(access.block_addr, access.insn_addr)
        valid = (
            type(access.address) is IRAddress
            and type(access.kind) is IRMemoryAccessKind8616
            and access.kind is not IRMemoryAccessKind8616.UNKNOWN
            and _valid_coordinate(access.insn_addr)
            and _valid_coordinate(access.function_addr)
            and _valid_coordinate(access.access_ordinal)
            and type(access.address_bits) is int
            and access.address_bits in (16, 32)
        )
        selection.retain(owners, (access.address,), valid)


def _initialize_selection(blocks: tuple[IRBlock, ...]) -> _Selection:
    """Index exact instruction sites, refusing invalid owned coordinates."""
    selection = _Selection({}, {})
    for block in blocks:
        if not _valid_coordinate(block.addr):
            selection.unbounded = True
            continue
        if block.addr in selection.payloads:
            selection.unbounded = True
        selection.payloads[block.addr] = []
        for instruction in block.instrs:
            if instruction.addr is None:
                continue
            if not _valid_coordinate(instruction.addr):
                selection.refused.add(block.addr)
                continue
            selection.instruction_owners.setdefault(instruction.addr, set()).add(block.addr)
    return selection


def select_dead_temporary_capture_inputs_8616(
    blocks: tuple[IRBlock, ...],
    condition_capture: ConditionLiftCaptureSession8616,
    captured_accesses: tuple[IRLogicalMemoryCaptureRecord8616, ...],
    terminal_evidence: Mapping[int, TerminalJumpEvidence8616],
) -> DeadTemporaryCaptureInputs8616:
    """Select per-producer metadata roots, retaining every uncertain block.

    Callers must pass COMPLETE payloads to the normalizer's authoritative
    dependency reader and skip deletion for UNKNOWN_REFUSE blocks. The helper
    does not replace or mutate captures, blocks, terminal evidence, or operands.
    Foreign producers and missing bounds refuse the whole imported surface.
    """
    selection = _initialize_selection(blocks)
    if type(condition_capture) is ConditionLiftCaptureSession8616:
        _select_conditions(selection, condition_capture)
    else:
        selection.unbounded = True
    _select_accesses(selection, captured_accesses)
    for owner, evidence in terminal_evidence.items():
        owners = selection.owners(owner, None)
        if not _terminal_metadata_valid(evidence):
            selection.refuse(owners)
    if selection.unbounded:
        selection.refused.update(selection.payloads)
    selected = tuple(
        DeadTemporaryBlockCaptureInputs8616(
            block.addr,
            tuple(selection.payloads.get(block.addr, ())) if _valid_coordinate(block.addr) else (),
            DeadTemporaryCaptureStatus8616.UNKNOWN_REFUSE
            if selection.unbounded or block.addr in selection.refused
            else DeadTemporaryCaptureStatus8616.COMPLETE,
        )
        for block in blocks
    )
    status = (
        DeadTemporaryCaptureStatus8616.UNKNOWN_REFUSE
        if selection.unbounded or selection.refused else DeadTemporaryCaptureStatus8616.COMPLETE
    )
    return DeadTemporaryCaptureInputs8616(selected, status)
