"""Recover aggregate stack objects from binary frame-layout evidence.

Layer: Types/Lowering.
Responsibility: classify and materialize aggregate BP-local objects only when a
binary-proven stack allocation plus address-taking, or repeated element-scaled
indexed accesses, and any required non-overlapping scalar boundary establish one
frame partition.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Forbidden: source/COD type recovery, rendered-C matching, or name-based object
joins.
Postprocess may replay the exported bounded consumer after CFunction or AST
rebuilding. Orchestration must replay it immediately before declaration
rendering, but it must not infer aggregate facts, boundaries, or array types.
Dynamic boundary: reads Capstone instructions and angr codegen/type objects whose
plugin-defined compatibility fields are not available through owned protocols.
"""

from __future__ import annotations

import contextlib
import logging
import os
import typing
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import (
    SimType,
    SimTypeArray,
    SimTypeChar,
    SimTypeFixedSizeArray,
    SimTypeLong,
    SimTypeShort,
)
from angr.sim_variable import SimStackVariable, SimVariable
from capstone.x86_const import (
    X86_INS_CALL,
    X86_INS_LCALL,
    X86_INS_LEA,
    X86_INS_MOV,
    X86_INS_PUSH,
    X86_INS_SAL,
    X86_INS_SHL,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
)

from ..c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616
from ..compiler_helpers import (
    identify_x86_16_compiler_helper_at_8616,
    is_x86_16_registered_stack_probe_target_8616,
    is_x86_16_stack_probe_evidence_kind_8616,
)
from .call_output_stack_object_replay import (
    reapply_call_output_stack_object_types_8616,
)
from .stack_aggregate_projection import (
    rebind_stack_aggregate_views_8616,
    restore_live_stack_aggregate_declaration_8616,
    select_stack_aggregate_projection_8616,
)
from .stack_frame_projection import entry_sp_offset_for_machine_bp_range_8616
from .stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
)

__all__ = [
    "StackAggregateCallDecay8616",
    "StackAggregateCarrierPrune8616",
    "StackAggregateEvidenceKind8616",
    "StackAggregateObjectFact8616",
    "StackAggregateObjectReplay8616",
    "StackAggregateRecovery8616",
    "StackAggregateRecoveryStatus8616",
    "collect_stack_aggregate_object_facts_8616",
    "decay_stack_aggregate_call_arguments_8616",
    "materialize_stack_aggregate_objects_8616",
    "prune_nonmemory_stack_aggregate_carriers_8616",
    "reapply_stack_aggregate_object_facts_8616",
    "recover_stack_aggregate_object_facts_from_instructions_8616",
    "stack_aggregate_object_facts_8616",
]


class StackAggregateRecoveryStatus8616(StrEnum):
    """Terminal classification for one stack-aggregate recovery attempt."""

    MATERIALIZABLE = "materializable"
    REFUSED = "refused"
    NO_EVIDENCE = "no_evidence"


class StackAggregateEvidenceKind8616(StrEnum):
    """Binary proof shape establishing one aggregate frame extent."""

    INDEXED_PARTITION = "indexed_partition"
    FULL_FRAME_ADDRESS = "full_frame_address"
    ADDRESSED_PARTITION = "addressed_partition"


@dataclass(frozen=True, slots=True)
class StackAggregateObjectFact8616:
    """Proof that one BP-local byte range is one aggregate object."""

    base_offset: int
    byte_size: int
    element_width: int
    frame_allocation_size: int
    address_taken_count: int
    indexed_access_count: int
    indexed_offsets: tuple[int, ...]
    scalar_boundary_offset: int | None
    scalar_boundary_width: int | None
    evidence_kind: StackAggregateEvidenceKind8616 = (
        StackAggregateEvidenceKind8616.INDEXED_PARTITION
    )


class _StackAggregateFactCarrier8616(Protocol):
    """Third-party codegen field retaining owned stack-aggregate facts."""

    _inertia_stack_aggregate_object_facts_8616: tuple[
        StackAggregateObjectFact8616, ...
    ]


class _VariableManagerTypeBoundary8616(Protocol):
    """Type-assignment surface exposed by angr's function variable manager."""

    def set_variable_type(
        self,
        variable: SimVariable,
        type_: SimType,
        *,
        override_bot: bool = True,
        all_unified: bool = False,
    ) -> None:
        """Assign a recovered type to one variable storage identity."""
        ...


class _AggregateCFunctionBoundary8616(Protocol):
    """CFunction fields needed to persist a proven aggregate declaration."""

    variable_manager: _VariableManagerTypeBoundary8616


def stack_aggregate_object_facts_8616(
    codegen: object,
) -> tuple[StackAggregateObjectFact8616, ...]:
    """Read typed stack-aggregate facts from the dynamic codegen boundary."""
    carrier = typing.cast(_StackAggregateFactCarrier8616, codegen)
    try:
        facts = carrier._inertia_stack_aggregate_object_facts_8616
    except AttributeError:
        return ()
    if not isinstance(facts, tuple) or not all(
        isinstance(fact, StackAggregateObjectFact8616) for fact in facts
    ):
        raise TypeError(
            "_inertia_stack_aggregate_object_facts_8616 must be a tuple "
            "of StackAggregateObjectFact8616"
        )
    return facts


@dataclass(frozen=True, slots=True)
class StackAggregateRecovery8616:
    """Closed evidence loop for aggregate stack-object recovery."""

    status: StackAggregateRecoveryStatus8616
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    facts: tuple[StackAggregateObjectFact8616, ...] = ()
    refusals: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class StackAggregateCarrierPrune8616:
    """Closed evidence loop for outgoing-stack artifacts aliased to an aggregate."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class StackAggregateCallDecay8616:
    """Closed evidence loop for typed stack-array call-argument decay."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class StackAggregateObjectReplay8616:
    """Closed evidence loop for replaying proven aggregate frame objects."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


class _InstructionLike8616(Protocol):
    """Capstone instruction fields consumed at the dynamic decode boundary."""

    id: int
    operands: tuple[object, ...]

    def reg_name(self, reg_id: int) -> str:
        """Return the architecture register name for an operand id."""
        ...


def _instruction(wrapper: object) -> object:
    """Unwrap an angr CapstoneInsn wrapper when present."""
    return getattr(wrapper, "insn", wrapper)


def _reg_name(insn: object, reg_id: object) -> str | None:
    """Return a normalized register name across the Capstone boundary."""
    if not isinstance(reg_id, int):
        return None
    reg_name = getattr(insn, "reg_name", None)
    if not callable(reg_name):
        return None
    with contextlib.suppress(Exception):
        value = reg_name(reg_id)
        if isinstance(value, str) and value:
            return value.lower()
    return None


def _direct_call_target(insn: object) -> int | None:
    """Return the immediate target of one direct call instruction."""
    if getattr(insn, "id", None) != X86_INS_CALL:
        return None
    operands = tuple(getattr(insn, "operands", ()) or ())
    if len(operands) != 1 or getattr(operands[0], "type", None) != X86_OP_IMM:
        return None
    target = getattr(operands[0], "imm", None)
    return target if isinstance(target, int) else None


def _stack_probe_allocation_before_call(insns: tuple[object, ...], call_index: int) -> int | None:
    """Recover a bounded ``mov ax, imm`` allocation input before a probe call."""
    for index in range(call_index - 1, max(-1, call_index - 5), -1):
        insn = _instruction(insns[index])
        operands = tuple(getattr(insn, "operands", ()) or ())
        if getattr(insn, "id", None) == X86_INS_MOV and len(operands) == 2:
            if getattr(operands[0], "type", None) != X86_OP_REG:
                continue
            if _reg_name(insn, getattr(operands[0], "reg", None)) != "ax":
                continue
            if getattr(operands[1], "type", None) != X86_OP_IMM:
                return None
            value = getattr(operands[1], "imm", None)
            return value if isinstance(value, int) and 0 < value <= 0x7FFF else None
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        if mnemonic.startswith(("j", "ret", "call")):
            return None
    return None


def _bp_memory_access(insn: object, operand: object) -> tuple[int, int, str | None] | None:
    """Return ``(displacement, width, index-name)`` for one BP memory operand."""
    if getattr(operand, "type", None) != X86_OP_MEM:
        return None
    memory = getattr(operand, "mem", None)
    if _reg_name(insn, getattr(memory, "base", None)) != "bp":
        return None
    displacement = getattr(memory, "disp", None)
    width = getattr(operand, "size", None)
    if not isinstance(displacement, int) or not isinstance(width, int) or width <= 0:
        return None
    index_name = _reg_name(insn, getattr(memory, "index", None))
    return displacement, width, index_name


def _index_scale_matches_width_8616(
    insns: tuple[object, ...],
    access_index: int,
    index_name: str,
    width: int,
) -> bool:
    """Prove an indexed access uses byte offsets scaled to its element width."""
    expected_shift = {1: 0, 2: 1, 4: 2}.get(width)
    if expected_shift is None:
        return False
    if expected_shift == 0:
        return True
    if access_index <= 0:
        return False
    previous = _instruction(insns[access_index - 1])
    if getattr(previous, "id", None) not in {X86_INS_SAL, X86_INS_SHL}:
        return False
    operands = tuple(getattr(previous, "operands", ()) or ())
    if len(operands) != 2:
        return False
    if getattr(operands[0], "type", None) != X86_OP_REG:
        return False
    if _reg_name(previous, getattr(operands[0], "reg", None)) != index_name:
        return False
    if getattr(operands[1], "type", None) != X86_OP_IMM:
        return False
    return getattr(operands[1], "imm", None) == expected_shift


def _recover_interior_scaled_aggregate_8616(
    *,
    frame_size: int,
    fixed_accesses: tuple[tuple[int, int], ...],
    indexed_accesses: tuple[tuple[int, int], ...],
    scaled_indexed_accesses: tuple[tuple[int, int], ...],
    raw_count: int,
) -> StackAggregateRecovery8616:
    """Recover one interior array from repeated scaled accesses and its next scalar."""
    indexed_counts: dict[tuple[int, int], int] = {}
    for access in scaled_indexed_accesses:
        indexed_counts[access] = indexed_counts.get(access, 0) + 1

    candidates: list[StackAggregateObjectFact8616] = []
    for (base_offset, element_width), indexed_count in sorted(indexed_counts.items()):
        if indexed_count < 2 or element_width not in {2, 4}:
            continue
        candidate = _interior_scaled_candidate_8616(
            base_offset=base_offset,
            element_width=element_width,
            frame_size=frame_size,
            fixed_accesses=fixed_accesses,
            indexed_accesses=indexed_accesses,
        )
        if candidate is not None:
            candidates.append(candidate)
    if len(candidates) == 1:
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.MATERIALIZABLE,
            raw_count,
            raw_count,
            1,
            0,
            0,
            facts=(candidates[0],),
        )
    if len(candidates) > 1:
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.REFUSED,
            raw_count,
            raw_count,
            0,
            0,
            1,
            refusals=("ambiguous_interior_scaled_aggregate",),
        )
    return StackAggregateRecovery8616(
        StackAggregateRecoveryStatus8616.NO_EVIDENCE,
        raw_count,
        raw_count,
        0,
        0,
        0,
        refusals=("missing_address_or_scaled_index_evidence",),
    )


def _recover_bottom_addressed_partition_8616(
    *,
    frame_size: int,
    fixed_accesses: tuple[tuple[int, int], ...],
    address_taken: tuple[tuple[int, int], ...],
    raw_count: int,
) -> StackAggregateRecovery8616:
    """Recover a bottom byte object separated from one repeated top scalar."""
    base_offset = -frame_size
    base_address_count = sum(
        displacement == base_offset for displacement, _width in address_taken
    )
    if base_address_count < 2:
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.NO_EVIDENCE,
            raw_count,
            raw_count,
            0,
            0,
            0,
            refusals=("insufficient_base_address_evidence",),
        )
    if base_address_count != len(address_taken):
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.REFUSED,
            raw_count,
            raw_count,
            0,
            0,
            1,
            refusals=("conflicting_addressed_frame_offsets",),
        )

    unique_fixed_accesses = set(fixed_accesses)
    if len(unique_fixed_accesses) != 1:
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.REFUSED,
            raw_count,
            raw_count,
            0,
            0,
            1,
            refusals=("addressed_partition_boundary_ambiguous",),
        )
    boundary_offset, boundary_width = next(iter(unique_fixed_accesses))
    boundary_access_count = fixed_accesses.count((boundary_offset, boundary_width))
    if boundary_access_count < 2:
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.NO_EVIDENCE,
            raw_count,
            raw_count,
            0,
            0,
            0,
            refusals=("scalar_boundary_not_repeated",),
        )
    if (
        boundary_width not in {2, 4}
        or boundary_offset <= base_offset
        or boundary_offset + boundary_width != 0
    ):
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.REFUSED,
            raw_count,
            raw_count,
            0,
            0,
            1,
            refusals=("addressed_partition_boundary_invalid",),
        )

    byte_size = boundary_offset - base_offset
    if byte_size < 2:
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.REFUSED,
            raw_count,
            raw_count,
            0,
            0,
            1,
            refusals=("addressed_partition_extent_invalid",),
        )
    fact = StackAggregateObjectFact8616(
        base_offset=base_offset,
        byte_size=byte_size,
        element_width=1,
        frame_allocation_size=frame_size,
        address_taken_count=base_address_count,
        indexed_access_count=0,
        indexed_offsets=(),
        scalar_boundary_offset=boundary_offset,
        scalar_boundary_width=boundary_width,
        evidence_kind=StackAggregateEvidenceKind8616.ADDRESSED_PARTITION,
    )
    return StackAggregateRecovery8616(
        StackAggregateRecoveryStatus8616.MATERIALIZABLE,
        raw_count,
        raw_count,
        1,
        0,
        0,
        facts=(fact,),
    )


def _recover_top_addressed_partition_8616(
    *,
    frame_size: int,
    fixed_accesses: tuple[tuple[int, int], ...],
    indexed_accesses: tuple[tuple[int, int], ...],
    address_taken: tuple[tuple[int, int], ...],
    raw_count: int,
) -> StackAggregateRecovery8616:
    """Recover a top byte object separated from one exact bottom scalar."""
    if len(address_taken) < 2:
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.NO_EVIDENCE,
            raw_count,
            raw_count,
            0,
            0,
            0,
            refusals=("insufficient_top_object_address_evidence",),
        )
    addressed_offsets = {displacement for displacement, _width in address_taken}
    if len(addressed_offsets) != 1:
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.REFUSED,
            raw_count,
            raw_count,
            0,
            0,
            1,
            refusals=("conflicting_top_object_address_offsets",),
        )

    frame_base = -frame_size
    aggregate_base = next(iter(addressed_offsets))
    if not frame_base < aggregate_base < 0:
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.NO_EVIDENCE,
            raw_count,
            raw_count,
            0,
            0,
            0,
            refusals=("addressed_object_not_above_frame_base",),
        )

    scalar_width = aggregate_base - frame_base
    expected_scalar_access = (frame_base, scalar_width)
    if not fixed_accesses:
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.NO_EVIDENCE,
            raw_count,
            raw_count,
            0,
            0,
            0,
            refusals=("missing_bottom_scalar_boundary_evidence",),
        )
    if scalar_width not in {2, 4} or set(fixed_accesses) != {expected_scalar_access}:
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.REFUSED,
            raw_count,
            raw_count,
            0,
            0,
            1,
            refusals=("top_addressed_partition_fixed_access_conflict",),
        )

    expected_indexed_access = (aggregate_base, 1)
    if not indexed_accesses:
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.NO_EVIDENCE,
            raw_count,
            raw_count,
            0,
            0,
            0,
            refusals=("missing_top_object_indexed_evidence",),
        )
    if set(indexed_accesses) != {expected_indexed_access}:
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.REFUSED,
            raw_count,
            raw_count,
            0,
            0,
            1,
            refusals=("top_addressed_partition_indexed_access_conflict",),
        )

    byte_size = -aggregate_base
    if byte_size < 2:
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.REFUSED,
            raw_count,
            raw_count,
            0,
            0,
            1,
            refusals=("top_addressed_partition_extent_invalid",),
        )
    fact = StackAggregateObjectFact8616(
        base_offset=aggregate_base,
        byte_size=byte_size,
        element_width=1,
        frame_allocation_size=frame_size,
        address_taken_count=len(address_taken),
        indexed_access_count=len(indexed_accesses),
        indexed_offsets=(aggregate_base,),
        scalar_boundary_offset=frame_base,
        scalar_boundary_width=scalar_width,
        evidence_kind=StackAggregateEvidenceKind8616.ADDRESSED_PARTITION,
    )
    return StackAggregateRecovery8616(
        StackAggregateRecoveryStatus8616.MATERIALIZABLE,
        raw_count,
        raw_count,
        1,
        0,
        0,
        facts=(fact,),
    )


def _interior_scaled_candidate_8616(
    *,
    base_offset: int,
    element_width: int,
    frame_size: int,
    fixed_accesses: tuple[tuple[int, int], ...],
    indexed_accesses: tuple[tuple[int, int], ...],
) -> StackAggregateObjectFact8616 | None:
    """Build one interior-array fact when its scalar boundary is proven."""
    if not -frame_size <= base_offset < 0:
        return None
    boundary_offsets = sorted(
        {
            offset
            for offset, width in fixed_accesses
            if base_offset < offset < 0 and width > 0
        }
    )
    if not boundary_offsets:
        return None
    boundary_offset = boundary_offsets[0]
    boundary_widths = {
        width
        for offset, width in fixed_accesses
        if offset == boundary_offset and width > 0
    }
    if len(boundary_widths) != 1:
        return None
    byte_size = boundary_offset - base_offset
    if byte_size < element_width * 2 or byte_size % element_width != 0:
        return None
    if any(
        base_offset <= offset < boundary_offset
        for offset, _width in fixed_accesses
    ):
        return None
    return StackAggregateObjectFact8616(
        base_offset=base_offset,
        byte_size=byte_size,
        element_width=element_width,
        frame_allocation_size=frame_size,
        address_taken_count=0,
        indexed_access_count=sum(
            displacement == base_offset and width == element_width
            for displacement, width in indexed_accesses
        ),
        indexed_offsets=(base_offset,),
        scalar_boundary_offset=boundary_offset,
        scalar_boundary_width=next(iter(boundary_widths)),
    )


def recover_stack_aggregate_object_facts_from_instructions_8616(
    instructions: tuple[object, ...],
    *,
    stack_probe_targets: frozenset[int],
) -> StackAggregateRecovery8616:
    """Classify bottom-of-frame aggregates from decoded binary instructions."""
    insns = tuple(_instruction(item) for item in instructions)
    (
        allocations,
        fixed_accesses,
        indexed_accesses,
        scaled_indexed_accesses,
        address_taken,
    ) = _classify_instruction_stack_accesses_8616(insns, stack_probe_targets)

    raw_count = len(allocations) + len(fixed_accesses) + len(indexed_accesses) + len(address_taken)
    if not allocations:
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.NO_EVIDENCE,
            raw_count,
            raw_count,
            0,
            0,
            0,
            refusals=("missing_stack_allocation_evidence",),
        )
    unique_allocations = set(allocations)
    if len(unique_allocations) != 1:
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.REFUSED,
            raw_count,
            raw_count,
            0,
            0,
            1,
            refusals=("ambiguous_frame_allocation",),
        )

    frame_size = next(iter(unique_allocations))
    base_offset = -frame_size
    base_address_count = sum(
        displacement == base_offset for displacement, _width in address_taken
    )
    full_frame = _full_frame_address_recovery_8616(
        frame_size=frame_size,
        base_address_count=base_address_count,
        address_taken=tuple(address_taken),
        fixed_accesses=tuple(fixed_accesses),
        indexed_accesses=tuple(indexed_accesses),
        raw_count=raw_count,
    )
    if full_frame is not None:
        return full_frame
    if not indexed_accesses:
        addressed_partition = _recover_bottom_addressed_partition_8616(
            frame_size=frame_size,
            fixed_accesses=tuple(fixed_accesses),
            address_taken=tuple(address_taken),
            raw_count=raw_count,
        )
        if addressed_partition.status is not StackAggregateRecoveryStatus8616.NO_EVIDENCE:
            return addressed_partition
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.NO_EVIDENCE,
            raw_count,
            raw_count,
            0,
            0,
            0,
            refusals=("missing_indexed_partition_evidence",),
        )
    interior_recovery = _recover_interior_scaled_aggregate_8616(
        frame_size=frame_size,
        fixed_accesses=tuple(fixed_accesses),
        indexed_accesses=tuple(indexed_accesses),
        scaled_indexed_accesses=tuple(scaled_indexed_accesses),
        raw_count=raw_count,
    )
    if interior_recovery.status is not StackAggregateRecoveryStatus8616.NO_EVIDENCE:
        return interior_recovery
    top_addressed_partition = _recover_top_addressed_partition_8616(
        frame_size=frame_size,
        fixed_accesses=tuple(fixed_accesses),
        indexed_accesses=tuple(indexed_accesses),
        address_taken=tuple(address_taken),
        raw_count=raw_count,
    )
    if top_addressed_partition.status is not StackAggregateRecoveryStatus8616.NO_EVIDENCE:
        return top_addressed_partition
    return _recover_bottom_indexed_aggregate_8616(
        frame_size=frame_size,
        base_offset=base_offset,
        base_address_count=base_address_count,
        fixed_accesses=tuple(fixed_accesses),
        indexed_accesses=tuple(indexed_accesses),
        address_taken=tuple(address_taken),
        raw_count=raw_count,
        interior_recovery=interior_recovery,
    )


def _full_frame_address_recovery_8616(
    *,
    frame_size: int,
    base_address_count: int,
    address_taken: tuple[tuple[int, int], ...],
    fixed_accesses: tuple[tuple[int, int], ...],
    indexed_accesses: tuple[tuple[int, int], ...],
    raw_count: int,
) -> StackAggregateRecovery8616 | None:
    """Materialize a full-frame addressed aggregate, or None when unproven."""
    if not (
        base_address_count > 0
        and base_address_count == len(address_taken)
        and not fixed_accesses
        and not indexed_accesses
    ):
        return None
    fact = StackAggregateObjectFact8616(
        base_offset=-frame_size,
        byte_size=frame_size,
        element_width=1,
        frame_allocation_size=frame_size,
        address_taken_count=base_address_count,
        indexed_access_count=0,
        indexed_offsets=(),
        scalar_boundary_offset=None,
        scalar_boundary_width=None,
        evidence_kind=StackAggregateEvidenceKind8616.FULL_FRAME_ADDRESS,
    )
    return StackAggregateRecovery8616(
        StackAggregateRecoveryStatus8616.MATERIALIZABLE,
        raw_count,
        raw_count,
        1,
        0,
        0,
        facts=(fact,),
    )


def _recover_bottom_indexed_aggregate_8616(
    *,
    frame_size: int,
    base_offset: int,
    base_address_count: int,
    fixed_accesses: tuple[tuple[int, int], ...],
    indexed_accesses: tuple[tuple[int, int], ...],
    address_taken: tuple[tuple[int, int], ...],
    raw_count: int,
    interior_recovery: StackAggregateRecovery8616,
) -> StackAggregateRecovery8616:
    """Resolve the bottom-of-frame indexed aggregate lane."""
    if not address_taken:
        return interior_recovery
    return _bottom_indexed_aggregate_tail_8616(
        frame_size=frame_size,
        base_offset=base_offset,
        base_address_count=base_address_count,
        fixed_accesses=fixed_accesses,
        indexed_accesses=indexed_accesses,
        raw_count=raw_count,
    )


def _bottom_indexed_aggregate_tail_8616(
    *,
    frame_size: int,
    base_offset: int,
    base_address_count: int,
    fixed_accesses: tuple[tuple[int, int], ...],
    indexed_accesses: tuple[tuple[int, int], ...],
    raw_count: int,
) -> StackAggregateRecovery8616:
    """Materialize or refuse the bottom-of-frame indexed aggregate evidence."""
    indexed_widths = {width for displacement, width in indexed_accesses if displacement in {base_offset - width, base_offset}}
    if len(indexed_widths) != 1 or base_address_count == 0:
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.REFUSED,
            raw_count,
            raw_count,
            0,
            0,
            1,
            refusals=("aggregate_base_or_element_width_unproven",),
        )
    element_width = next(iter(indexed_widths))
    if element_width != 1:
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.REFUSED,
            raw_count,
            raw_count,
            0,
            0,
            1,
            refusals=("indexed_element_units_unproven",),
        )
    boundaries = sorted(
        (offset, width)
        for offset, width in set(fixed_accesses)
        if base_offset < offset < 0 and width > element_width and offset + width == 0
    )
    if len(boundaries) != 1:
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.REFUSED,
            raw_count,
            raw_count,
            0,
            0,
            1,
            refusals=("scalar_frame_boundary_unproven",),
        )
    boundary_offset, boundary_width = boundaries[0]
    byte_size = boundary_offset - base_offset
    if byte_size <= 0 or byte_size % element_width != 0:
        return StackAggregateRecovery8616(
            StackAggregateRecoveryStatus8616.REFUSED,
            raw_count,
            raw_count,
            0,
            0,
            1,
            refusals=("aggregate_extent_invalid",),
        )
    indexed_count = sum(
        width == element_width and displacement in {base_offset - element_width, base_offset}
        for displacement, width in indexed_accesses
    )
    indexed_offsets = tuple(
        sorted(
            {
                displacement
                for displacement, width in indexed_accesses
                if width == element_width and displacement in {base_offset - element_width, base_offset}
            }
        )
    )
    fact = StackAggregateObjectFact8616(
        base_offset=base_offset,
        byte_size=byte_size,
        element_width=element_width,
        frame_allocation_size=frame_size,
        address_taken_count=base_address_count,
        indexed_access_count=indexed_count,
        indexed_offsets=indexed_offsets,
        scalar_boundary_offset=boundary_offset,
        scalar_boundary_width=boundary_width,
    )
    return StackAggregateRecovery8616(
        StackAggregateRecoveryStatus8616.MATERIALIZABLE,
        raw_count,
        raw_count,
        1,
        0,
        0,
        facts=(fact,),
    )


def _function_instructions(function: object) -> tuple[object, ...]:
    """Collect deterministic decoded instructions from an angr function boundary."""
    by_address: dict[int, object] = {}
    with contextlib.suppress(Exception):
        for block in tuple(getattr(function, "blocks", ()) or ()):
            capstone = getattr(block, "capstone", None)
            for wrapper in tuple(getattr(capstone, "insns", ()) or ()):
                insn = _instruction(wrapper)
                address = getattr(insn, "address", None)
                if isinstance(address, int):
                    by_address.setdefault(address, wrapper)
    return tuple(by_address[address] for address in sorted(by_address))


def collect_stack_aggregate_object_facts_8616(
    project: object,
    function: object,
    *,
    instructions: tuple[object, ...] | None = None,
) -> StackAggregateRecovery8616:
    """Collect aggregate frame-object facts from a live function and helper registry."""
    decoded = instructions if instructions is not None else _function_instructions(function)
    registered_targets = (
        getattr(getattr(project, "arch", None), "_inertia_stack_probe_helper_targets_8616", ()) or ()
    )
    targets: set[int] = {target for target in registered_targets if isinstance(target, int)}
    for wrapper in decoded:
        insn = _instruction(wrapper)
        target = _direct_call_target(insn)
        if not isinstance(target, int):
            continue
        evidence = identify_x86_16_compiler_helper_at_8616(project, target)
        if (evidence is not None and is_x86_16_stack_probe_evidence_kind_8616(evidence.kind)) or is_x86_16_registered_stack_probe_target_8616(getattr(project, "arch", None), target):
            targets.add(target)
    return recover_stack_aggregate_object_facts_from_instructions_8616(
        decoded,
        stack_probe_targets=frozenset(targets),
    )


def _classify_instruction_stack_accesses_8616(
    insns: tuple[object, ...],
    stack_probe_targets: frozenset[int],
) -> tuple[
    list[int],
    list[tuple[int, int]],
    list[tuple[int, int]],
    list[tuple[int, int]],
    list[tuple[int, int]],
]:
    """Scan decoded instructions into allocation and access buckets."""
    allocations: list[int] = []
    fixed_accesses: list[tuple[int, int]] = []
    indexed_accesses: list[tuple[int, int]] = []
    scaled_indexed_accesses: list[tuple[int, int]] = []
    address_taken: list[tuple[int, int]] = []

    for index, insn in enumerate(insns):
        target = _direct_call_target(insn)
        if isinstance(target, int) and (target in stack_probe_targets or (target & 0xFFFF) in stack_probe_targets):
            allocation = _stack_probe_allocation_before_call(insns, index)
            if isinstance(allocation, int):
                allocations.append(allocation)
        buckets = (fixed_accesses, indexed_accesses, scaled_indexed_accesses, address_taken)
        for operand in tuple(getattr(insn, "operands", ()) or ()):
            access = _bp_memory_access(insn, operand)
            if access is None:
                continue
            _record_bp_stack_access_8616(insns, index, insn, access, buckets)
    return allocations, fixed_accesses, indexed_accesses, scaled_indexed_accesses, address_taken


def _record_bp_stack_access_8616(
    insns: tuple[object, ...],
    index: int,
    insn: object,
    access: tuple[int, int, str | None],
    buckets: tuple[
        list[tuple[int, int]],
        list[tuple[int, int]],
        list[tuple[int, int]],
        list[tuple[int, int]],
    ],
) -> None:
    """Bucket one BP-relative memory access as fixed/indexed/scaled/address-taken."""
    fixed_accesses, indexed_accesses, scaled_indexed_accesses, address_taken = buckets
    displacement, width, index_name = access
    if displacement >= 0:
        return
    if getattr(insn, "id", None) == X86_INS_LEA:
        if index_name is None:
            address_taken.append((displacement, width))
        return
    if index_name is None:
        fixed_accesses.append((displacement, width))
        return
    indexed_accesses.append((displacement, width))
    if _index_scale_matches_width_8616(
        insns,
        index,
        index_name,
        width,
    ):
        scaled_indexed_accesses.append((displacement, width))


def _materialize_fact(codegen: object, fact: StackAggregateObjectFact8616) -> tuple[bool, bool]:
    """Return ``(materialized, changed)`` for one exact aggregate frame partition."""
    cfunc = getattr(codegen, "cfunc", None)
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        return False, False
    tracked_cvars = getattr(codegen, "_inertia_stack_aggregate_cvars_8616", {}) or {}
    if not isinstance(tracked_cvars, dict):
        tracked_cvars = {}
    tracked_cvar = tracked_cvars.get(fact.base_offset)
    entry_sp_offset = entry_sp_offset_for_machine_bp_range_8616(codegen, fact.base_offset, fact.byte_size)
    restored = restore_live_stack_aggregate_declaration_8616(
        codegen, tracked_cvar, bp_offset=fact.base_offset, entry_sp_offset=entry_sp_offset, size=fact.byte_size,
    )
    candidates_by_offset: dict[int, list[structured_c.CVariable]] = {
        fact.base_offset: [],
    }
    if isinstance(fact.scalar_boundary_offset, int):
        candidates_by_offset[fact.scalar_boundary_offset] = []
    seen_candidates: set[int] = set()

    unified_local_vars = getattr(cfunc, "unified_local_vars", None)
    _collect_partition_candidates_8616(
        codegen, variables_in_use, unified_local_vars, candidates_by_offset, seen_candidates
    )

    # Codegen regeneration may copy private evidence attributes while replacing
    # every C node. A tracked CVariable is reusable only when it is also present
    # on the current declaration surface.
    current_tracked_cvar = tracked_cvar if id(tracked_cvar) in seen_candidates else None
    aggregate_candidates = candidates_by_offset[fact.base_offset]
    if fact.element_width not in {1, 2, 4}:
        return False, False
    arch = getattr(getattr(codegen, "project", None), "arch", None)
    element_type = {
        1: SimTypeChar(False),
        2: SimTypeShort(False),
        4: SimTypeLong(False),
    }[fact.element_width].with_arch(arch)
    array_type = SimTypeFixedSizeArray(element_type, fact.byte_size // fact.element_width).with_arch(
        arch
    )
    typed_cfunc = typing.cast(_AggregateCFunctionBoundary8616, cfunc)
    try:
        variable_manager = typed_cfunc.variable_manager
    except AttributeError:
        variable_manager = None

    changed = restored
    if not aggregate_candidates:
        changed = _materialize_missing_aggregate_8616(
            codegen,
            cfunc,
            fact,
            entry_sp_offset,
            array_type,
            variables_in_use,
            unified_local_vars,
            aggregate_candidates,
            seen_candidates,
            variable_manager,
        ) or changed
    changed = _persist_aggregate_frame_types_8616(
        codegen, variables_in_use, aggregate_candidates, fact, array_type, variable_manager
    ) or changed

    boundary_types, boundary_changed = _persist_boundary_scalar_types_8616(
        fact, candidates_by_offset, arch, variable_manager
    )
    changed = boundary_changed or changed

    changed = _rewrite_unified_partition_entries_8616(
        codegen, unified_local_vars, candidates_by_offset, fact, array_type, boundary_types
    ) or changed

    cvar = select_stack_aggregate_projection_8616(
        codegen, aggregate_candidates, current_tracked_cvar,
        bp_offset=fact.base_offset, entry_sp_offset=entry_sp_offset,
        size=fact.byte_size,
    )
    changed = rebind_stack_aggregate_views_8616(codegen, aggregate_candidates, cvar).materialized_count > 0 or changed
    typing.cast(Any, codegen)._inertia_stack_aggregate_cvars_8616 = {
        **tracked_cvars,
        fact.base_offset: cvar,
    }
    decay = _decay_stack_aggregate_call_arguments(codegen, fact)
    typing.cast(Any, codegen)._inertia_stack_aggregate_call_decay_8616 = decay
    return True, changed or decay.materialized_count > 0


def _collect_partition_candidates_8616(
    codegen: object,
    variables_in_use: dict[object, object],
    unified_local_vars: object,
    candidates_by_offset: dict[int, list[structured_c.CVariable]],
    seen_candidates: set[int],
) -> None:
    """Collect current-codegen CVariable views for each partition offset."""

    def add_candidate(variable: object, cvar: object) -> None:
        """Record one current-codegen view in the proven frame partition."""
        if not isinstance(variable, SimStackVariable) or not isinstance(cvar, structured_c.CVariable):
            return
        bp_offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
        if variable.base != "bp" or bp_offset not in candidates_by_offset or id(cvar) in seen_candidates:
            return
        seen_candidates.add(id(cvar))
        candidates_by_offset[bp_offset].append(cvar)

    for candidate_variable, candidate_cvar in variables_in_use.items():
        add_candidate(candidate_variable, candidate_cvar)
    if isinstance(unified_local_vars, dict):
        for candidate_variable, entries in unified_local_vars.items():
            if not isinstance(entries, set):
                continue
            for entry in entries:
                if isinstance(entry, tuple) and len(entry) == 2:
                    add_candidate(candidate_variable, entry[0])


def _persist_partition_type_8616(
    variable_manager: _VariableManagerTypeBoundary8616 | None, variable: object, variable_type: SimType
) -> None:
    """Persist one exact frame-partition type across CFunction.refresh()."""
    if variable_manager is None or not isinstance(variable, SimVariable):
        return
    variable_manager.set_variable_type(
        variable,
        variable_type,
        override_bot=True,
        all_unified=True,
    )


def _materialize_missing_aggregate_8616(
    codegen: object,
    cfunc: object,
    fact: StackAggregateObjectFact8616,
    entry_sp_offset: int | None,
    array_type: SimType,
    variables_in_use: dict[object, object],
    unified_local_vars: object,
    aggregate_candidates: list[structured_c.CVariable],
    seen_candidates: set[int],
    variable_manager: _VariableManagerTypeBoundary8616 | None,
) -> bool:
    """Create the aggregate frame variable when no declaration exists."""
    aggregate_variable = SimStackVariable(
        fact.base_offset if entry_sp_offset is None else entry_sp_offset,
        fact.byte_size,
        base="bp",
        name=f"local_{abs(fact.base_offset):x}",
        region=getattr(cfunc, "addr", None),
    )
    aggregate_cvar = structured_c.CVariable(
        aggregate_variable,
        variable_type=array_type,
        codegen=codegen,
    )
    variables_in_use[aggregate_variable] = aggregate_cvar
    aggregate_candidates.append(aggregate_cvar)
    seen_candidates.add(id(aggregate_cvar))
    if isinstance(unified_local_vars, dict):
        unified_local_vars[aggregate_variable] = {(aggregate_cvar, array_type)}
    _persist_partition_type_8616(variable_manager, aggregate_variable, array_type)
    return True


def _persist_aggregate_frame_types_8616(
    codegen: object,
    variables_in_use: dict[object, object],
    aggregate_candidates: list[structured_c.CVariable],
    fact: StackAggregateObjectFact8616,
    array_type: SimType,
    variable_manager: _VariableManagerTypeBoundary8616 | None,
) -> bool:
    """Persist the array type on the partition and its candidate views."""
    changed = False
    for candidate_variable, candidate_cvar in variables_in_use.items():  # noqa: B007
        if (
            isinstance(candidate_variable, SimStackVariable)
            and candidate_variable.base == "bp"
            and machine_bp_offset_for_stack_variable_8616(codegen, candidate_variable)
            == fact.base_offset
        ):
            _persist_partition_type_8616(variable_manager, candidate_variable, array_type)
    for candidate_cvar in aggregate_candidates:
        if candidate_cvar.variable_type != array_type:
            candidate_cvar.variable_type = array_type
            changed = True
    return changed


def _persist_boundary_scalar_types_8616(
    fact: StackAggregateObjectFact8616,
    candidates_by_offset: dict[int, list[structured_c.CVariable]],
    arch: object,
    variable_manager: _VariableManagerTypeBoundary8616 | None,
) -> tuple[dict[int, SimType], bool]:
    """Persist proven scalar boundary types; returns (id(cvar)->type, changed)."""
    boundary_types: dict[int, SimType] = {}
    changed = False
    if isinstance(fact.scalar_boundary_offset, int) and isinstance(
        fact.scalar_boundary_width,
        int,
    ):
        for candidate_cvar in candidates_by_offset[fact.scalar_boundary_offset]:
            boundary_type = _integer_type_for_width(
                fact.scalar_boundary_width,
                candidate_cvar.variable_type,
                arch,
            )
            if boundary_type is None:
                continue
            _persist_partition_type_8616(variable_manager, candidate_cvar.variable, boundary_type)
            boundary_types[id(candidate_cvar)] = boundary_type
            if candidate_cvar.variable_type != boundary_type:
                candidate_cvar.variable_type = boundary_type
                changed = True
    return boundary_types, changed


def _rewrite_unified_partition_entries_8616(
    codegen: object,
    unified_local_vars: object,
    candidates_by_offset: dict[int, list[structured_c.CVariable]],
    fact: StackAggregateObjectFact8616,
    array_type: SimType,
    boundary_types: dict[int, SimType],
) -> bool:
    """Rewrite unified-local-var entries to the proven partition types."""
    changed = False
    if not isinstance(unified_local_vars, dict):
        return False
    for unified_variable, entries in tuple(unified_local_vars.items()):
        if not isinstance(unified_variable, SimStackVariable):
            continue
        bp_offset = machine_bp_offset_for_stack_variable_8616(
            codegen,
            unified_variable,
        )
        if unified_variable.base != "bp" or bp_offset not in candidates_by_offset:
            continue
        if isinstance(entries, set):
            updated_entries: set[object] = set()
            for entry in entries:
                if not isinstance(entry, tuple) or len(entry) != 2:
                    updated_entries.add(entry)
                    continue
                entry_cvar, entry_type = entry
                if not isinstance(entry_cvar, structured_c.CVariable):
                    updated_entries.add(entry)
                    continue
                replacement_type = (
                    array_type
                    if bp_offset == fact.base_offset
                    else boundary_types.get(id(entry_cvar))
                )
                if replacement_type is None:
                    updated_entries.add(entry)
                    continue
                changed = (
                    changed
                    or entry_type != replacement_type
                    or entry_cvar.variable_type != replacement_type
                )
                entry_cvar.variable_type = replacement_type
                updated_entries.add((entry_cvar, replacement_type))
            unified_local_vars[unified_variable] = updated_entries
    return changed


def _decay_stack_aggregate_call_arguments(
    codegen: object,
    fact: StackAggregateObjectFact8616,
) -> StackAggregateCallDecay8616:
    """Replace ``&array`` call arguments with the binary-proven array value.

    A C array expression already decays to its first-element pointer at a call.
    Keeping ``&array`` instead produces a pointer-to-array type even though the
    16-bit ABI address bits are identical. Inferred callee prototypes cannot
    distinguish those source-level spellings and therefore are not evidence
    against normal C array decay.
    """
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None)
    tracked_cvars = getattr(codegen, "_inertia_stack_aggregate_cvars_8616", {}) or {}
    aggregate_cvar = tracked_cvars.get(fact.base_offset) if isinstance(tracked_cvars, dict) else None
    raw_count = 0
    normalized_count = 0
    classified_count = 0
    materialized_count = 0

    def decay_reference(candidate: object) -> object:
        """Decay one exact reference to the proven aggregate inside a call argument."""
        nonlocal raw_count, normalized_count, classified_count, materialized_count
        if not isinstance(candidate, structured_c.CUnaryOp) or candidate.op != "Reference":
            return candidate
        raw_count += 1
        operand = candidate.operand
        if not isinstance(operand, structured_c.CVariable):
            return candidate
        normalized_count += 1
        variable = operand.variable
        _log_stack_aggregate_decay_debug_8616(operand, variable, aggregate_cvar)
        if (
            not isinstance(variable, SimStackVariable)
            or variable.base != "bp"
            or machine_bp_offset_for_stack_variable_8616(codegen, variable)
            != fact.base_offset
            or not isinstance(aggregate_cvar, structured_c.CVariable)
            or not isinstance(aggregate_cvar.type, (SimTypeArray, SimTypeFixedSizeArray))
        ):
            return candidate
        classified_count += 1
        materialized_count += 1
        return aggregate_cvar

    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, structured_c.CFunctionCall) or not isinstance(node.args, (list, tuple)):
            continue
        _decay_call_arguments_8616(node, decay_reference)
    return StackAggregateCallDecay8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=classified_count - materialized_count,
    )


def _log_stack_aggregate_decay_debug_8616(
    operand: object, variable: object, aggregate_cvar: object
) -> None:
    """Emit the optional stack-aggregate decay diagnostic."""
    if not os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        return
    logging.getLogger(__name__).warning(
        "[stack-aggregate-decay] operand=%s variable=%s offset=%r canonical=%s canonical_type=%s",
        type(operand).__name__,
        type(variable).__name__,
        variable.offset if isinstance(variable, SimStackVariable) else None,
        type(aggregate_cvar).__name__,
        type(aggregate_cvar.type).__name__
        if isinstance(aggregate_cvar, structured_c.CVariable)
        else None,
    )


def _decay_call_arguments_8616(
    node: structured_c.CFunctionCall, decay_reference: typing.Callable[[object], object]
) -> None:
    """Apply the decay rewrite to one call's argument list in place."""
    args = list(node.args)
    call_changed = False
    for index, arg in enumerate(args):
        replacement = decay_reference(arg)
        if replacement is not arg:
            args[index] = replacement
            call_changed = True
            continue
        if _replace_c_children_8616(arg, decay_reference):
            call_changed = True
    if call_changed:
        node.args = args


def decay_stack_aggregate_call_arguments_8616(codegen: object) -> bool:
    """Replay typed array decay after a later pass regenerates call arguments.

    Stack-object classification remains owned by this Types/Lowering module.
    Rewrite orchestration may call this bounded consumer after rebuilding call
    AST nodes, but it must not infer aggregate facts or array types itself.
    """
    facts_value = getattr(codegen, "_inertia_stack_aggregate_object_facts_8616", ()) or ()
    facts = tuple(
        fact
        for fact in facts_value
        if isinstance(fact, StackAggregateObjectFact8616)
    )
    results = tuple(_decay_stack_aggregate_call_arguments(codegen, fact) for fact in facts)
    result = StackAggregateCallDecay8616(
        raw_fact_count=sum(item.raw_fact_count for item in results),
        normalized_fact_count=sum(item.normalized_fact_count for item in results),
        classified_fact_count=sum(item.classified_fact_count for item in results),
        materialized_count=sum(item.materialized_count for item in results),
        failure_count=sum(item.failure_count for item in results),
    )
    typing.cast(Any, codegen)._inertia_stack_aggregate_call_decay_8616 = result
    return result.materialized_count > 0


def reapply_stack_aggregate_object_facts_8616(codegen: object) -> bool:
    """Replay proven frame-object types after a CFunction lifecycle rebuild.

    This bounded consumer performs no recovery. It applies only facts already
    classified from binary frame allocation, address-taking, indexed access,
    and scalar-boundary evidence.
    """
    facts = stack_aggregate_object_facts_8616(codegen)
    materialized = 0
    changed = False
    for fact in facts:
        fact_materialized, fact_changed = _materialize_fact(codegen, fact)
        materialized += int(fact_materialized)
        changed = fact_changed or changed
    stats = StackAggregateObjectReplay8616(
        raw_fact_count=len(facts),
        normalized_fact_count=len(facts),
        classified_fact_count=len(facts),
        materialized_count=materialized,
        failure_count=max(len(facts) - materialized, 0),
    )
    typing.cast(Any, codegen)._inertia_stack_aggregate_object_replay_8616 = stats
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        from ..pipeline.errors import PipelineHardError

        raise PipelineHardError(
            "classified stack aggregate object facts were not replayed",
            layer="types_lowering:stack_aggregate_objects",
        )
    return reapply_call_output_stack_object_types_8616(codegen) or changed


def _integer_type_for_width(
    width: int,
    existing_type: object,
    arch: object,
) -> SimType | None:
    """Build an integer type at an exact binary access width, preserving signedness."""
    signed = getattr(existing_type, "signed", False)
    signed = signed if isinstance(signed, bool) else False
    type_class: type[SimType] | None = {
        1: SimTypeChar,
        2: SimTypeShort,
        4: SimTypeLong,
    }.get(width)
    if type_class is None:
        return None
    return type_class(signed).with_arch(arch)


def _pure_carrier_expression(node: object) -> bool:
    """Return whether a C expression is pure enough to delete with proven non-memory effect."""
    if isinstance(node, structured_c.CConstant | structured_c.CVariable):
        return True
    if isinstance(node, structured_c.CBinaryOp):
        return _pure_carrier_expression(node.lhs) and _pure_carrier_expression(node.rhs)
    if isinstance(node, structured_c.CTypeCast):
        return _pure_carrier_expression(node.expr)
    if isinstance(node, structured_c.CUnaryOp) and node.op not in {"Dereference", "Reference"}:
        return _pure_carrier_expression(node.operand)
    return False


def _instruction_covering_tag(
    instructions: tuple[object, ...],
    tag_addr: int,
) -> object | None:
    """Return the decoded instruction whose byte interval owns a C-node tag."""
    by_address: dict[int, object] = {}
    for wrapper in instructions:
        insn = _instruction(wrapper)
        address = getattr(insn, "address", None)
        if isinstance(address, int):
            by_address.setdefault(address, insn)
    for address in sorted(by_address, reverse=True):
        if address > tag_addr:
            continue
        insn = by_address[address]
        size = getattr(insn, "size", None)
        if isinstance(size, int) and size > 0 and tag_addr < address + size:
            return insn
        return insn if address == tag_addr else None
    return None


def prune_nonmemory_stack_aggregate_carriers_8616(
    codegen: object,
    instructions: tuple[object, ...],
) -> bool:
    """Prune pure aggregate assignments proven to represent PUSH/CALL stack effects."""
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None)
    facts = getattr(codegen, "_inertia_stack_aggregate_object_facts_8616", ()) or ()
    base_offsets = {
        fact.base_offset
        for fact in facts
        if isinstance(fact, StackAggregateObjectFact8616)
    }
    raw_count = 0
    classified_count = 0
    materialized_count = 0
    seen: set[int] = set()

    counts = {"raw": 0, "classified": 0, "materialized": 0}
    _visit_carrier_nodes_8616(
        root, codegen, base_offsets, instructions, counts, seen
    )
    raw_count = counts["raw"]
    classified_count = counts["classified"]
    materialized_count = counts["materialized"]
    result = StackAggregateCarrierPrune8616(
        raw_fact_count=raw_count,
        normalized_fact_count=raw_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=max(classified_count - materialized_count, 0),
    )
    typing.cast(Any, codegen)._inertia_stack_aggregate_carrier_prune_8616 = result
    return materialized_count > 0


def _prune_carrier_statements_8616(
    node: object,
    candidate: typing.Callable[[object], bool],
    visit: typing.Callable[[object], None],
    counts: dict[str, int],
) -> None:
    """Filter one node's statement list, pruning proven carrier assignments."""
    statements = getattr(node, "statements", None)
    if not isinstance(statements, list):
        return
    retained: list[object] = []
    for statement in statements:
        if candidate(statement):
            counts["materialized"] += 1
            continue
        retained.append(statement)
        visit(statement)
    if len(retained) != len(statements):
        statements[:] = retained


def _carrier_candidate_8616(
    codegen: object,
    base_offsets: frozenset[int] | set[int],
    instructions: tuple[object, ...],
    counts: dict[str, int],
    statement: object,
) -> bool:
    """Classify one statement as a proven push/call carrier candidate."""
    if not isinstance(statement, structured_c.CAssignment):
        return False
    lhs = statement.lhs
    if not isinstance(lhs, structured_c.CVariable):
        return False
    variable = lhs.variable
    if (
        not isinstance(variable, SimStackVariable)
        or variable.base != "bp"
        or machine_bp_offset_for_stack_variable_8616(codegen, variable)
        not in base_offsets
    ):
        return False
    counts["raw"] += 1
    tags = getattr(statement, "tags", None)
    ins_addr = tags.get("ins_addr") if isinstance(tags, dict) else None
    if not isinstance(ins_addr, int) or not _pure_carrier_expression(statement.rhs):
        return False
    insn = _instruction_covering_tag(instructions, ins_addr)
    if getattr(insn, "id", None) not in {X86_INS_PUSH, X86_INS_CALL, X86_INS_LCALL}:
        return False
    counts["classified"] += 1
    return True


def _visit_carrier_nodes_8616(
    node: object,
    codegen: object,
    base_offsets: frozenset[int] | set[int],
    instructions: tuple[object, ...],
    counts: dict[str, int],
    seen: set[int],
) -> None:
    """Walk C nodes depth-first, pruning proven carrier statements."""
    if node is None or id(node) in seen:
        return
    seen.add(id(node))
    _prune_carrier_statements_8616(
        node,
        lambda statement: _carrier_candidate_8616(codegen, base_offsets, instructions, counts, statement),
        lambda child: _visit_carrier_nodes_8616(child, codegen, base_offsets, instructions, counts, seen),
        counts,
    )
    for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
        _visit_carrier_nodes_8616(
            getattr(node, attr, None), codegen, base_offsets, instructions, counts, seen
        )
    pairs = getattr(node, "condition_and_nodes", None)
    if pairs:
        for _condition, body in tuple(pairs):
            _visit_carrier_nodes_8616(body, codegen, base_offsets, instructions, counts, seen)


def materialize_stack_aggregate_objects_8616(
    codegen: object,
    project: object,
    function: object,
    *,
    instructions: tuple[object, ...] | None = None,
) -> bool:
    """Collect and materialize binary-proven stack aggregate objects."""
    if function is None or getattr(codegen, "cfunc", None) is None:
        return False
    decoded = instructions if instructions is not None else _function_instructions(function)
    recovery = collect_stack_aggregate_object_facts_8616(project, function, instructions=decoded)
    materialized = 0
    changed = False
    for fact in recovery.facts:
        fact_materialized, fact_changed = _materialize_fact(codegen, fact)
        materialized += int(fact_materialized)
        changed = fact_changed or changed
    final = StackAggregateRecovery8616(
        status=recovery.status,
        raw_fact_count=recovery.raw_fact_count,
        normalized_fact_count=recovery.normalized_fact_count,
        classified_fact_count=recovery.classified_fact_count,
        materialized_count=materialized,
        failure_count=recovery.failure_count + max(recovery.classified_fact_count - materialized, 0),
        facts=recovery.facts,
        refusals=recovery.refusals,
    )
    typing.cast(Any, codegen)._inertia_stack_aggregate_recovery_8616 = final
    typing.cast(Any, codegen)._inertia_stack_aggregate_object_facts_8616 = final.facts
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        logging.getLogger(__name__).warning(
            "[stack-aggregate] status=%s raw=%d classified=%d materialized=%d "
            "failures=%d facts=%r refusals=%r",
            final.status.value,
            final.raw_fact_count,
            final.classified_fact_count,
            final.materialized_count,
            final.failure_count,
            final.facts,
            final.refusals,
        )
    changed = prune_nonmemory_stack_aggregate_carriers_8616(codegen, decoded) or changed
    if changed:
        typing.cast(Any, codegen)._inertia_codegen_decl_refresh_required_8616 = True
    return changed
