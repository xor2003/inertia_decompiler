"""Gate data-object lowering on exact function-local segment evidence.

Layer: Types/Lowering.
Responsibility: consume IR-owned segment contracts to decide whether one C AST
access may use the entry-DS object namespace or must remain segmented.
Consumes alias, widening, and typed facts by applying local must-evidence at the
object-lowering boundary.
Do not recover semantics from COD, source, assembly, or rendered C text.
This module does not infer segment identity from C shape, program labels, memory
model names, sidecars, or rendered text. A program-wide layout verdict may
describe compatibility, but it cannot promote missing or conflicting local
must-evidence.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from inertia.ir.segment_contract import (
    SegmentAccessFact,
    SegmentAccessKind,
    SegmentFactVerdict,
    SegmentFunctionContract,
    SegmentInstructionStateFact,
)

from .segment_access_coverage import (
    segment_access_matches_query_8616,
    select_contiguous_segment_access_facts_8616,
)
from .segment_codegen_access_provenance import (
    instruction_addrs_from_node_8616,
    unique_access_instruction_in_tagged_blocks_8616,
)

_LOGGER = logging.getLogger(__name__)

__all__ = [
    "SegmentAccessLoweringDecision8616",
    "SegmentAccessLoweringResult8616",
    "SegmentAccessLoweringStats8616",
    "classify_codegen_segment_access_8616",
    "classify_codegen_segment_address_8616",
    "classify_local_segment_access_8616",
    "classify_local_segment_address_8616",
    "instruction_addrs_from_node_8616",
    "may_lower_codegen_access_to_entry_ds_object_8616",
    "may_lower_codegen_address_to_entry_ds_object_8616",
    "record_segment_access_lowering_result_8616",
]


class _CodegenBoundary8616(Protocol):
    """Typed fields carried across the dynamic angr codegen boundary."""

    _inertia_segment_function_contract: SegmentFunctionContract
    _inertia_segment_access_lowering_stats_8616: SegmentAccessLoweringStats8616


class SegmentAccessLoweringDecision8616(StrEnum):
    """Fail-closed object-lowering decision for one segmented access."""

    ENTRY_DS_OBJECT = "entry_ds_object"
    EXPLICIT_SEGMENTED = "explicit_segmented"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class SegmentAccessLoweringStats8616:
    """Closed evidence census accumulated by segment-access consumers."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class SegmentAccessLoweringResult8616:
    """Decision and exact local facts supporting one lowering query."""

    decision: SegmentAccessLoweringDecision8616
    facts: tuple[SegmentAccessFact, ...] = ()
    instruction_states: tuple[SegmentInstructionStateFact, ...] = ()
    stats: SegmentAccessLoweringStats8616 = SegmentAccessLoweringStats8616()
    contract_available: bool = True


def _normalized_segment_register_8616(segment_register: str | None) -> str | None:
    """Normalize one real segment register and reject synthetic labels."""
    if not isinstance(segment_register, str):
        return None
    normalized = segment_register.lower()
    return normalized if normalized in {"cs", "ds", "es", "ss", "fs", "gs"} else None


def _unknown_result_8616(
    facts: tuple[SegmentAccessFact, ...] = (),
    *,
    instruction_states: tuple[SegmentInstructionStateFact, ...] = (),
    raw_fact_count: int = 0,
    contract_available: bool = True,
) -> SegmentAccessLoweringResult8616:
    """Build one explicit refusal with a closed per-query census."""
    return SegmentAccessLoweringResult8616(
        decision=SegmentAccessLoweringDecision8616.UNKNOWN_REFUSE,
        facts=facts,
        instruction_states=instruction_states,
        stats=SegmentAccessLoweringStats8616(
            raw_fact_count=raw_fact_count,
            normalized_fact_count=len(facts) + len(instruction_states),
            failure_count=1,
        ),
        contract_available=contract_available,
    )


def classify_local_segment_access_8616(
    contract: SegmentFunctionContract,
    *,
    instruction_addrs: frozenset[int] = frozenset(),
    access_kind: SegmentAccessKind | None = None,
    segment_register: str | None,
    offset: int | None,
    width: int | None,
) -> SegmentAccessLoweringResult8616:
    """Classify one access from exact local must-facts, refusing ambiguity."""
    register = _normalized_segment_register_8616(segment_register)
    candidates = tuple(
        fact
        for fact in contract.accesses
        if segment_access_matches_query_8616(
            fact,
            access_kind=access_kind,
            segment_register=register,
            offset=offset,
            width=width,
        )
        and (not instruction_addrs or fact.instruction_addr in instruction_addrs)
    )
    used_split_coverage = False
    if not candidates and isinstance(width, int) and width > 1 and register is not None:
        split_facts = tuple(
            fact
            for fact in contract.accesses
            if fact.segment_register == register
            and (access_kind is None or fact.kind is access_kind)
        )
        candidates = select_contiguous_segment_access_facts_8616(
            split_facts,
            instruction_addrs=instruction_addrs,
            offset=offset,
            width=width,
        )
        used_split_coverage = bool(candidates)
    if not candidates:
        return _unknown_result_8616(raw_fact_count=len(contract.accesses))
    if not instruction_addrs and (register is None or (len(candidates) != 1 and not used_split_coverage)):
        return _unknown_result_8616(candidates, raw_fact_count=len(contract.accesses))
    if any(fact.verdict is not SegmentFactVerdict.PROVEN for fact in candidates):
        return _unknown_result_8616(candidates, raw_fact_count=len(contract.accesses))
    physical_sources = {fact.physical_source for fact in candidates}
    if len(physical_sources) != 1 or None in physical_sources:
        return _unknown_result_8616(candidates, raw_fact_count=len(contract.accesses))
    decision = (
        SegmentAccessLoweringDecision8616.ENTRY_DS_OBJECT
        if physical_sources == {"ds"}
        else SegmentAccessLoweringDecision8616.EXPLICIT_SEGMENTED
    )
    return SegmentAccessLoweringResult8616(
        decision=decision,
        facts=candidates,
        stats=SegmentAccessLoweringStats8616(
            raw_fact_count=len(contract.accesses),
            normalized_fact_count=len(candidates),
            classified_fact_count=1,
            materialized_count=1,
        ),
    )


def classify_local_segment_address_8616(
    contract: SegmentFunctionContract,
    *,
    instruction_addrs: frozenset[int],
    segment_register: str | None,
) -> SegmentAccessLoweringResult8616:
    """Classify address formation from exact pre-instruction segment state."""
    register = _normalized_segment_register_8616(segment_register)
    candidates = tuple(
        fact
        for fact in contract.instruction_states
        if fact.register == register and fact.instruction_addr in instruction_addrs
    )
    raw_count = len(contract.instruction_states)
    if register is None or not instruction_addrs:
        return _unknown_result_8616(raw_fact_count=raw_count)
    if {fact.instruction_addr for fact in candidates} != set(instruction_addrs):
        return _unknown_result_8616(instruction_states=candidates, raw_fact_count=raw_count)
    if any(fact.verdict is not SegmentFactVerdict.PROVEN for fact in candidates):
        return _unknown_result_8616(instruction_states=candidates, raw_fact_count=raw_count)
    physical_sources = {fact.physical_source for fact in candidates}
    if len(physical_sources) != 1 or None in physical_sources:
        return _unknown_result_8616(instruction_states=candidates, raw_fact_count=raw_count)
    decision = (
        SegmentAccessLoweringDecision8616.ENTRY_DS_OBJECT
        if physical_sources == {"ds"}
        else SegmentAccessLoweringDecision8616.EXPLICIT_SEGMENTED
    )
    return SegmentAccessLoweringResult8616(
        decision=decision,
        instruction_states=candidates,
        stats=SegmentAccessLoweringStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=len(candidates),
            classified_fact_count=1,
            materialized_count=1,
        ),
    )


def classify_codegen_segment_access_8616(
    codegen: object,
    node: object,
    *,
    instruction_addrs: frozenset[int] = frozenset(),
    access_kind: SegmentAccessKind | None = None,
    segment_register: str | None,
    offset: int | None,
    width: int | None,
) -> SegmentAccessLoweringResult8616:
    """Read the owned local contract at the dynamic codegen boundary."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        contract = boundary._inertia_segment_function_contract
    except AttributeError:
        return _unknown_result_8616(contract_available=False)
    if not isinstance(contract, SegmentFunctionContract):
        return _unknown_result_8616(contract_available=False)
    node_instruction_addrs = instruction_addrs | instruction_addrs_from_node_8616(node)
    result = classify_local_segment_access_8616(
        contract,
        instruction_addrs=node_instruction_addrs,
        access_kind=access_kind,
        segment_register=segment_register,
        offset=offset,
        width=width,
    )
    if result.decision is not SegmentAccessLoweringDecision8616.UNKNOWN_REFUSE:
        return result
    register = _normalized_segment_register_8616(segment_register)
    if register is None:
        return result
    block_instruction_addrs = unique_access_instruction_in_tagged_blocks_8616(
        contract,
        node,
        access_kind=access_kind,
        segment_register=register,
        offset=offset,
        width=width,
    )
    if not block_instruction_addrs:
        return result
    return classify_local_segment_access_8616(
        contract,
        instruction_addrs=block_instruction_addrs,
        access_kind=access_kind,
        segment_register=segment_register,
        offset=offset,
        width=width,
    )


def classify_codegen_segment_address_8616(
    codegen: object,
    node: object,
    *,
    instruction_addrs: frozenset[int] = frozenset(),
    segment_register: str | None,
) -> SegmentAccessLoweringResult8616:
    """Read exact address-formation state at the dynamic codegen boundary."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        contract = boundary._inertia_segment_function_contract
    except AttributeError:
        return _unknown_result_8616(contract_available=False)
    if not isinstance(contract, SegmentFunctionContract):
        return _unknown_result_8616(contract_available=False)
    return classify_local_segment_address_8616(
        contract,
        instruction_addrs=instruction_addrs | instruction_addrs_from_node_8616(node),
        segment_register=segment_register,
    )


def record_segment_access_lowering_result_8616(
    codegen: object,
    result: SegmentAccessLoweringResult8616,
) -> None:
    """Accumulate a typed closed census on the dynamic codegen boundary."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        previous = boundary._inertia_segment_access_lowering_stats_8616
    except AttributeError:
        previous = SegmentAccessLoweringStats8616()
    if not isinstance(previous, SegmentAccessLoweringStats8616):
        previous = SegmentAccessLoweringStats8616()
    current = result.stats
    boundary._inertia_segment_access_lowering_stats_8616 = SegmentAccessLoweringStats8616(
        raw_fact_count=previous.raw_fact_count + current.raw_fact_count,
        normalized_fact_count=previous.normalized_fact_count + current.normalized_fact_count,
        classified_fact_count=previous.classified_fact_count + current.classified_fact_count,
        materialized_count=previous.materialized_count + current.materialized_count,
        failure_count=previous.failure_count + current.failure_count,
    )


def may_lower_codegen_access_to_entry_ds_object_8616(
    codegen: object,
    node: object,
    *,
    instruction_addrs: frozenset[int] = frozenset(),
    access_kind: SegmentAccessKind | None = None,
    segment_register: str | None,
    offset: int | None,
    width: int | None,
) -> bool:
    """Record local evidence and allow only proven entry-DS object identity.

    Isolated legacy consumers without an attached contract keep their prior
    behavior. The main Structuring path is separately guarded to attach the IR
    contract before segmented-memory consumers run.
    """
    result = classify_codegen_segment_access_8616(
        codegen,
        node,
        instruction_addrs=instruction_addrs,
        access_kind=access_kind,
        segment_register=segment_register,
        offset=offset,
        width=width,
    )
    if os.environ.get("INERTIA_DEBUG_SEGMENT_ACCESS_POLICY") == "1":
        _LOGGER.warning(
            "segment access policy kind=%s register=%s offset=%r width=%r instructions=%s decision=%s facts=%s states=%s",
            None if access_kind is None else access_kind.value,
            segment_register,
            offset,
            width,
            tuple(sorted(instruction_addrs_from_node_8616(node) | instruction_addrs)),
            result.decision.value,
            result.facts,
            result.instruction_states,
        )
    record_segment_access_lowering_result_8616(codegen, result)
    return not result.contract_available or (
        result.decision is SegmentAccessLoweringDecision8616.ENTRY_DS_OBJECT
    )


def may_lower_codegen_address_to_entry_ds_object_8616(
    codegen: object,
    node: object,
    *,
    instruction_addrs: frozenset[int] = frozenset(),
    segment_register: str | None,
) -> bool:
    """Record exact address-state evidence and allow only entry-DS identity."""
    result = classify_codegen_segment_address_8616(
        codegen,
        node,
        instruction_addrs=instruction_addrs,
        segment_register=segment_register,
    )
    record_segment_access_lowering_result_8616(codegen, result)
    return not result.contract_available or (
        result.decision is SegmentAccessLoweringDecision8616.ENTRY_DS_OBJECT
    )
