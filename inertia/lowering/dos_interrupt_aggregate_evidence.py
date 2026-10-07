"""Collect DOS interrupt aggregate facts from typed callsite evidence.

Layer: Types/Lowering.
Responsibility: join resolved DOS wrapper ABIs and exact immediate call
arguments to global storage identities. Optional COD aliases affect display
names only; they do not prove argument types or field layouts.

Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.semantics.callsite_summary import CallsiteSummary8616

from .cod_global_identity import CodGlobalIdentityFact8616
from .dos_interrupt_abi import (
    DosInterruptAbiArgumentKind8616,
    DosInterruptAbiContract8616,
    dos_interrupt_abi_contract_8616,
)
from .indexed_global_evidence import IndexedSegmentedGlobalEvidence8616

__all__ = [
    "DosInterruptAggregateCallFact8616",
    "DosInterruptAggregateObjectFact8616",
    "collect_dos_interrupt_aggregate_call_facts_8616",
]


@dataclass(frozen=True, slots=True)
class DosInterruptAggregateObjectFact8616:
    """One exact ABI argument address joined to a global storage identity."""

    argument_index: int
    base_offset: int
    kind: DosInterruptAbiArgumentKind8616
    canonical_names: tuple[str, ...]
    display_name: str


@dataclass(frozen=True, slots=True)
class DosInterruptAggregateCallFact8616:
    """One fully classified DOS interrupt wrapper call."""

    call: structured_c.CFunctionCall
    contract: DosInterruptAbiContract8616
    objects: tuple[DosInterruptAggregateObjectFact8616, ...]


def _call_name_8616(call: structured_c.CFunctionCall) -> str | None:
    """Return an exact structured external call identity."""
    if isinstance(call.callee_target, str):
        return call.callee_target
    callee = call.callee_func
    if callee is None:
        return None
    try:
        name = cast(Any, callee).name
    except AttributeError:
        return None
    return name if isinstance(name, str) else None


def _summary_for_call_8616(
    call: structured_c.CFunctionCall,
    summaries: Mapping[int, CallsiteSummary8616],
    inventory: Mapping[int, CallsiteSummary8616],
) -> CallsiteSummary8616 | None:
    """Resolve one call to its exact typed summary identity."""
    exact = summaries.get(id(call))
    if exact is not None:
        return exact
    tags = call.tags
    callsite_addr = tags.get("ins_addr") if isinstance(tags, Mapping) else None
    return inventory.get(callsite_addr) if isinstance(callsite_addr, int) else None


def _source_immediate_8616(source: object) -> int | None:
    """Return one exact immediate push source from a typed summary tuple."""
    if not isinstance(source, tuple) or len(source) < 2 or source[0] != "imm":
        return None
    value = source[1]
    return value & 0xFFFF if isinstance(value, int) else None


def _object_fact_8616(
    argument_index: int,
    base_offset: int,
    kind: DosInterruptAbiArgumentKind8616,
    evidence: tuple[IndexedSegmentedGlobalEvidence8616, ...],
    identities: tuple[CodGlobalIdentityFact8616, ...],
) -> DosInterruptAggregateObjectFact8616:
    """Join one ABI object address to optional canonical and display names."""
    canonical_names = tuple(
        dict.fromkeys(
            item.name
            for item in evidence
            if ((item.base_offset - item.relative_disp) & 0xFFFF) == base_offset
        )
    )
    aliases = tuple(
        dict.fromkeys(
            fact.source_alias
            for fact in identities
            if fact.canonical_name in canonical_names
        )
    )
    display_name = aliases[0] if len(aliases) == 1 else f"g_{base_offset:04X}"
    return DosInterruptAggregateObjectFact8616(
        argument_index,
        base_offset,
        kind,
        canonical_names,
        display_name,
    )


def collect_dos_interrupt_aggregate_call_facts_8616(
    root: object,
    summaries: Mapping[int, CallsiteSummary8616],
    inventory: Mapping[int, CallsiteSummary8616],
    evidence: tuple[IndexedSegmentedGlobalEvidence8616, ...],
    identities: tuple[CodGlobalIdentityFact8616, ...],
) -> tuple[int, int, tuple[DosInterruptAggregateCallFact8616, ...]]:
    """Collect fully classified calls plus raw and normalized fact counts."""
    raw_count = 0
    normalized_count = 0
    facts: list[DosInterruptAggregateCallFact8616] = []
    calls = (
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, structured_c.CFunctionCall)
    )
    for call in calls:
        contract = dos_interrupt_abi_contract_8616(_call_name_8616(call))
        if contract is None:
            continue
        raw_count += 1
        summary = _summary_for_call_8616(call, summaries, inventory)
        if summary is None or summary.arg_count != len(contract.argument_kinds):
            continue
        sources = tuple(reversed(summary.push_arg_sources))
        if len(sources) != len(contract.argument_kinds):
            continue
        normalized_count += 1
        objects: list[DosInterruptAggregateObjectFact8616] = []
        for index, kind in enumerate(contract.argument_kinds):
            if not kind.is_aggregate:
                continue
            address = _source_immediate_8616(sources[index])
            if address is None:
                objects = []
                break
            objects.append(_object_fact_8616(index, address, kind, evidence, identities))
        expected_objects = sum(kind.is_aggregate for kind in contract.argument_kinds)
        if len(objects) == expected_objects:
            facts.append(DosInterruptAggregateCallFact8616(call, contract, tuple(objects)))
    return raw_count, normalized_count, tuple(facts)
