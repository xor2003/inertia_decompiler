"""Recover indexed global tables whose elements are proven near pointers.

Layer: Types/Lowering.
Responsibility: join exact binary call-argument sources with typed structured
arguments to materialize global near-pointer table element types.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Forbidden: name/address allowlists, rendered-C parsing, call repair, or pointer
promotion without an exact global-index/segment pair and a compatible typed
pointer anchor for the same callee argument slot.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall, CIndexedVariable, CVariable
from angr.sim_type import SimType, SimTypeArray, SimTypeFixedSizeArray, SimTypePointer
from angr.sim_variable import SimMemoryVariable
from archinfo import Arch

from ..callsite_summary import CallsitePushSourceKind8616, CallsiteSummary8616
from ..codegen_metadata import GlobalDeclarationArrayExtent8616
from ..pipeline.errors import PipelineHardError
from .global_declarations import (
    replace_global_declaration_spec_from_stronger_typed_evidence_8616,
)

type CallsitePushSource8616 = tuple[object, ...]

__all__ = [
    "CallsitePointerTableStats8616",
    "CallsitePointerTableTypeFact8616",
    "callsite_pointer_table_argument_type_8616",
    "materialize_callsite_pointer_table_types_8616",
]


class _CodegenSurface8616(Protocol):
    """Owned codegen fields required by pointer-table materialization."""

    _inertia_callsite_pointer_table_stats_8616: CallsitePointerTableStats8616
    _inertia_callsite_pointer_table_types_8616: tuple[CallsitePointerTableTypeFact8616, ...]


class _ProjectSurface8616(Protocol):
    """Typed project fields required to bind generated pointer types."""

    arch: Arch


@dataclass(slots=True)
class CallsitePointerTableStats8616:
    """Closed evidence census for indexed global pointer-table promotion."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class CallsitePointerTableTypeFact8616:
    """One proven global storage identity and its pointer element type."""

    base_offset: int
    name: str
    pointer_type: SimTypePointer


@dataclass(frozen=True, slots=True)
class _PointerTableCandidate8616:
    """One exact indexed-global call argument awaiting pointee evidence."""

    node: CIndexedVariable
    base: CVariable
    name: str
    array_len: GlobalDeclarationArrayExtent8616
    base_offset: int


def _argument_type_8616(argument: object) -> SimType | None:
    """Return one structured argument type at the third-party AST boundary."""
    try:
        argument_type = cast(CVariable, argument).type
    except AttributeError:
        return None
    return argument_type if isinstance(argument_type, SimType) else None


def _pointer_anchor_pointee_8616(argument: object) -> SimType | None:
    """Return a pointee type only from an explicit pointer or array argument."""
    argument_type = _argument_type_8616(argument)
    if isinstance(argument_type, SimTypePointer):
        return argument_type.pts_to
    if isinstance(argument_type, (SimTypeArray, SimTypeFixedSizeArray)):
        return argument_type.elem_type
    return None


def _source_kind_8616(source: CallsitePushSource8616 | None) -> str | None:
    """Return the typed source-kind field from one binary push fact."""
    if not isinstance(source, tuple) or not source or not isinstance(source[0], str):
        return None
    return source[0]


def _has_segment_companion_8616(
    sources: tuple[CallsitePushSource8616 | None, ...],
    index: int,
) -> bool:
    """Return whether the following source argument is an exact segment push."""
    companion_index = index + 1
    if companion_index >= len(sources):
        return False
    companion = sources[companion_index]
    if _source_kind_8616(companion) != CallsitePushSourceKind8616.SEGMENT.value:
        return False
    return (
        isinstance(companion, tuple)
        and len(companion) >= 2
        and isinstance(companion[1], str)
        and companion[1].lower() in {"cs", "ds", "es", "ss"}
    )


def _indexed_global_candidate_8616(
    argument: object,
    source: CallsitePushSource8616 | None,
) -> _PointerTableCandidate8616 | None:
    """Join one structured global index with its exact binary push source."""
    if not isinstance(argument, CIndexedVariable):
        return None
    if not isinstance(source, tuple) or len(source) < 3:
        return None
    if source[0] != CallsitePushSourceKind8616.GLOBAL_INDEX_VALUE.value:
        return None
    base_offset, width = source[1:3]
    if not isinstance(base_offset, int) or not isinstance(width, int) or width != 2:
        return None
    base = argument.variable
    if not isinstance(base, CVariable) or not isinstance(base.variable, SimMemoryVariable):
        return None
    if not isinstance(base.variable.addr, int) or (base.variable.addr & 0xFFFF) != (base_offset & 0xFFFF):
        return None
    name = base.name
    if not isinstance(name, str) or not name:
        return None
    return _PointerTableCandidate8616(
        argument,
        base,
        name,
        GlobalDeclarationArrayExtent8616.UNKNOWN,
        base_offset & 0xFFFF,
    )


def _compatible_pointee_8616(types: Sequence[SimType]) -> SimType | None:
    """Join pointer anchors only when their structured pointee types agree."""
    if not types:
        return None
    first = types[0]
    return first if all(candidate == first for candidate in types[1:]) else None


def callsite_pointer_table_argument_type_8616(
    codegen: object,
    argument: object,
) -> SimTypePointer | None:
    """Return a proven pointer-table element type for one indexed argument."""
    if not isinstance(argument, CIndexedVariable) or not isinstance(argument.variable, CVariable):
        return None
    base = argument.variable
    if not isinstance(base.variable, SimMemoryVariable) or not isinstance(base.variable.addr, int):
        return None
    name = base.name
    if not isinstance(name, str):
        return None
    surface = cast(_CodegenSurface8616, codegen)
    try:
        facts = surface._inertia_callsite_pointer_table_types_8616
    except AttributeError:
        return None
    matches = tuple(
        fact.pointer_type
        for fact in facts
        if fact.base_offset == (base.variable.addr & 0xFFFF) and fact.name == name
    )
    if not matches or any(candidate != matches[0] for candidate in matches[1:]):
        return None
    return matches[0]


def _collect_call_slot_evidence_8616(
    call: CFunctionCall,
    summary: CallsiteSummary8616,
    stats: CallsitePointerTableStats8616,
    candidates_by_slot: dict[tuple[int, int], list[_PointerTableCandidate8616]],
    anchors_by_slot: dict[tuple[int, int], list[SimType]],
) -> None:
    """Collect indexed candidates and anchor pointees from one resolved call."""
    args = tuple(cast(Sequence[object], call.args or ()))
    push_sources = cast(
        tuple[CallsitePushSource8616 | None, ...],
        tuple(reversed(summary.push_arg_sources)),
    )
    stats.raw_fact_count += len(args)
    if not isinstance(summary.target_addr, int) or len(push_sources) != len(args):
        stats.failure_count += 1
        return
    for index, (argument, source) in enumerate(zip(args, push_sources, strict=True)):
        if not _has_segment_companion_8616(push_sources, index):
            continue
        slot = (summary.target_addr, index)
        source_kind = _source_kind_8616(source)
        candidate = _indexed_global_candidate_8616(argument, source)
        if candidate is not None:
            stats.normalized_fact_count += 1
            candidates_by_slot.setdefault(slot, []).append(candidate)
            continue
        if source_kind not in {
            CallsitePushSourceKind8616.BP_ADDRESS.value,
            CallsitePushSourceKind8616.BP_INDEX_ADDRESS.value,
        }:
            continue
        pointee = _pointer_anchor_pointee_8616(argument)
        if pointee is not None:
            stats.normalized_fact_count += 1
            anchors_by_slot.setdefault(slot, []).append(pointee)


def _materialize_slot_candidates_8616(
    codegen: object,
    project_surface: _ProjectSurface8616,
    candidates: list[_PointerTableCandidate8616],
    anchors: Sequence[SimType],
    stats: CallsitePointerTableStats8616,
    materialized_facts: list[CallsitePointerTableTypeFact8616],
) -> None:
    """Materialize one slot's candidates under its compatible pointee type."""
    pointee = _compatible_pointee_8616(anchors)
    if pointee is None:
        stats.failure_count += len(candidates)
        return
    pointer_type = cast(SimTypePointer, SimTypePointer(pointee).with_arch(project_surface.arch))
    ctype = pointer_type.c_repr(name="").strip()
    for candidate in candidates:
        stats.classified_fact_count += 1
        materialized_facts.append(
            CallsitePointerTableTypeFact8616(candidate.base_offset, candidate.name, pointer_type)
        )
        replace_global_declaration_spec_from_stronger_typed_evidence_8616(
            codegen,
            ctype=ctype,
            name=candidate.name,
            array_len=candidate.array_len,
        )
        stats.materialized_count += 1


def materialize_callsite_pointer_table_types_8616(
    project: object,
    codegen: object,
    resolved_calls: Iterable[tuple[CFunctionCall, CallsiteSummary8616]],
) -> bool:
    """Materialize globally indexed near-pointer elements from closed evidence.

    Binary summaries establish the physical global-index plus segment pair.
    Structured pointer or array arguments to the same target and slot establish
    the pointee type. Unknown or conflicting anchors leave the scalar table
    unchanged.
    """
    stats = CallsitePointerTableStats8616()
    candidates_by_slot: dict[tuple[int, int], list[_PointerTableCandidate8616]] = {}
    anchors_by_slot: dict[tuple[int, int], list[SimType]] = {}

    for call, summary in resolved_calls:
        _collect_call_slot_evidence_8616(
            call, summary, stats, candidates_by_slot, anchors_by_slot
        )

    codegen_surface = cast(_CodegenSurface8616, codegen)
    project_surface = cast(_ProjectSurface8616, project)
    try:
        previous_facts = codegen_surface._inertia_callsite_pointer_table_types_8616
    except AttributeError:
        previous_facts = ()
    materialized_facts: list[CallsitePointerTableTypeFact8616] = []
    for slot, candidates in candidates_by_slot.items():
        _materialize_slot_candidates_8616(
            codegen,
            project_surface,
            candidates,
            anchors_by_slot.get(slot, ()),
            stats,
            materialized_facts,
        )

    unique_facts = tuple(dict.fromkeys(materialized_facts))
    codegen_surface._inertia_callsite_pointer_table_types_8616 = unique_facts
    changed = unique_facts != previous_facts
    codegen_surface._inertia_callsite_pointer_table_stats_8616 = stats
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError("classified callsite pointer-table facts were not materialized")
    return changed
