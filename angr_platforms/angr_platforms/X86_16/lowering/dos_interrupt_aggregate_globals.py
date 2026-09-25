"""Coordinate typed DOS interrupt aggregate global materialization.

Layer: Types/Lowering.
Responsibility: replay classified DOS wrapper argument and field facts, record
complete named C types, and enforce the closed evidence loop. Semantic proof
is collected by sibling Lowering modules, never from rendered C or names.

Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from ..c_ast_utils import _replace_c_children_8616
from ..callsite_summary import CallsiteSummary8616, callsite_summary_inventory_8616
from ..pipeline.errors import PipelineHardError
from .cod_global_identity import CodGlobalIdentityFact8616
from .dos_interrupt_abi import (
    DosInterruptAbiArgumentKind8616,
    DosInterruptAggregateTypes8616,
    dos_interrupt_aggregate_type_definitions_8616,
    dos_interrupt_aggregate_types_8616,
)
from .dos_interrupt_aggregate_evidence import (
    DosInterruptAggregateObjectFact8616,
    collect_dos_interrupt_aggregate_call_facts_8616,
)
from .dos_interrupt_aggregate_projection import (
    materialize_dos_interrupt_call_arguments_8616,
    project_dos_interrupt_global_access_8616,
)
from .global_declarations import (
    NamedAggregateDeclarationCType8616,
    replace_global_declaration_spec_from_stronger_typed_evidence_8616,
)
from .indexed_global_evidence import IndexedSegmentedGlobalEvidence8616
from .named_type_definitions import record_named_type_definitions_8616

__all__ = [
    "DosInterruptAggregateMaterializationStats8616",
    "materialize_dos_interrupt_aggregate_globals_8616",
]


@dataclass(frozen=True, slots=True)
class DosInterruptAggregateMaterializationStats8616:
    """Closed evidence loop for DOS interrupt aggregate lowering."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    object_count: int = 0
    argument_count: int = 0
    field_projection_count: int = 0


class _CFunctionSurface8616(Protocol):
    """Third-party C function fields consumed by aggregate lowering."""

    statements: object
    body: object


class _CodegenSurface8616(Protocol):
    """Owned metadata and third-party fields consumed by aggregate lowering."""

    cfunc: _CFunctionSurface8616
    project: Any
    _inertia_callsite_summaries: object
    _inertia_indexed_global_evidence_8616: object
    _inertia_cod_global_identity_facts_8616: object
    _inertia_global_declaration_specs_8616: object
    _inertia_dos_interrupt_aggregate_stats_8616: DosInterruptAggregateMaterializationStats8616


def _root_8616(cfunc: _CFunctionSurface8616) -> object | None:
    """Return the current structured root without reading rendered C."""
    return cfunc.statements if cfunc.statements is not None else cfunc.body


def _typed_summaries_8616(value: object) -> dict[int, CallsiteSummary8616]:
    """Narrow owned summary metadata to its typed mapping contract."""
    if not isinstance(value, Mapping):
        return {}
    return {
        key: summary
        for key, summary in value.items()
        if isinstance(key, int) and isinstance(summary, CallsiteSummary8616)
    }


def _indexed_evidence_8616(value: object) -> tuple[IndexedSegmentedGlobalEvidence8616, ...]:
    """Narrow persistent indexed-global evidence to typed facts."""
    if not isinstance(value, tuple):
        return ()
    return tuple(item for item in value if isinstance(item, IndexedSegmentedGlobalEvidence8616))


def _identity_facts_8616(value: object) -> tuple[CodGlobalIdentityFact8616, ...]:
    """Narrow optional COD alias metadata to typed identity facts."""
    if not isinstance(value, tuple):
        return ()
    return tuple(item for item in value if isinstance(item, CodGlobalIdentityFact8616))


def _record_object_types_8616(
    codegen: object,
    objects: tuple[DosInterruptAggregateObjectFact8616, ...],
) -> bool:
    """Record complete definitions and stronger scalar global declarations."""
    kinds = tuple(dict.fromkeys(obj.kind for obj in objects))
    type_definitions = dos_interrupt_aggregate_type_definitions_8616(kinds)
    changed = record_named_type_definitions_8616(codegen, type_definitions)
    definitions = dict(zip(kinds, type_definitions, strict=True))
    surface = cast(_CodegenSurface8616, codegen)
    declarations_before = surface._inertia_global_declaration_specs_8616
    for obj in tuple(dict.fromkeys(objects)):
        type_name = "REGS" if obj.kind is DosInterruptAbiArgumentKind8616.REGS else "SREGS"
        replace_global_declaration_spec_from_stronger_typed_evidence_8616(
            codegen,
            ctype=NamedAggregateDeclarationCType8616(type_name, definitions[obj.kind], True),
            name=obj.display_name,
            array_len=None,
        )
    return changed or declarations_before != surface._inertia_global_declaration_specs_8616


def _project_interrupt_accesses_8616(
    root: object,
    codegen: object,
    objects: tuple[DosInterruptAggregateObjectFact8616, ...],
    evidence: tuple[IndexedSegmentedGlobalEvidence8616, ...],
    identities: tuple[CodGlobalIdentityFact8616, ...],
    types: DosInterruptAggregateTypes8616,
) -> tuple[bool, int]:
    """Project exact scalar accesses; return ``(changed, projection_count)``."""
    projection_count = 0

    def transform(node: object) -> object:
        """Project exact scalar accesses while preserving whole-object references."""
        nonlocal projection_count
        replacement = project_dos_interrupt_global_access_8616(
            codegen,
            node,
            objects,
            evidence,
            identities,
            types,
        )
        if replacement is not None:
            projection_count += 1
            return replacement
        return node

    def should_process_child(parent: object, attr: str) -> bool:
        """Keep aggregate bases whole beneath references and existing fields."""
        if isinstance(parent, structured_c.CUnaryOp) and parent.op == "Reference" and attr == "operand":
            return False
        return not isinstance(parent, structured_c.CVariableField) or attr != "variable"

    changed = bool(objects) and _replace_c_children_8616(
        root,
        transform,
        should_process_child=should_process_child,
    )
    return changed, projection_count


def materialize_dos_interrupt_aggregate_globals_8616(codegen: object) -> bool:
    """Materialize every fully classified DOS interrupt aggregate call."""
    surface = cast(_CodegenSurface8616, codegen)
    try:
        root = _root_8616(surface.cfunc)
        summary_value = surface._inertia_callsite_summaries
        evidence_value = surface._inertia_indexed_global_evidence_8616
    except AttributeError:
        return False
    if root is None:
        return False
    try:
        identity_value = surface._inertia_cod_global_identity_facts_8616
    except AttributeError:
        identity_value = ()
    summaries = _typed_summaries_8616(summary_value)
    inventory = callsite_summary_inventory_8616(codegen)
    evidence = _indexed_evidence_8616(evidence_value)
    identities = _identity_facts_8616(identity_value)
    raw_count, normalized_count, facts = collect_dos_interrupt_aggregate_call_facts_8616(
        root,
        summaries,
        inventory,
        evidence,
        identities,
    )
    types = dos_interrupt_aggregate_types_8616(surface.project.arch)
    objects = tuple(dict.fromkeys(obj for fact in facts for obj in fact.objects))
    changed = _record_object_types_8616(codegen, objects) if objects else False
    materialized_count = 0
    argument_count = 0
    for fact in facts:
        materialized, call_changed = materialize_dos_interrupt_call_arguments_8616(
            codegen,
            fact,
            types,
        )
        changed = call_changed or changed
        if materialized:
            materialized_count += 1
            argument_count += len(fact.objects)
    projected, projection_count = _project_interrupt_accesses_8616(
        root,
        codegen,
        objects,
        evidence,
        identities,
        types,
    )
    changed = changed or projected
    failure_count = (raw_count - normalized_count) + (len(facts) - materialized_count)
    stats = DosInterruptAggregateMaterializationStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=len(facts),
        materialized_count=materialized_count,
        failure_count=failure_count,
        object_count=len(objects),
        argument_count=argument_count,
        field_projection_count=projection_count,
    )
    surface._inertia_dos_interrupt_aggregate_stats_8616 = stats
    if stats.classified_fact_count > 0 and stats.materialized_count != stats.classified_fact_count:
        raise PipelineHardError(
            "classified DOS interrupt aggregate calls were not fully materialized",
            layer="lowering",
        )
    return changed
