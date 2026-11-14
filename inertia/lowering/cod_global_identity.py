# cython: language_level=3, infer_types=True
"""Preserve unique COD global identities through declaration reconciliation.

Layer: Types/Lowering.
Responsibility: retain compiler-unique static storage names while carrying COD
source aliases as optional display evidence.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, cast

from inertia.frontend.x86_16.cod_extract import CODGlobalRef, CODProcMetadata
from inertia.lowering.codegen_metadata import (
    GlobalDeclarationArrayExtent8616,
    GlobalDeclarationArrayLength8616,
)
from inertia.pipeline.errors import PipelineHardError

from .global_declarations import (
    merge_global_array_extents_8616,
    record_global_declaration_spec_8616,
)
from .global_symbol_names import (
    DSGlobalSymbolNameFact8616,
    reconcile_ds_global_local_declarations_8616,
    synchronize_ds_global_symbol_names_8616,
)
import dataclasses
import operator
import builtins

__all__ = [
    "CodGlobalIdentityStats8616",
    "CodGlobalStorageSurface8616",
    "reconcile_recorded_cod_global_storage_identities_8616",
    "record_cod_global_storage_identities_8616",
]


@dataclasses.dataclass(frozen=True, )
class CodGlobalStorageSurface8616:
    """One exact DS storage surface with its canonical compiler symbol."""

    offset: cython.longlong
    width: cython.longlong
    canonical_name: object


@dataclasses.dataclass(frozen=True, )
class CodGlobalIdentityFact8616:
    """One exact storage identity joined to an optional COD display alias."""

    offset: cython.longlong
    width: cython.longlong
    canonical_name: object
    source_alias: object
    source_ctype: object = None
    source_array_len: GlobalDeclarationArrayLength8616 = None


@dataclasses.dataclass(frozen=True, )
class CodGlobalIdentityStats8616:
    """Closed evidence counters for COD global identity preservation."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0


class _CodGlobalIdentityCodegen8616(Protocol):
    """Owned metadata fields used across Lowering and final rendering."""

    _inertia_cod_global_identity_facts_8616: object
    _inertia_cod_global_identity_stats_8616: CodGlobalIdentityStats8616
    _inertia_global_declaration_specs_8616: object
    _inertia_strong_global_declaration_specs_8616: object


def _cod_alias_pairs_8616(
    metadata: object,
) -> tuple[tuple[str, str], ...]:
    """Return explicit canonical/display pairs from owned COD metadata."""
    if metadata is None:
        return ()
    return tuple(
        (ref.name, ref.source_alias)
        for ref in iter(metadata.global_refs)
        if isinstance(ref, CODGlobalRef)
        and isinstance(ref.source_alias, str)
        and bool(ref.source_alias)
        and operator.ne(ref.source_alias, ref.name)
    )


def _unambiguous_aliases_8616(
    pairs: Iterable[tuple[str, str]],
) -> tuple[dict[str, str], cython.longlong]:
    """Return one-to-one aliases and the number of ambiguous pairs refused."""
    canonical_name: object
    source_alias: object
    canonical_to_aliases: dict[str, set[str]] = {}
    alias_to_canonicals: dict[str, set[str]] = {}
    pair_tuple = tuple(dict.fromkeys(pairs))
    for canonical_name, source_alias in pair_tuple:
        canonical_to_aliases.setdefault(canonical_name, set()).add(source_alias)
        alias_to_canonicals.setdefault(source_alias, set()).add(canonical_name)
    aliases = {
        canonical_name: next(iter(source_aliases))
        for canonical_name, source_aliases in builtins.iter(canonical_to_aliases.items())
        if len(source_aliases) == 1
        and len(alias_to_canonicals[next(iter(source_aliases))]) == 1
    }
    accepted = sum(1 for canonical_name, _source_alias in iter(pair_tuple) if canonical_name in aliases)
    return aliases, len(pair_tuple) - accepted


def _declaration_specs_8616(
    codegen: _CodGlobalIdentityCodegen8616,
) -> tuple[tuple[str, str, GlobalDeclarationArrayLength8616], ...]:
    """Return normalized owned global declaration specs."""
    try:
        raw_specs = codegen._inertia_global_declaration_specs_8616
    except AttributeError:
        return ()
    return tuple(
        (ctype, name, array_len)
        for ctype, name, array_len in iter(raw_specs)
        if isinstance(ctype, str)
        and isinstance(name, str)
        and (
            array_len is None
            or isinstance(array_len, int)
            or array_len is GlobalDeclarationArrayExtent8616.UNKNOWN
        )
    )


def _rebind_declaration_alias_8616(
    codegen: _CodGlobalIdentityCodegen8616,
    fact: CodGlobalIdentityFact8616,
) -> cython.bint:
    """Merge one canonical declaration into its proven source display alias."""
    _name: object
    array_len: object
    ctype: object
    try:
        strong_specs = codegen._inertia_strong_global_declaration_specs_8616
    except AttributeError:
        strong_specs = ()
    canonical_strong = tuple(spec for spec in iter(strong_specs) if operator.eq(spec[1], fact.canonical_name))
    alias_strong = tuple(spec for spec in iter(strong_specs) if operator.eq(spec[1], fact.source_alias))
    rebound_strong = tuple(
        (ctype, fact.source_alias, array_len)
        for ctype, _name, array_len in iter(canonical_strong)
    )
    if canonical_strong and alias_strong and operator.ne(set(rebound_strong), set(alias_strong)):
        raise PipelineHardError(
            "conflicting strong declarations for one COD global identity: "
            f"canonical={fact.canonical_name!r} alias={fact.source_alias!r}"
        )
    if canonical_strong:
        retained_strong = tuple(
            spec
            for spec in iter(strong_specs)
            if spec[1] not in {fact.canonical_name, fact.source_alias}
        )
        codegen._inertia_strong_global_declaration_specs_8616 = tuple(
            dict.fromkeys(tuple(retained_strong) + tuple(rebound_strong) + tuple(alias_strong))
        )
    before = _declaration_specs_8616(codegen)
    current_alias_specs = tuple(spec for spec in iter(before) if operator.eq(spec[1], fact.source_alias))
    persisted_alias_specs = (
        tuple(((fact.source_ctype, fact.source_alias, fact.source_array_len),))
        if isinstance(fact.source_ctype, str) and fact.source_ctype
        else tuple(())
    )
    alias_specs = tuple(dict.fromkeys(tuple(persisted_alias_specs) + tuple(current_alias_specs)))
    canonical_specs = tuple(spec for spec in iter(before) if operator.eq(spec[1], fact.canonical_name))
    if not alias_specs and not canonical_specs:
        return False
    codegen._inertia_global_declaration_specs_8616 = tuple(
        spec
        for spec in iter(before)
        if spec[1] not in {fact.source_alias, fact.canonical_name}
    )
    # Alias declarations carry the optional source type and aggregate extent.
    # Record them first so equal-width generic canonical declarations cannot
    # replace stronger source-side signedness or array shape.
    for ctype, _name, array_len in tuple(alias_specs) + tuple(canonical_specs):
        record_global_declaration_spec_8616(
            codegen,
            ctype=ctype,
            name=fact.source_alias,
            array_len=array_len,
        )
    return operator.ne(_declaration_specs_8616(codegen), before)


def _source_declaration_for_alias_8616(
    codegen: _CodGlobalIdentityCodegen8616,
    source_alias: object,
) -> tuple[str | None, GlobalDeclarationArrayLength8616]:
    """Return the strongest currently recorded declaration for one COD alias."""
    candidates = tuple(
        spec
        for spec in builtins.iter(_declaration_specs_8616(codegen))
        if operator.eq(spec[1], source_alias)
    )
    if not candidates:
        return None, None
    ctype, _name, array_len = max(
        candidates,
        key=lambda spec: (
            int(spec[2]) if isinstance(spec[2], int) else 0,
            len(spec[0]),
            spec[0],
        ),
    )
    return ctype, array_len


@cython.ccall
def _merge_identity_facts_8616(
    facts: Iterable[CodGlobalIdentityFact8616],
) -> tuple[CodGlobalIdentityFact8616, ...]:
    """Merge repeated lifecycle observations without losing declaration shape."""
    previous: object
    fact: object
    merged: dict[tuple[cython.longlong, cython.longlong, str, str], CodGlobalIdentityFact8616] = {}
    for fact in facts:
        key = (
            fact.offset,
            fact.width,
            fact.canonical_name,
            fact.source_alias,
        )
        previous = merged.get(key)
        if previous is None:
            merged[key] = fact
            continue
        source_ctype = previous.source_ctype or fact.source_ctype
        source_array_len = merge_global_array_extents_8616(
            previous.source_array_len,
            fact.source_array_len,
        )
        merged[key] = CodGlobalIdentityFact8616(
            offset=fact.offset,
            width=fact.width,
            canonical_name=fact.canonical_name,
            source_alias=fact.source_alias,
            source_ctype=source_ctype,
            source_array_len=source_array_len,
        )
    return tuple(merged.values())
def reconcile_recorded_cod_global_storage_identities_8616(codegen: object) -> cython.bint:
    """Reapply persistent unambiguous display aliases after AST rebuilding."""
    fact: object
    typed_codegen = cast(_CodGlobalIdentityCodegen8616, codegen)
    try:
        raw_facts = typed_codegen._inertia_cod_global_identity_facts_8616
    except AttributeError:
        raw_facts = ()
    facts = tuple(
        dict.fromkeys(
            fact
            for fact in iter(raw_facts)
            if isinstance(fact, CodGlobalIdentityFact8616)
            and fact.width > 0
            and bool(fact.canonical_name)
            and bool(fact.source_alias)
        )
    )
    if not facts:
        return False
    name_facts = tuple(
        DSGlobalSymbolNameFact8616(
            offset=fact.offset & 0xFFFF,
            width=fact.width,
            name=fact.source_alias,
        )
        for fact in iter(facts)
    )
    changed = bool(synchronize_ds_global_symbol_names_8616(codegen, name_facts))
    changed = reconcile_ds_global_local_declarations_8616(codegen, name_facts) or changed
    for fact in facts:
        changed = _rebind_declaration_alias_8616(typed_codegen, fact) or changed
    try:
        previous_stats = typed_codegen._inertia_cod_global_identity_stats_8616
    except AttributeError:
        previous_stats = CodGlobalIdentityStats8616(
            normalized_fact_count=len(facts),
            classified_fact_count=len(facts),
        )
    typed_codegen._inertia_cod_global_identity_stats_8616 = CodGlobalIdentityStats8616(
        raw_fact_count=previous_stats.raw_fact_count,
        normalized_fact_count=previous_stats.normalized_fact_count,
        classified_fact_count=len(facts),
        materialized_count=len(facts),
        failure_count=previous_stats.failure_count,
    )
    return changed


@cython.ccall
def record_cod_global_storage_identities_8616(
    codegen: object,
    metadata: CODProcMetadata | None,
    surfaces: Iterable[CodGlobalStorageSurface8616],
) -> cython.bint:
    """Join exact storage surfaces to COD aliases and persist display names."""
    surface: object
    typed_codegen = cast(_CodGlobalIdentityCodegen8616, codegen)
    pairs = _cod_alias_pairs_8616(metadata)
    aliases, ambiguous_count = _unambiguous_aliases_8616(pairs)
    surface_tuple = tuple(dict.fromkeys(surfaces))
    facts: list[CodGlobalIdentityFact8616] = []
    for surface in surface_tuple:
        if surface.width <= 0 or surface.canonical_name not in aliases:
            continue
        source_alias = aliases[surface.canonical_name]
        source_ctype, source_array_len = _source_declaration_for_alias_8616(
            typed_codegen,
            source_alias,
        )
        facts.append(
            CodGlobalIdentityFact8616(
                offset=surface.offset & 0xFFFF,
                width=surface.width,
                canonical_name=surface.canonical_name,
                source_alias=source_alias,
                source_ctype=source_ctype,
                source_array_len=source_array_len,
            )
        )
    try:
        previous = typed_codegen._inertia_cod_global_identity_facts_8616
    except AttributeError:
        previous = ()
    typed_codegen._inertia_cod_global_identity_facts_8616 = _merge_identity_facts_8616(
        tuple(previous) + tuple(facts)
    )
    typed_codegen._inertia_cod_global_identity_stats_8616 = (
        CodGlobalIdentityStats8616(
            raw_fact_count=len(pairs),
            normalized_fact_count=len(aliases),
            classified_fact_count=len(facts),
            materialized_count=0,
            failure_count=ambiguous_count,
        )
    )
    return reconcile_recorded_cod_global_storage_identities_8616(codegen)
