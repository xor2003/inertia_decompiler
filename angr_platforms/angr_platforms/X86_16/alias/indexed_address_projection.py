"""Project indexed IR addresses into symbolic Alias storage identities.

Layer: Alias.
Responsibility: bind each indexed DS/ES IR fact to the exact stack Alias range
that supplies its dynamic term while preserving segment, displacement, width,
SSA identity, shift, proof path, and typed refusals. This module deliberately
does not infer bounds, arrays, fields, C types, or rendered expressions.
Owns storage identity and exact Alias-domain relationships.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
Widening and Types/Lowering consume these facts only after Alias proof.
"""

from __future__ import annotations

from collections import Counter
from typing import Protocol, cast

from ..ir.indexed_address_contracts import IndexedAddressEvidence8616, IndexedAddressFact8616
from ..ir.indexed_address_copy_contracts import IndexedAddressCopyEvidence8616
from ..ir.indexed_address_range_contracts import IndexedLoopRangeEvidence8616
from ..pipeline.errors import PipelineHardError
from .alias_model_impl import AliasFailure, AliasStorageFacts, alias_facts_for_ir_address_8616
from .indexed_address_access_classification import classify_indexed_alias_accesses_8616
from .indexed_address_access_contracts import IndexedAliasAccessEvidence8616
from .indexed_address_contracts import (
    IndexedAddressAliasEvidence8616,
    IndexedAddressAliasFact8616,
    IndexedAddressAliasFailureKind8616,
    IndexedAddressAliasRefusal8616,
    IndexedAddressAliasStats8616,
    IndexedAliasStorage8616,
)
from .indexed_address_copy_contracts import IndexedAliasCopyEvidence8616
from .indexed_address_copy_projection import project_indexed_address_copies_8616
from .indexed_address_range_contracts import IndexedAliasLoopRangeEvidence8616
from .indexed_address_range_projection import project_indexed_loop_ranges_to_alias_8616
from .storage_fact_join import build_segmented_alias_range_8616


class _CodegenBoundary8616(Protocol):
    """Typed IR and Alias artifacts on the dynamic angr codegen boundary."""

    _inertia_vex_ir_function_ssa: object
    _inertia_indexed_address_evidence_8616: IndexedAddressEvidence8616
    _inertia_indexed_address_copy_evidence_8616: IndexedAddressCopyEvidence8616
    _inertia_indexed_loop_range_evidence_8616: IndexedLoopRangeEvidence8616
    _inertia_indexed_address_alias_evidence_8616: IndexedAddressAliasEvidence8616
    _inertia_indexed_address_alias_access_evidence_8616: IndexedAliasAccessEvidence8616
    _inertia_indexed_address_alias_copy_evidence_8616: IndexedAliasCopyEvidence8616
    _inertia_indexed_loop_range_alias_evidence_8616: IndexedAliasLoopRangeEvidence8616


def _source_key_8616(fact: IndexedAddressFact8616) -> tuple[object, ...]:
    """Return the exact machine/SSA identity of one indexed access."""
    return (
        fact.function_addr,
        fact.block_addr,
        fact.instr_index,
        fact.instr_addr,
        fact.kind,
    )


def _project_fact_8616(
    fact: IndexedAddressFact8616,
) -> IndexedAddressAliasFact8616 | IndexedAddressAliasRefusal8616:
    """Project one complete indexed fact without widening its meaning."""
    if not fact.complete:
        return IndexedAddressAliasRefusal8616(
            IndexedAddressAliasFailureKind8616.INCOMPLETE_SOURCE_FACT,
            "indexed IR source fact is incomplete",
            source_fact=fact,
        )
    index_storage = alias_facts_for_ir_address_8616(fact.index_source)
    if isinstance(index_storage, AliasFailure):
        return IndexedAddressAliasRefusal8616(
            IndexedAddressAliasFailureKind8616.INDEX_SOURCE_ALIAS_FAILURE,
            index_storage.reason,
            source_fact=fact,
        )
    if not isinstance(index_storage, AliasStorageFacts):
        return IndexedAddressAliasRefusal8616(
            IndexedAddressAliasFailureKind8616.INDEX_SOURCE_UNCLASSIFIABLE,
            "canonical Alias model did not classify the stack index source",
            source_fact=fact,
        )
    source_range = build_segmented_alias_range_8616(
        (fact.index_source,),
        (index_storage,),
    )
    if source_range is None:
        return IndexedAddressAliasRefusal8616(
            IndexedAddressAliasFailureKind8616.INDEX_SOURCE_RANGE_REFUSED,
            "stack index source did not form one exact segmented Alias range",
            source_fact=fact,
        )
    storage = IndexedAliasStorage8616(
        fact.address.space,
        fact.address.offset & 0xFFFF,
        fact.address.size,
        fact.index_value,
        source_range,
        fact.index_shift,
    )
    projected = IndexedAddressAliasFact8616(fact, storage)
    if not projected.complete:
        return IndexedAddressAliasRefusal8616(
            IndexedAddressAliasFailureKind8616.INCOMPLETE_SOURCE_FACT,
            "indexed IR and symbolic Alias storage disagree",
            source_fact=fact,
        )
    return projected


def project_indexed_address_aliases_8616(
    evidence: IndexedAddressEvidence8616,
) -> IndexedAddressAliasEvidence8616:
    """Project every closed indexed IR outcome into Alias or a typed refusal."""
    if not evidence.closed:
        raise PipelineHardError(
            "indexed-address IR evidence is incomplete before Alias projection",
            layer="alias",
        )
    duplicate_keys = {
        key
        for key, count in Counter(_source_key_8616(fact) for fact in evidence.facts).items()
        if count > 1
    }
    facts: list[IndexedAddressAliasFact8616] = []
    refusals = [
        IndexedAddressAliasRefusal8616(
            IndexedAddressAliasFailureKind8616.UPSTREAM_REFUSAL,
            f"IR refused indexed address: {source.failure.value}",
            source_refusal=source,
        )
        for source in evidence.refusals
    ]
    for source in evidence.facts:
        if _source_key_8616(source) in duplicate_keys:
            refusals.append(
                IndexedAddressAliasRefusal8616(
                    IndexedAddressAliasFailureKind8616.DUPLICATE_ACCESS,
                    "duplicate indexed IR access identity",
                    source_fact=source,
                )
            )
            continue
        projected = _project_fact_8616(source)
        if isinstance(projected, IndexedAddressAliasRefusal8616):
            refusals.append(projected)
        else:
            facts.append(projected)
    materialized = len(facts)
    result = IndexedAddressAliasEvidence8616(
        evidence.function_addr,
        tuple(facts),
        tuple(refusals),
        IndexedAddressAliasStats8616(
            raw_fact_count=evidence.stats.normalized_fact_count,
            normalized_fact_count=materialized,
            classified_fact_count=materialized,
            materialized_count=materialized,
            failure_count=len(refusals),
        ),
        evidence,
    )
    if not result.closed:
        raise PipelineHardError(
            "indexed-address Alias projection has incomplete accounting",
            layer="alias",
        )
    return result


def _required_ir_evidence_8616(
    boundary: _CodegenBoundary8616,
) -> (
    tuple[
        IndexedAddressEvidence8616,
        IndexedAddressCopyEvidence8616,
        IndexedLoopRangeEvidence8616,
    ]
    | None
):
    """Read required IR evidence or return None when no IR owner ran."""
    try:
        source = boundary._inertia_indexed_address_evidence_8616
    except AttributeError as error:
        try:
            boundary._inertia_vex_ir_function_ssa  # noqa: B018
        except AttributeError:
            return None
        raise PipelineHardError(
            "indexed-address IR evidence is missing before Alias projection",
            layer="alias",
        ) from error
    if not isinstance(source, IndexedAddressEvidence8616):
        raise PipelineHardError(
            "indexed-address IR evidence has the wrong pipeline contract",
            layer="alias",
        )
    try:
        copy_source = boundary._inertia_indexed_address_copy_evidence_8616
    except AttributeError as error:
        raise PipelineHardError(
            "indexed-address IR copy evidence is missing before Alias projection",
            layer="alias",
        ) from error
    if not isinstance(copy_source, IndexedAddressCopyEvidence8616):
        raise PipelineHardError(
            "indexed-address IR copy evidence has the wrong pipeline contract",
            layer="alias",
        )
    try:
        range_source = boundary._inertia_indexed_loop_range_evidence_8616
    except AttributeError as error:
        raise PipelineHardError(
            "indexed loop-range IR evidence is missing before Alias projection",
            layer="alias",
        ) from error
    if not isinstance(range_source, IndexedLoopRangeEvidence8616):
        raise PipelineHardError(
            "indexed loop-range IR evidence has the wrong pipeline contract",
            layer="alias",
        )
    return source, copy_source, range_source


def _project_alias_evidence_8616(
    boundary: _CodegenBoundary8616,
    source: IndexedAddressEvidence8616,
    copy_source: IndexedAddressCopyEvidence8616,
    range_source: IndexedLoopRangeEvidence8616,
) -> None:
    """Refresh cached Alias projections when upstream evidence changed."""
    try:
        existing = boundary._inertia_indexed_address_alias_evidence_8616
    except AttributeError:
        existing = None
    if not (
        isinstance(existing, IndexedAddressAliasEvidence8616)
        and existing.source == source
    ):
        existing = project_indexed_address_aliases_8616(source)
        boundary._inertia_indexed_address_alias_evidence_8616 = existing
    try:
        access_evidence = boundary._inertia_indexed_address_alias_access_evidence_8616
    except AttributeError:
        access_evidence = None
    if not (
        isinstance(access_evidence, IndexedAliasAccessEvidence8616)
        and access_evidence.source == existing
    ):
        access_evidence = classify_indexed_alias_accesses_8616(existing)
        boundary._inertia_indexed_address_alias_access_evidence_8616 = access_evidence
    try:
        range_evidence = boundary._inertia_indexed_loop_range_alias_evidence_8616
    except AttributeError:
        range_evidence = None
    if not (
        isinstance(range_evidence, IndexedAliasLoopRangeEvidence8616)
        and range_evidence.source == range_source
        and range_evidence.accesses == access_evidence
    ):
        boundary._inertia_indexed_loop_range_alias_evidence_8616 = (
            project_indexed_loop_ranges_to_alias_8616(
                range_source,
                access_evidence,
            )
        )
    try:
        copy_evidence = boundary._inertia_indexed_address_alias_copy_evidence_8616
    except AttributeError:
        copy_evidence = None
    if not (
        isinstance(copy_evidence, IndexedAliasCopyEvidence8616)
        and copy_evidence.source == copy_source
        and copy_evidence.aliases == existing
        and copy_evidence.accesses == access_evidence
    ):
        boundary._inertia_indexed_address_alias_copy_evidence_8616 = (
            project_indexed_address_copies_8616(
                copy_source,
                existing,
                access_evidence,
            )
        )


def apply_x86_16_indexed_address_aliases_8616(
    project: object,
    codegen: object,
) -> bool:
    """Publish Alias projection and fail if the preceding IR owner is absent."""
    boundary = cast(_CodegenBoundary8616, codegen)
    required = _required_ir_evidence_8616(boundary)
    if required is None:
        return False
    source, copy_source, range_source = required
    _project_alias_evidence_8616(boundary, source, copy_source, range_source)
    return False


__all__ = [
    "apply_x86_16_indexed_address_aliases_8616",
    "project_indexed_address_aliases_8616",
]
