"""Classify Alias-proven indexed addresses by exact access role.

Layer: Alias.
Responsibility: classify direct unscaled dereferences as pointer-relative and
scaled nonzero-base accesses as globally indexed, retaining all other forms as
typed refusals. This module deliberately does not infer aggregate bounds,
layouts, fields, C types, or rendered expressions.
Owns storage identity and exact Alias-domain relationships.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from inertia.pipeline.errors import PipelineHardError

from .indexed_address_access_contracts import (
    IndexedAliasAccessEvidence8616,
    IndexedAliasAccessFact8616,
    IndexedAliasAccessFailureKind8616,
    IndexedAliasAccessRefusal8616,
    IndexedAliasAccessRole8616,
    IndexedAliasAccessStats8616,
)
from .indexed_address_contracts import (
    IndexedAddressAliasEvidence8616,
    IndexedAddressAliasFact8616,
)


def _classify_access_8616(
    source: IndexedAddressAliasFact8616,
) -> IndexedAliasAccessFact8616 | IndexedAliasAccessRefusal8616:
    """Classify one complete Alias fact without inventing aggregate bounds."""
    if not source.complete:
        return IndexedAliasAccessRefusal8616(
            IndexedAliasAccessFailureKind8616.INCOMPLETE_ALIAS_FACT,
            "indexed Alias source fact is incomplete",
            source_fact=source,
        )
    storage = source.storage
    if storage.base_offset == 0 and storage.index_shift == 0:
        return IndexedAliasAccessFact8616(
            source,
            IndexedAliasAccessRole8616.POINTER_RELATIVE,
        )
    if storage.base_offset != 0 and storage.index_shift > 0:
        return IndexedAliasAccessFact8616(
            source,
            IndexedAliasAccessRole8616.GLOBAL_INDEXED,
        )
    return IndexedAliasAccessRefusal8616(
        IndexedAliasAccessFailureKind8616.AMBIGUOUS_ADDRESS_FORM,
        "address form does not distinguish pointer-relative from globally indexed storage",
        source_fact=source,
    )


def classify_indexed_alias_accesses_8616(
    source: IndexedAddressAliasEvidence8616,
) -> IndexedAliasAccessEvidence8616:
    """Classify every closed Alias outcome into one exact role or refusal."""
    if not source.closed:
        raise PipelineHardError(
            "indexed-address Alias evidence is incomplete before access classification",
            layer="alias",
        )
    facts: list[IndexedAliasAccessFact8616] = []
    refusals = [
        IndexedAliasAccessRefusal8616(
            IndexedAliasAccessFailureKind8616.UPSTREAM_REFUSAL,
            f"Alias refused indexed address: {refusal.failure.value}",
            source_refusal=refusal,
        )
        for refusal in source.refusals
    ]
    for source_fact in source.facts:
        classified = _classify_access_8616(source_fact)
        if isinstance(classified, IndexedAliasAccessRefusal8616):
            refusals.append(classified)
        else:
            facts.append(classified)
    materialized = len(facts)
    result = IndexedAliasAccessEvidence8616(
        source.function_addr,
        tuple(facts),
        tuple(refusals),
        IndexedAliasAccessStats8616(
            raw_fact_count=source.stats.raw_fact_count,
            normalized_fact_count=materialized,
            classified_fact_count=materialized,
            materialized_count=materialized,
            failure_count=len(refusals),
        ),
        source,
    )
    if not result.closed:
        raise PipelineHardError(
            "indexed-address Alias access classification has incomplete accounting",
            layer="alias",
        )
    return result


__all__ = ["classify_indexed_alias_accesses_8616"]
