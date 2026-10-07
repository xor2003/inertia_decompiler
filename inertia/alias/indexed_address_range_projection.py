"""Project bounded indexed-address IR ranges onto canonical Alias storage.

Layer: Alias.
Responsibility: resolve each accepted IR loop range to the exact existing
global indexed access and verify its canonical stack Alias identity. This pass
does not choose element counts, widen extents, or repair missing IR evidence.
Owns storage identity.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from inertia.ir.indexed_address_range_contracts import (
    IndexedLoopRangeEvidence8616,
    IndexedLoopRangeFact8616,
    canonical_induction_source_identity_8616,
)

from .indexed_address_access_contracts import (
    IndexedAliasAccessEvidence8616,
    IndexedAliasAccessFact8616,
    IndexedAliasAccessRole8616,
)
from .indexed_address_range_contracts import (
    IndexedAliasLoopRangeEvidence8616,
    IndexedAliasLoopRangeFact8616,
    IndexedAliasLoopRangeRefusal8616,
    IndexedAliasLoopRangeStats8616,
    IndexedLoopRangeAliasFailureKind8616,
)


def _refusal_8616(
    source: IndexedLoopRangeFact8616,
    failure: IndexedLoopRangeAliasFailureKind8616,
    detail: str,
) -> IndexedAliasLoopRangeRefusal8616:
    """Return one typed Alias refusal for an accepted IR range."""
    return IndexedAliasLoopRangeRefusal8616(
        failure,
        detail,
        source_fact=source,
    )


def _matching_accesses_8616(
    source: IndexedLoopRangeFact8616,
    accesses: IndexedAliasAccessEvidence8616,
) -> tuple[IndexedAliasAccessFact8616, ...]:
    """Return exact existing Alias accesses owning the IR indexed fact."""
    return tuple(
        access
        for access in accesses.facts
        if access.source.source == source.source
    )


def _project_fact_8616(
    source: IndexedLoopRangeFact8616,
    accesses: IndexedAliasAccessEvidence8616,
) -> IndexedAliasLoopRangeFact8616 | IndexedAliasLoopRangeRefusal8616:
    """Project one IR range while preserving the existing Alias objects."""
    matches = _matching_accesses_8616(source, accesses)
    if not matches:
        return _refusal_8616(
            source,
            IndexedLoopRangeAliasFailureKind8616.ACCESS_MISSING,
            "IR range has no exact existing Alias access",
        )
    if len(matches) != 1:
        return _refusal_8616(
            source,
            IndexedLoopRangeAliasFailureKind8616.ACCESS_CONFLICT,
            "IR range maps to multiple Alias accesses",
        )
    access = matches[0]
    if not access.complete:
        return _refusal_8616(
            source,
            IndexedLoopRangeAliasFailureKind8616.INCOMPLETE_ACCESS,
            "existing Alias access is incomplete",
        )
    if access.role is not IndexedAliasAccessRole8616.GLOBAL_INDEXED:
        return _refusal_8616(
            source,
            IndexedLoopRangeAliasFailureKind8616.NON_GLOBAL_ACCESS,
            "indexed loop range belongs to a pointer-relative access",
        )
    storage = access.source.storage
    source_range = storage.index_source_range
    alias_identity = source_range.storage.identity
    canonical = canonical_induction_source_identity_8616(source_range.addresses[0])
    if (
        alias_identity is None
        or canonical != source.induction_source
        or len(source_range.addresses) != 1
        or len(source_range.source_facts) != 1
        or source_range.source_facts[0].identity != alias_identity
    ):
        return _refusal_8616(
            source,
            IndexedLoopRangeAliasFailureKind8616.IDENTITY_MISMATCH,
            "IR induction source and canonical Alias stack identity disagree",
        )
    result = IndexedAliasLoopRangeFact8616(
        source,
        access,
        storage,
        alias_identity,
    )
    if not result.complete:
        return _refusal_8616(
            source,
            IndexedLoopRangeAliasFailureKind8616.IDENTITY_MISMATCH,
            "Alias range projection is internally inconsistent",
        )
    return result


def project_indexed_loop_ranges_to_alias_8616(
    source: IndexedLoopRangeEvidence8616,
    accesses: IndexedAliasAccessEvidence8616,
) -> IndexedAliasLoopRangeEvidence8616:
    """Project every closed IR range outcome to one Alias fact or refusal."""
    if not source.closed or not accesses.closed:
        raise ValueError("indexed range Alias projection requires closed inputs")
    if source.function_addr != accesses.function_addr:
        raise ValueError("indexed range Alias projection function mismatch")
    facts: list[IndexedAliasLoopRangeFact8616] = []
    refusals = [
        IndexedAliasLoopRangeRefusal8616(
            IndexedLoopRangeAliasFailureKind8616.UPSTREAM_REFUSAL,
            f"IR refused indexed loop range: {refusal.failure.value}",
            source_refusal=refusal,
        )
        for refusal in source.refusals
    ]
    for source_fact in source.facts:
        projected = _project_fact_8616(source_fact, accesses)
        if isinstance(projected, IndexedAliasLoopRangeRefusal8616):
            refusals.append(projected)
        else:
            facts.append(projected)
    raw_count = source.stats.raw_fact_count
    result = IndexedAliasLoopRangeEvidence8616(
        source.function_addr,
        tuple(facts),
        tuple(refusals),
        IndexedAliasLoopRangeStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=raw_count,
            classified_fact_count=raw_count,
            materialized_count=len(facts),
            failure_count=len(refusals),
        ),
        source,
        accesses,
    )
    if not result.closed:
        raise ValueError("indexed range Alias projection accounting did not close")
    return result


__all__ = ["project_indexed_loop_ranges_to_alias_8616"]
