"""Project exact indexed IR value copies through Alias storage identity.

Layer: Alias.
Responsibility: resolve both IR copy endpoints to canonical Alias facts and
accept a relation only when both access roles are global-indexed and their
exact stack index range plus shift match. Aggregate family and bound recovery
remain Widening responsibilities.
Owns storage identity and exact Alias-domain relationships.
Widening is out of scope.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from inertia.pipeline.errors import PipelineHardError

from inertia.ir.indexed_address_contracts import IndexedAddressFact8616
from inertia.ir.indexed_address_copy_contracts import (
    IndexedAddressCopyEvidence8616,
    IndexedAddressCopyFact8616,
)

from .indexed_address_access_contracts import (
    IndexedAliasAccessEvidence8616,
    IndexedAliasAccessFact8616,
    IndexedAliasAccessRole8616,
)
from .indexed_address_contracts import (
    IndexedAddressAliasEvidence8616,
    IndexedAddressAliasFact8616,
)
from .indexed_address_copy_contracts import (
    IndexedAliasCopyEvidence8616,
    IndexedAliasCopyFact8616,
    IndexedAliasCopyFailureKind8616,
    IndexedAliasCopyRefusal8616,
    IndexedAliasCopyStats8616,
)


def _alias_endpoint_8616(
    aliases: IndexedAddressAliasEvidence8616,
    source: IndexedAddressFact8616,
    *,
    missing: IndexedAliasCopyFailureKind8616,
    conflict: IndexedAliasCopyFailureKind8616,
) -> IndexedAddressAliasFact8616 | IndexedAliasCopyFailureKind8616:
    """Resolve one IR endpoint to exactly one canonical Alias fact."""
    matches = tuple(fact for fact in aliases.facts if fact.source == source)
    if not matches:
        return missing
    if len(matches) != 1:
        return conflict
    return matches[0]


def _access_endpoint_8616(
    accesses: IndexedAliasAccessEvidence8616,
    source: IndexedAddressAliasFact8616,
    *,
    missing: IndexedAliasCopyFailureKind8616,
) -> IndexedAliasAccessFact8616 | IndexedAliasCopyFailureKind8616:
    """Resolve one Alias endpoint to its exact access-role fact."""
    matches = tuple(fact for fact in accesses.facts if fact.source == source)
    if len(matches) != 1:
        return missing
    return matches[0]


def _refusal_8616(
    source: IndexedAddressCopyFact8616,
    failure: IndexedAliasCopyFailureKind8616,
    detail: str,
) -> IndexedAliasCopyRefusal8616:
    """Return one typed refusal for an IR-proven copy."""
    return IndexedAliasCopyRefusal8616(
        failure,
        detail,
        source_copy=source,
    )


def _project_copy_8616(
    source_copy: IndexedAddressCopyFact8616,
    aliases: IndexedAddressAliasEvidence8616,
    accesses: IndexedAliasAccessEvidence8616,
) -> IndexedAliasCopyFact8616 | IndexedAliasCopyRefusal8616:
    """Project both endpoints and require one exact global index identity."""
    source = _alias_endpoint_8616(
        aliases,
        source_copy.source,
        missing=IndexedAliasCopyFailureKind8616.SOURCE_ALIAS_MISSING,
        conflict=IndexedAliasCopyFailureKind8616.SOURCE_ALIAS_CONFLICT,
    )
    if isinstance(source, IndexedAliasCopyFailureKind8616):
        return _refusal_8616(source_copy, source, "copy source has no unique Alias fact")
    destination = _alias_endpoint_8616(
        aliases,
        source_copy.destination,
        missing=IndexedAliasCopyFailureKind8616.DESTINATION_ALIAS_MISSING,
        conflict=IndexedAliasCopyFailureKind8616.DESTINATION_ALIAS_CONFLICT,
    )
    if isinstance(destination, IndexedAliasCopyFailureKind8616):
        return _refusal_8616(
            source_copy,
            destination,
            "copy destination has no unique Alias fact",
        )
    source_access = _access_endpoint_8616(
        accesses,
        source,
        missing=IndexedAliasCopyFailureKind8616.SOURCE_ACCESS_ROLE_MISSING,
    )
    if isinstance(source_access, IndexedAliasCopyFailureKind8616):
        return _refusal_8616(
            source_copy,
            source_access,
            "copy source has no unique Alias access role",
        )
    destination_access = _access_endpoint_8616(
        accesses,
        destination,
        missing=IndexedAliasCopyFailureKind8616.DESTINATION_ACCESS_ROLE_MISSING,
    )
    if isinstance(destination_access, IndexedAliasCopyFailureKind8616):
        return _refusal_8616(
            source_copy,
            destination_access,
            "copy destination has no unique Alias access role",
        )
    if (
        source_access.role is not IndexedAliasAccessRole8616.GLOBAL_INDEXED
        or destination_access.role is not IndexedAliasAccessRole8616.GLOBAL_INDEXED
    ):
        return _refusal_8616(
            source_copy,
            IndexedAliasCopyFailureKind8616.NON_GLOBAL_ENDPOINT,
            "copy endpoint is pointer-relative rather than globally indexed",
        )
    if source.storage.width != destination.storage.width:
        return _refusal_8616(
            source_copy,
            IndexedAliasCopyFailureKind8616.WIDTH_CONFLICT,
            "copy endpoint Alias widths differ",
        )
    source_range = source.storage.index_source_range
    destination_range = destination.storage.index_source_range
    if (
        source.storage.index_shift != destination.storage.index_shift
        or source_range.space is not destination_range.space
        or source_range.addresses != destination_range.addresses
        or source_range.storage.identity != destination_range.storage.identity
    ):
        return _refusal_8616(
            source_copy,
            IndexedAliasCopyFailureKind8616.INDEX_IDENTITY_CONFLICT,
            "copy endpoints use different Alias index storage or shifts",
        )
    result = IndexedAliasCopyFact8616(
        source_copy,
        source,
        destination,
        source_access,
        destination_access,
    )
    if not result.complete:
        return _refusal_8616(
            source_copy,
            IndexedAliasCopyFailureKind8616.INDEX_IDENTITY_CONFLICT,
            "Alias copy relation is internally inconsistent",
        )
    return result


def project_indexed_address_copies_8616(
    source: IndexedAddressCopyEvidence8616,
    aliases: IndexedAddressAliasEvidence8616,
    accesses: IndexedAliasAccessEvidence8616,
) -> IndexedAliasCopyEvidence8616:
    """Project every IR copy outcome into Alias evidence or a typed refusal."""
    if not source.closed or not aliases.closed or not accesses.closed:
        raise PipelineHardError(
            "indexed copy Alias projection requires closed input evidence",
            layer="alias",
        )
    if (
        source.function_addr != aliases.function_addr
        or source.function_addr != accesses.function_addr
        or aliases.source != source.source
        or accesses.source != aliases
    ):
        raise PipelineHardError(
            "indexed copy Alias projection received incoherent source artifacts",
            layer="alias",
        )
    facts: list[IndexedAliasCopyFact8616] = []
    refusals = [
        IndexedAliasCopyRefusal8616(
            IndexedAliasCopyFailureKind8616.UPSTREAM_REFUSAL,
            f"IR refused indexed copy: {refusal.failure.value}",
            source_refusal=refusal,
        )
        for refusal in source.refusals
    ]
    for source_copy in source.facts:
        projected = _project_copy_8616(source_copy, aliases, accesses)
        if isinstance(projected, IndexedAliasCopyRefusal8616):
            refusals.append(projected)
        else:
            facts.append(projected)
    result = IndexedAliasCopyEvidence8616(
        source.function_addr,
        tuple(facts),
        tuple(refusals),
        IndexedAliasCopyStats8616(
            raw_fact_count=source.stats.raw_fact_count,
            normalized_fact_count=len(facts),
            classified_fact_count=len(facts),
            materialized_count=len(facts),
            failure_count=len(refusals),
        ),
        source,
        aliases,
        accesses,
    )
    if not result.closed:
        raise PipelineHardError(
            "indexed copy Alias projection has incomplete accounting",
            layer="alias",
        )
    return result


__all__ = ["project_indexed_address_copies_8616"]
