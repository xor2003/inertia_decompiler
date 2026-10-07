"""Widen Alias-proven carry-result stores into one typed stack destination.

Layer: Widening.
Responsibility: consume exact carry-value and destination Alias artifacts, join
the adjacent low/high stack views, and retain one immutable four-byte storage
fact for Types/Lowering. This module does not discover stores or mutate codegen.
Consumes alias-proven storage identity before joining values or propagating widths.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.alias.alias_model_impl import AliasStorageFacts
from inertia.alias.carry_borrow_destinations import (
    CarryBorrowDestinationAliasEvidence8616,
    CarryBorrowDestinationAliasFact8616,
    CarryBorrowDestinationAliasResolution8616,
    CarryBorrowDestinationAliasVerdict8616,
)
from inertia.alias.storage_fact_join import join_adjacent_stack_alias_facts_8616
from inertia.ir.core import IRAddress

from .carry_borrow_values import (
    WideCarryBorrowEvidence8616,
    WideCarryBorrowValue8616,
)


class WideCarryBorrowStorageVerdict8616(StrEnum):
    """Stable Widening outcome for one destination Alias resolution."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class WideCarryBorrowStorageFailure8616(StrEnum):
    """Stable reason an Alias destination cannot become wide storage."""

    ALIAS_REFUSED = "alias_refused"
    FUNCTION_IDENTITY_MISMATCH = "function_identity_mismatch"
    STORAGE_CONTAINMENT_MISMATCH = "storage_containment_mismatch"
    STORAGE_JOIN_FAILED = "storage_join_failed"
    VALUE_PROVENANCE_MISMATCH = "value_provenance_mismatch"


@dataclass(frozen=True, slots=True)
class WideCarryBorrowStorage8616:
    """One wide arithmetic value stored into an exact four-byte stack range."""

    value: WideCarryBorrowValue8616
    destination: CarryBorrowDestinationAliasFact8616
    address: IRAddress
    storage: AliasStorageFacts
    source_versions: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class WideCarryBorrowStorageResolution8616:
    """Materialized wide storage or typed refusal for one Alias destination."""

    alias: CarryBorrowDestinationAliasResolution8616
    verdict: WideCarryBorrowStorageVerdict8616
    value: WideCarryBorrowStorage8616 | None = None
    failure: WideCarryBorrowStorageFailure8616 | None = None


@dataclass(frozen=True, slots=True)
class WideCarryBorrowStorageStats8616:
    """Closed evidence accounting for wide destination candidates."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every Alias destination has one retained outcome."""
        return (
            self.raw_fact_count == self.normalized_fact_count
            and self.raw_fact_count == self.materialized_count + self.failure_count
            and self.classified_fact_count == self.materialized_count
        )


@dataclass(frozen=True, slots=True)
class WideCarryBorrowStorageEvidence8616:
    """Function-level wide destinations and explicit refusals."""

    function_addr: int
    resolutions: tuple[WideCarryBorrowStorageResolution8616, ...]
    stats: WideCarryBorrowStorageStats8616

    @property
    def values(self) -> tuple[WideCarryBorrowStorage8616, ...]:
        """Return materialized wide destinations in deterministic order."""
        return tuple(item.value for item in self.resolutions if item.value is not None)

    @property
    def complete(self) -> bool:
        """Return whether resolution count and evidence accounting are closed."""
        return self.stats.complete and len(self.resolutions) == self.stats.raw_fact_count


def _refusal(
    alias: CarryBorrowDestinationAliasResolution8616,
    failure: WideCarryBorrowStorageFailure8616,
) -> WideCarryBorrowStorageResolution8616:
    return WideCarryBorrowStorageResolution8616(
        alias=alias,
        verdict=WideCarryBorrowStorageVerdict8616.UNKNOWN_REFUSE,
        failure=failure,
    )


def _wide_value_for_alias(
    evidence: WideCarryBorrowEvidence8616,
    fact: CarryBorrowDestinationAliasFact8616,
) -> WideCarryBorrowValue8616 | None:
    matches = tuple(value for value in evidence.values if value.provenance is fact.carry.link)
    return matches[0] if len(matches) == 1 else None


def _materialize(
    wide_values: WideCarryBorrowEvidence8616,
    alias: CarryBorrowDestinationAliasResolution8616,
    fact: CarryBorrowDestinationAliasFact8616,
) -> WideCarryBorrowStorageResolution8616:
    value = _wide_value_for_alias(wide_values, fact)
    if value is None:
        return _refusal(alias, WideCarryBorrowStorageFailure8616.VALUE_PROVENANCE_MISMATCH)
    low = fact.low_store.address
    high = fact.high_store.address
    storage = join_adjacent_stack_alias_facts_8616(
        fact.low_store.storage,
        fact.high_store.storage,
    )
    source_versions = fact.low_store.versions + fact.high_store.versions
    if storage is None or len(source_versions) != low.size + high.size:
        return _refusal(alias, WideCarryBorrowStorageFailure8616.STORAGE_JOIN_FAILED)
    owners = (fact.low_store, fact.high_store)
    if any(
        not storage.contains(owner.storage)
        or any(not owner.storage.contains(item.storage) for item in owner.slices)
        for owner in owners
    ):
        return _refusal(
            alias,
            WideCarryBorrowStorageFailure8616.STORAGE_CONTAINMENT_MISMATCH,
        )
    address = IRAddress(
        space=low.space,
        base=low.base,
        offset=low.offset,
        size=low.size + high.size,
        status=low.status,
        segment_origin=low.segment_origin,
        expr=low.expr,
    )
    return WideCarryBorrowStorageResolution8616(
        alias=alias,
        verdict=WideCarryBorrowStorageVerdict8616.PROVEN,
        value=WideCarryBorrowStorage8616(
            value=value,
            destination=fact,
            address=address,
            storage=storage,
            source_versions=source_versions,
        ),
    )


def widen_carry_borrow_storage_8616(
    wide_values: WideCarryBorrowEvidence8616,
    aliases: CarryBorrowDestinationAliasEvidence8616,
) -> WideCarryBorrowStorageEvidence8616:
    """Join every exact Alias-proven destination while preserving refusals."""
    if wide_values.function_addr != aliases.function_addr:
        resolutions = tuple(
            _refusal(item, WideCarryBorrowStorageFailure8616.FUNCTION_IDENTITY_MISMATCH)
            for item in aliases.resolutions
        )
    else:
        resolutions = tuple(
            _materialize(wide_values, item, item.fact)
            if item.verdict is CarryBorrowDestinationAliasVerdict8616.PROVEN
            and item.fact is not None
            else _refusal(item, WideCarryBorrowStorageFailure8616.ALIAS_REFUSED)
            for item in aliases.resolutions
        )
    materialized = sum(item.value is not None for item in resolutions)
    return WideCarryBorrowStorageEvidence8616(
        function_addr=aliases.function_addr,
        resolutions=resolutions,
        stats=WideCarryBorrowStorageStats8616(
            raw_fact_count=len(resolutions),
            normalized_fact_count=len(resolutions),
            classified_fact_count=materialized,
            materialized_count=materialized,
            failure_count=len(resolutions) - materialized,
        ),
    )


__all__ = [
    "WideCarryBorrowStorage8616",
    "WideCarryBorrowStorageEvidence8616",
    "WideCarryBorrowStorageFailure8616",
    "WideCarryBorrowStorageResolution8616",
    "WideCarryBorrowStorageStats8616",
    "WideCarryBorrowStorageVerdict8616",
    "widen_carry_borrow_storage_8616",
]
