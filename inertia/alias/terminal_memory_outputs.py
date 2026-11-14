# cython: language_level=3, infer_types=True
"""Classify exact terminal-memory outputs into segmented Alias owners.

Layer: Alias.
Responsibility: bind every Semantics-proven direct DS/ES output to canonical
Alias storage and select one unique maximal owner for nested overlapping views.
This module does not inspect CFGs, infer values or C types, mutate prototypes,
or render code. Crossing overlaps and incomplete identities remain atomic
refusals. Types/Lowering may consume owners but must retain this proof.
Owns storage identity and exact overlapping-view ownership.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum

from inertia.semantics.terminal_memory_output_contracts import (
    MemoryOutputKey8616,
    TerminalMemoryOutputEvidence8616,
    TerminalMemoryOutputFact8616,
)

from .alias_model_impl import AliasStorageFacts, alias_facts_for_ir_address_8616
from .storage_fact_join import SegmentedAliasRange8616, build_segmented_alias_range_8616
import dataclasses
import operator


class TerminalMemoryAliasDisposition8616(StrEnum):
    """Alias ownership of one exact terminal-memory output view."""

    OWNER = "owner"
    SUBVIEW = "subview"


class TerminalMemoryAliasFailure8616(StrEnum):
    """Stable reasons terminal-memory Alias evidence cannot close."""

    TERMINAL_EVIDENCE_REFUSED = "terminal_evidence_refused"
    STORAGE_FACT_UNAVAILABLE = "storage_fact_unavailable"
    RANGE_BUILD_REFUSED = "range_build_refused"
    DUPLICATE_STORAGE = "duplicate_storage"
    CROSSING_OVERLAP = "crossing_overlap"


@dataclasses.dataclass(frozen=True, )
class TerminalMemoryAliasStats8616:
    """Closed evidence accounting for terminal-memory Alias classification."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0

    @property
    def complete(self) -> cython.bint:
        """Return whether every Semantics fact has one retained Alias outcome."""
        return (
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            and self.failure_count == 0
        )


@dataclasses.dataclass(frozen=True, )
class TerminalMemoryAliasFact8616:
    """One exact Semantics output, its Alias range, and maximal owner."""

    terminal_output: TerminalMemoryOutputFact8616
    storage_range: SegmentedAliasRange8616
    owner_range: SegmentedAliasRange8616
    disposition: TerminalMemoryAliasDisposition8616

    @property
    def key(self) -> MemoryOutputKey8616:
        """Return the exact terminal-output storage key."""
        return self.terminal_output.key

    @property
    def is_owner(self) -> cython.bint:
        """Return whether this fact is the canonical maximal range."""
        return self.disposition is TerminalMemoryAliasDisposition8616.OWNER

    @property
    def complete(self) -> cython.bint:
        """Return whether output, storage, and ownership remain coherent."""
        address = self.terminal_output.address
        storage_matches = bool(
            self.terminal_output.complete
            and operator.eq(self.storage_range.addresses, (address,))
            and self.storage_range.space is address.space
            and operator.eq(self.storage_range.offset, address.offset)
            and operator.eq(self.storage_range.size, address.size)
        )
        owner_matches = self.owner_range.contains(self.storage_range)
        disposition_matches = (
            operator.eq(self.storage_range, self.owner_range)
            if self.is_owner
            else operator.ne(self.storage_range, self.owner_range)
        )
        return storage_matches and owner_matches and disposition_matches


@dataclasses.dataclass(frozen=True, )
class TerminalMemoryAliasEvidence8616:
    """Complete Alias ownership facts or one atomic typed refusal."""

    function_addr: cython.longlong
    facts: object
    failure: TerminalMemoryAliasFailure8616 | None
    stats: TerminalMemoryAliasStats8616

    @property
    def complete(self) -> cython.bint:
        """Return whether every input has one coherent retained owner."""
        return (
            self.failure is None
            and self.stats.complete
            and all(fact.complete for fact in iter(self.facts))
        )

    @property
    def canonical_facts(self) -> tuple[TerminalMemoryAliasFact8616, ...]:
        """Return deterministic unique maximal output facts for Lowering."""
        return tuple(fact for fact in iter(self.facts) if fact.is_owner)


@cython.ccall
def _refused_8616(
    function_addr: cython.longlong,
    failure: TerminalMemoryAliasFailure8616,
    raw_count: cython.longlong,
    normalized_count: cython.longlong = 0,
) -> TerminalMemoryAliasEvidence8616:
    """Build one atomic Alias refusal without publishing partial facts."""
    return TerminalMemoryAliasEvidence8616(
        function_addr=function_addr,
        facts=(),
        failure=failure,
        stats=TerminalMemoryAliasStats8616(
            raw_fact_count=max(1, raw_count),
            normalized_fact_count=normalized_count,
            failure_count=1,
        ),
    )


@cython.ccall
def _storage_range_8616(
    output: TerminalMemoryOutputFact8616,
) -> tuple[SegmentedAliasRange8616 | None, TerminalMemoryAliasFailure8616 | None]:
    """Build one exact segmented Alias range from a Semantics output."""
    storage_range: object
    storage = alias_facts_for_ir_address_8616(output.address)
    if not isinstance(storage, AliasStorageFacts):
        return None, TerminalMemoryAliasFailure8616.STORAGE_FACT_UNAVAILABLE
    storage_range = build_segmented_alias_range_8616((output.address,), (storage,))
    if storage_range is None:
        return None, TerminalMemoryAliasFailure8616.RANGE_BUILD_REFUSED
    return storage_range, None


def classify_terminal_memory_output_aliases_8616(
    evidence: TerminalMemoryOutputEvidence8616,
) -> TerminalMemoryAliasEvidence8616:
    """Classify nested exact outputs while refusing crossing Alias views."""
    failure: object
    storage_range: object
    index: object
    left: object
    output: object
    right: object
    raw_count = max(evidence.stats.raw_fact_count, len(evidence.facts))
    if not evidence.complete:
        return _refused_8616(
            evidence.function_addr,
            TerminalMemoryAliasFailure8616.TERMINAL_EVIDENCE_REFUSED,
            raw_count,
            evidence.stats.normalized_fact_count,
        )
    ordered_outputs = tuple(
        sorted(
            evidence.facts,
            key=lambda fact: (fact.key[0].value, fact.key[1], fact.key[2]),
        )
    )
    if operator.ne(len({output.key for output in iter(ordered_outputs)}), len(ordered_outputs)):
        return _refused_8616(
            evidence.function_addr,
            TerminalMemoryAliasFailure8616.DUPLICATE_STORAGE,
            raw_count,
        )
    ranges: list[SegmentedAliasRange8616] = []
    for output in ordered_outputs:
        storage_range, failure = _storage_range_8616(output)
        if storage_range is None or failure is not None:
            return _refused_8616(
                evidence.function_addr,
                failure or TerminalMemoryAliasFailure8616.RANGE_BUILD_REFUSED,
                raw_count,
                len(ranges),
            )
        ranges.append(storage_range)

    for index, left in enumerate(ranges):
        for right in ranges[index + 1 :]:
            if left.overlaps(right) and not left.contains(right) and not right.contains(left):
                return _refused_8616(
                    evidence.function_addr,
                    TerminalMemoryAliasFailure8616.CROSSING_OVERLAP,
                    raw_count,
                    len(ranges),
                )

    facts: list[TerminalMemoryAliasFact8616] = []
    for output, storage_range in zip(ordered_outputs, ranges, strict=True):
        containers = tuple(candidate for candidate in iter(ranges) if candidate.contains(storage_range))
        owner = max(containers, key=lambda candidate: candidate.size)
        disposition = (
            TerminalMemoryAliasDisposition8616.OWNER
            if operator.eq(owner, storage_range)
            else TerminalMemoryAliasDisposition8616.SUBVIEW
        )
        facts.append(TerminalMemoryAliasFact8616(output, storage_range, owner, disposition))
    count = len(facts)
    return TerminalMemoryAliasEvidence8616(
        function_addr=evidence.function_addr,
        facts=tuple(facts),
        failure=None,
        stats=TerminalMemoryAliasStats8616(count, count, count, count),
    )


__all__ = [
    "TerminalMemoryAliasDisposition8616",
    "TerminalMemoryAliasEvidence8616",
    "TerminalMemoryAliasFact8616",
    "TerminalMemoryAliasFailure8616",
    "TerminalMemoryAliasStats8616",
    "classify_terminal_memory_output_aliases_8616",
]
