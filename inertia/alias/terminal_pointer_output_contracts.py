"""Typed Alias contracts for terminal pointer-parameter outputs.

Layer: Alias.
Responsibility: retain each Semantics-proven pointer STORE together with the
exact positive-BP parameter storage that supplies its versioned base register.
This module does not inspect CFGs, widen byte lanes, choose types, bind caller
targets, mutate prototypes, or render C.
Owns storage identity and exact overlapping-view ownership.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.semantics.callsite_summary import CallsitePushSourceKind8616

from inertia.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from inertia.semantics.terminal_pointer_output_contracts import (
    TerminalPointerOutputEvidence8616,
    TerminalPointerOutputFact8616,
)

from .register_reaching_source import RegisterReachingSourceResult8616


class TerminalPointerAliasFailure8616(StrEnum):
    """Stable reasons a pointer output has no exact parameter owner."""

    TERMINAL_EVIDENCE_REFUSED = "terminal_evidence_refused"
    BASE_REGISTER_UNAVAILABLE = "base_register_unavailable"
    REACHING_SOURCE_REFUSED = "reaching_source_refused"
    PARAMETER_SOURCE_UNSUPPORTED = "parameter_source_unsupported"
    PARAMETER_SOURCE_CONFLICT = "parameter_source_conflict"


@dataclass(frozen=True, slots=True)
class TerminalPointerAliasFact8616:
    """One pointer output bound to one exact callee parameter storage."""

    terminal_output: TerminalPointerOutputFact8616
    parameter_storage: IRAddress
    reaching_sources: tuple[RegisterReachingSourceResult8616, ...]

    @property
    def complete(self) -> bool:
        """Return whether every STORE site proves the same pointer parameter."""
        parameter = self.parameter_storage
        expected_source = (
            CallsitePushSourceKind8616.BP_VALUE.value,
            parameter.offset,
            parameter.size,
        )
        return bool(
            self.terminal_output.complete
            and parameter.space is MemSpace.SS
            and parameter.base == ("bp",)
            and parameter.offset >= 4
            and parameter.size == 2
            and parameter.status is AddressStatus.STABLE
            and parameter.segment_origin is SegmentOrigin.PROVEN
            and len(self.reaching_sources) == len(self.terminal_output.store_sites)
            and self.reaching_sources
            and all(
                source.source == expected_source
                and source.failure_count == 0
                and source.classified_fact_count == source.materialized_count == 1
                for source in self.reaching_sources
            )
        )


@dataclass(frozen=True, slots=True)
class TerminalPointerAliasStats8616:
    """Closed accounting for Semantics pointer-output parameter binding."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every Semantics fact has one retained Alias fact."""
        return bool(
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            and self.failure_count == 0
        )


@dataclass(frozen=True, slots=True)
class TerminalPointerAliasEvidence8616:
    """Complete parameter bindings or one atomic Alias refusal."""

    function_addr: int
    facts: tuple[TerminalPointerAliasFact8616, ...]
    failure: TerminalPointerAliasFailure8616 | None
    stats: TerminalPointerAliasStats8616
    source: TerminalPointerOutputEvidence8616

    @property
    def complete(self) -> bool:
        """Return whether source identity and every Alias outcome close."""
        return bool(
            self.source.complete
            and self.function_addr == self.source.function_addr
            and self.failure is None
            and self.stats.complete
            and len(self.facts) == len(self.source.facts) == self.stats.materialized_count
            and all(fact.complete for fact in self.facts)
            and tuple(fact.terminal_output for fact in self.facts) == self.source.facts
        )


__all__ = [
    "TerminalPointerAliasEvidence8616",
    "TerminalPointerAliasFact8616",
    "TerminalPointerAliasFailure8616",
    "TerminalPointerAliasStats8616",
]
