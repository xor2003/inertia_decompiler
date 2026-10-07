"""Retain callsite semantic lookups for one immutable summary cohort.

Layer: Semantics.
Responsibility: reuse exact terminal stack-cleanup and callee-save evidence,
including typed refusals, only while one complete recovered function catalog is summarized.
Nothing in this request-local cache survives later discovery or project
mutation.

Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

from .terminal_stack_cleanup import TerminalStackCleanupEvidence8616

__all__ = [
    "CallsiteCleanupProjectRole8616",
    "CallsiteSummaryRequestCache8616",
    "CallsiteSummaryRequestStats8616",
]


class CallsiteCleanupProjectRole8616(StrEnum):
    """Stable project roles consulted by callsite cleanup recovery."""

    CURRENT = "current"
    ORIGINAL = "original"


@dataclass(frozen=True, slots=True)
class CallsiteSummaryRequestStats8616:
    """Closed accounting for request-local semantic lookup reuse."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    build_count: int
    reuse_count: int

    def validate(self) -> None:
        """Reject negative or open request accounting."""
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
            self.build_count,
            self.reuse_count,
        )
        if any(count < 0 for count in counts):
            raise ValueError("callsite summary request counters must be nonnegative")
        if not (
            self.raw_fact_count == self.normalized_fact_count
            and self.normalized_fact_count
            == self.materialized_count + self.failure_count
            and self.classified_fact_count == self.materialized_count
            and self.materialized_count == self.build_count + self.reuse_count
        ):
            raise ValueError("callsite summary request accounting does not close")


@dataclass(slots=True)
class CallsiteSummaryRequestCache8616:
    """Cache exact callsite semantics during one immutable summary request."""

    _cleanup_by_key: dict[
        tuple[CallsiteCleanupProjectRole8616, int],
        TerminalStackCleanupEvidence8616,
    ] = field(default_factory=dict)
    _frame_pushes_by_function_identity: dict[
        int,
        tuple[object, frozenset[int]],
    ] = field(default_factory=dict)
    _raw_fact_count: int = 0
    _build_count: int = 0
    _reuse_count: int = 0
    _failure_count: int = 0

    def terminal_cleanup(
        self,
        role: CallsiteCleanupProjectRole8616,
        address: int,
        collector: Callable[[], TerminalStackCleanupEvidence8616],
    ) -> TerminalStackCleanupEvidence8616:
        """Return one exact proof or refusal, collecting it at most once."""
        if not isinstance(address, int) or address < 0:
            raise ValueError("terminal cleanup request address must be nonnegative")
        self._raw_fact_count += 1
        key = (role, address)
        cached = self._cleanup_by_key.get(key)
        if cached is not None:
            self._reuse_count += 1
            return cached
        try:
            evidence = collector()
        except Exception:
            self._failure_count += 1
            raise
        if not isinstance(evidence, TerminalStackCleanupEvidence8616):
            self._failure_count += 1
            raise TypeError("terminal cleanup collector returned the wrong type")
        self._cleanup_by_key[key] = evidence
        self._build_count += 1
        return evidence

    def callee_saved_frame_pushes(
        self,
        function: object,
        collector: Callable[[], frozenset[int]],
    ) -> frozenset[int]:
        """Return one function's proven frame pushes, collecting them once."""
        self._raw_fact_count += 1
        key = id(function)
        cached = self._frame_pushes_by_function_identity.get(key)
        if cached is not None and cached[0] is function:
            self._reuse_count += 1
            return cached[1]
        try:
            addresses = collector()
        except Exception:
            self._failure_count += 1
            raise
        if not isinstance(addresses, frozenset) or any(
            not isinstance(address, int) or address < 0 for address in addresses
        ):
            self._failure_count += 1
            raise TypeError("callee-saved frame pushes must be nonnegative integers")
        self._frame_pushes_by_function_identity[key] = (function, addresses)
        self._build_count += 1
        return addresses

    def stats(self) -> CallsiteSummaryRequestStats8616:
        """Return validated closed accounting for this request."""
        materialized = self._build_count + self._reuse_count
        stats = CallsiteSummaryRequestStats8616(
            raw_fact_count=self._raw_fact_count,
            normalized_fact_count=self._raw_fact_count,
            classified_fact_count=materialized,
            materialized_count=materialized,
            failure_count=self._failure_count,
            build_count=self._build_count,
            reuse_count=self._reuse_count,
        )
        stats.validate()
        return stats
