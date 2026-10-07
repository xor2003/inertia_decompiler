"""Cache repeated linear-carrier decomposition for one Lowering request.

Layer: Types/Lowering.
Responsibility: retain immutable decomposition results for generated virtual
carriers while one structured-C mutation request owns the current AST.
The cache derives no evidence and must be discarded after the request.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass, field

type LinearGlobalCarrierKey8616 = tuple[str, int | str]
type LinearGlobalDecompositionResult8616 = tuple[
    str | None,
    int,
    tuple[tuple[int, object], ...],
]


@dataclass(frozen=True, slots=True)
class LinearGlobalDecompositionCacheLookup8616:
    """Result of one cache lookup where ``None`` is a valid cached refusal."""

    found: bool
    result: LinearGlobalDecompositionResult8616 | None


@dataclass(frozen=True, slots=True)
class LinearGlobalDecompositionCacheStats8616:
    """Closed accounting for request-local carrier decomposition reuse."""

    query_count: int
    hit_count: int
    miss_count: int
    record_count: int

    def __post_init__(self) -> None:
        """Reject incomplete or negative cache accounting."""
        if self.query_count != self.hit_count + self.miss_count:
            raise ValueError("linear-global decomposition cache accounting is not closed")
        if min(self.query_count, self.hit_count, self.miss_count, self.record_count) < 0:
            raise ValueError("linear-global decomposition cache counters must be non-negative")


@dataclass(slots=True)
class LinearGlobalDecompositionCache8616:
    """Request-owned cache keyed by exact generated-carrier identity."""

    _entries: dict[
        LinearGlobalCarrierKey8616,
        LinearGlobalDecompositionResult8616 | None,
    ] = field(default_factory=dict)
    _query_count: int = 0
    _hit_count: int = 0
    _miss_count: int = 0
    _record_count: int = 0

    def lookup(
        self,
        key: LinearGlobalCarrierKey8616,
    ) -> LinearGlobalDecompositionCacheLookup8616:
        """Return an exact cached result without conflating refusal and miss."""
        self._query_count += 1
        if key in self._entries:
            self._hit_count += 1
            return LinearGlobalDecompositionCacheLookup8616(True, self._entries[key])
        self._miss_count += 1
        return LinearGlobalDecompositionCacheLookup8616(False, None)

    def record(
        self,
        key: LinearGlobalCarrierKey8616,
        result: LinearGlobalDecompositionResult8616 | None,
    ) -> None:
        """Record one exact carrier result for this immutable request."""
        self._entries[key] = result
        self._record_count += 1

    def stats(self) -> LinearGlobalDecompositionCacheStats8616:
        """Return immutable closed accounting for this request."""
        return LinearGlobalDecompositionCacheStats8616(
            query_count=self._query_count,
            hit_count=self._hit_count,
            miss_count=self._miss_count,
            record_count=self._record_count,
        )


__all__ = [
    "LinearGlobalCarrierKey8616",
    "LinearGlobalDecompositionCache8616",
    "LinearGlobalDecompositionCacheLookup8616",
    "LinearGlobalDecompositionCacheStats8616",
    "LinearGlobalDecompositionResult8616",
]
