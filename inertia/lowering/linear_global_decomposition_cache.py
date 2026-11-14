# cython: language_level=3, infer_types=True
"""Cache repeated linear-carrier decomposition for one Lowering request.

Layer: Types/Lowering.
Responsibility: retain immutable decomposition results for generated virtual
carriers while one structured-C mutation request owns the current AST.
The cache derives no evidence and must be discarded after the request.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass, field
import dataclasses
import operator

LinearGlobalCarrierKey8616 = typing.TypeAliasType("LinearGlobalCarrierKey8616", tuple[str, int | str])
LinearGlobalDecompositionResult8616 = typing.TypeAliasType("LinearGlobalDecompositionResult8616", tuple[
    str | None,
    int,
    tuple[tuple[int, object], ...],
])


@dataclasses.dataclass(frozen=True, )
class LinearGlobalDecompositionCacheLookup8616:
    """Result of one cache lookup where ``None`` is a valid cached refusal."""

    found: cython.bint
    result: LinearGlobalDecompositionResult8616 | None


@dataclasses.dataclass(frozen=True, )
class LinearGlobalDecompositionCacheStats8616:
    """Closed accounting for request-local carrier decomposition reuse."""

    query_count: cython.longlong
    hit_count: cython.longlong
    miss_count: cython.longlong
    record_count: cython.longlong

    def __post_init__(self) -> None:
        """Reject incomplete or negative cache accounting."""
        if operator.ne(self.query_count, self.hit_count + self.miss_count):
            raise ValueError("linear-global decomposition cache accounting is not closed")
        if min(self.query_count, self.hit_count, self.miss_count, self.record_count) < 0:
            raise ValueError("linear-global decomposition cache counters must be non-negative")


@cython.dataclasses.dataclass()
class LinearGlobalDecompositionCache8616:
    """Request-owned cache keyed by exact generated-carrier identity."""

    _entries: object = field(default_factory=dict)
    _query_count: cython.longlong = 0
    _hit_count: cython.longlong = 0
    _miss_count: cython.longlong = 0
    _record_count: cython.longlong = 0

    @cython.ccall
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

    @cython.ccall
    def record(
        self,
        key: LinearGlobalCarrierKey8616,
        result: LinearGlobalDecompositionResult8616 | None,
    ) -> None:
        """Record one exact carrier result for this immutable request."""
        self._entries[key] = result
        self._record_count += 1

    @cython.ccall
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
