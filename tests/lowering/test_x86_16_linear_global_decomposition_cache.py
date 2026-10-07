"""Contracts for request-local linear-global decomposition reuse."""

from inertia.lowering.linear_global_decomposition_cache import (
    LinearGlobalDecompositionCache8616,
)


def test_linear_global_decomposition_cache_distinguishes_refusal_from_miss() -> None:
    """A cached ``None`` must remain a hit rather than trigger recomputation."""
    cache = LinearGlobalDecompositionCache8616()
    key = ("name", "vvar_31")

    assert cache.lookup(key).found is False
    cache.record(key, None)
    lookup = cache.lookup(key)

    assert lookup.found is True
    assert lookup.result is None
    stats = cache.stats()
    assert (stats.query_count, stats.hit_count, stats.miss_count, stats.record_count) == (
        2,
        1,
        1,
        1,
    )


def test_linear_global_decomposition_cache_returns_exact_typed_result() -> None:
    """A cached decomposition must preserve its segment and residual terms."""
    cache = LinearGlobalDecompositionCache8616()
    key = ("name", "vvar_47")
    residual = object()
    result = ("ds", 0x1234, ((1, residual),))

    cache.record(key, result)
    lookup = cache.lookup(key)

    assert lookup.found is True
    assert lookup.result == result
    stats = cache.stats()
    assert stats.query_count == stats.hit_count + stats.miss_count
