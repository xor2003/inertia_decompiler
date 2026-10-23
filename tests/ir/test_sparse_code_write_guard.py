"""Sparse written-byte overlap preserves exact code protection and accounting."""

import time
from itertools import combinations
from types import SimpleNamespace
from typing import cast

import pytest

from inertia.ir import real16_invocation_domain as owner
from inertia.ir.real16_path_memory8616 import (
    PathMemory8616,
    meet_path_memory_8616,
    restore_path_memory_8616,
    snapshot_path_memory_8616,
)

pytestmark = pytest.mark.decompiler
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616


def _ctx(spans: list[tuple[int, int]], limit: int = 100000) -> owner._PathCensusContext8616:
    return cast(
        owner._PathCensusContext8616,
        SimpleNamespace(
            manifest=spans, work_units=0, accounted_work_units=0, work_limit=limit, deadline=time.monotonic() + 10
        ),
    )


def test_sparse_count_reduction() -> None:
    """One external write needs two charged comparisons, not ten thousand bytes."""
    ctx = _ctx([(100, 10000)])
    with segment_call_dependency_traversal_scope_8616():
        assert owner._feasibility_code_unmodified_8616(ctx, owner.PathMemory8616({99: 0}))
    assert ctx.work_units == 5


@pytest.mark.parametrize(("limit", "expected", "units"), [(5, True, 5), (4, False, 5)])
def test_sparse_exact_limit(limit: int, expected: bool, units: int) -> None:
    """Sparse checks admit equality and refuse the first excess unit."""
    ctx = _ctx([(100, 10000)], limit)
    with segment_call_dependency_traversal_scope_8616():
        assert owner._feasibility_code_unmodified_8616(ctx, owner.PathMemory8616(unknown={99})) is expected
    assert ctx.work_units == units


@pytest.mark.parametrize(("address", "expected"), [(99, True), (100, False), (10099, False), (10100, True)])
@pytest.mark.parametrize("unknown", [False, True])
def test_sparse_boundary(address: int, expected: bool, unknown: bool) -> None:
    """Both written ledgers protect exactly the half-open native interval."""
    ctx = _ctx([(100, 10000)])
    memory = owner.PathMemory8616(unknown={address}) if unknown else owner.PathMemory8616({address: 0})
    with segment_call_dependency_traversal_scope_8616():
        assert owner._feasibility_code_unmodified_8616(ctx, memory) is expected


def test_dense_lane_exact_limit() -> None:
    """Unknown bounds cost one probe before the unchanged 19-unit dense walk."""
    for limit, expected in ((20, True), (19, False)):
        ctx = _ctx([(10, 3), (10, 3), (12, 3), (15, 2), (20, 1)], limit)
        with segment_call_dependency_traversal_scope_8616():
            assert (
                owner._feasibility_code_unmodified_8616(ctx, owner.PathMemory8616(dict.fromkeys(range(30, 50), 0)))
                is expected
            )
        assert ctx.work_units == 20


def test_empty_clean_overlay_needs_no_queries() -> None:
    """No written bytes implies no overlap without scanning code bytes."""
    ctx = _ctx([(100, 10000)])
    with segment_call_dependency_traversal_scope_8616():
        assert owner._feasibility_code_unmodified_8616(ctx, owner.PathMemory8616())
    assert ctx.work_units == 2


def test_exhaustive_small_half_open_unions() -> None:
    """All two-span geometries and up-to-two written addresses equal set overlap."""
    span_choices = [(start, size) for start in range(-2, 4) for size in range(-1, 4)]
    writes = [()] + [(a,) for a in range(-3, 8)] + list(combinations(range(-3, 8), 2))
    for first in span_choices:
        for second in span_choices:
            spans = [first, second, first]
            protected = {a for start, size in spans for a in range(start, start + size)}
            for addresses in writes:
                ctx = _ctx(spans)
                memory = owner.PathMemory8616(dict.fromkeys(addresses[::2], 0), set(addresses[1::2]))
                with segment_call_dependency_traversal_scope_8616():
                    assert owner._feasibility_code_unmodified_8616(ctx, memory) == (
                        not bool(protected.intersection(addresses))
                    )


def test_taint_deadline_exhaustion_before_construction() -> None:
    """Entry refusal prevents union construction after taint or exhausted budgets."""
    for kind in ("taint", "deadline", "work"):
        ctx = _ctx([(100, 10000)], -1 if kind == "work" else 100000)
        if kind == "deadline":
            ctx.deadline = time.monotonic() - 1
        with segment_call_dependency_traversal_scope_8616():
            assert not owner._feasibility_code_unmodified_8616(ctx, owner.PathMemory8616(tainted=kind == "taint"))
        assert ctx.work_units == 0


@pytest.mark.parametrize("data", [b"\x12\x34", None])
def test_overwritten_prefix_store_remains_protected(data: bytes | None) -> None:
    """Overwriting values cannot erase the earlier store's footprint."""
    memory = PathMemory8616()
    memory.apply_write(0x220, 2, b"\xaa\xbb")
    memory.apply_write(0x220, 2, data)
    saved = snapshot_path_memory_8616(memory)
    memory.taint()
    carried = restore_path_memory_8616(saved)
    assert set(carried.known) | carried.unknown == {0x220, 0x221}
    with segment_call_dependency_traversal_scope_8616():
        assert owner._feasibility_code_unmodified_8616(_ctx([(0x100, 16)]), carried)
        assert not owner._feasibility_code_unmodified_8616(
            _ctx([(0x100, 16), (0x221, 1)]), carried,
        )


def test_joined_prefix_retains_may_write_on_one_path() -> None:
    """A write absent from another arm is unknown, never unmodified memory."""
    written = PathMemory8616()
    written.apply_write(0x330, 1, b"\x00")
    joined = meet_path_memory_8616((written, PathMemory8616()))
    carried = restore_path_memory_8616(snapshot_path_memory_8616(joined))
    assert not carried.known
    assert carried.unknown == {0x330}
    with segment_call_dependency_traversal_scope_8616():
        assert not owner._feasibility_code_unmodified_8616(_ctx([(0x330, 1)]), carried)


def test_tainted_prefix_cannot_claim_empty_write_footprint() -> None:
    """Cleared ledgers after an unbounded effect must still refuse protection."""
    written = PathMemory8616({0x440: 0})
    joined = meet_path_memory_8616((written, PathMemory8616(tainted=True)))
    carried = restore_path_memory_8616(snapshot_path_memory_8616(joined))
    assert carried.tainted and not carried.known and not carried.unknown
    with segment_call_dependency_traversal_scope_8616():
        assert not owner._feasibility_code_unmodified_8616(_ctx([(0x100, 1)]), carried)
