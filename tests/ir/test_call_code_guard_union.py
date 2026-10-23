"""An operation-local interval union preserves every protected native byte."""

import time
from types import SimpleNamespace
from typing import cast

import pytest

from inertia.ir import real16_invocation_domain as owner
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616

pytestmark = pytest.mark.decompiler


def _ctx(
    spans: list[tuple[int, int]], limit: int = 10000, deadline: float | None = None
) -> owner._PathCensusContext8616:
    """Provide the exact resource fields this private guard consumes."""
    return cast(
        owner._PathCensusContext8616,
        SimpleNamespace(
            manifest=list(spans),
            work_units=0,
            accounted_work_units=0,
            work_limit=limit,
            deadline=time.monotonic() + 10 if deadline is None else deadline,
        ),
    )


@pytest.mark.parametrize(
    ("known", "unknown", "expected"),
    [
        ({}, set(), True),
        ({10: 0}, set(), False),
        ({}, {16}, False),
        ({17: 0}, {19}, True),
        ({}, {20}, False),
        ({21: 0}, set(), True),
    ],
)
def test_exact_overlap_and_boundary(known: dict[int, int], unknown: set[int], expected: bool) -> None:
    """Adjacent/overlapping intervals retain exact half-open byte protection."""
    spans = [(10, 3), (10, 3), (12, 3), (15, 2), (20, 1)]
    ctx = _ctx(spans)
    with segment_call_dependency_traversal_scope_8616():
        assert owner._feasibility_code_unmodified_8616(ctx, owner.PathMemory8616(known, set(unknown))) is expected
    assert ctx.manifest == spans


def test_union_is_exact_and_construction_is_charged() -> None:
    """Insertion and unique merges are charged before any protected-byte query."""
    ctx = _ctx([(10, 3), (10, 3), (12, 3), (15, 2), (20, 1)])
    with segment_call_dependency_traversal_scope_8616():
        assert owner._feasibility_protected_union_8616(ctx) == ((10, 17), (20, 21))
    assert ctx.work_units == 9


@pytest.mark.parametrize(("limit", "expected"), [(9, True), (8, False)])
def test_total_exact_limit(limit: int, expected: bool) -> None:
    """Equality with the existing work cap remains admitted; exceeding refuses."""
    ctx = _ctx([(10, 3), (10, 3), (12, 3), (15, 2), (20, 1)], limit=limit)
    with segment_call_dependency_traversal_scope_8616():
        assert owner._feasibility_code_unmodified_8616(ctx, owner.PathMemory8616()) is expected
    assert ctx.work_units == 9


def test_taint_expiry_and_exhaustion_refuse_before_construction() -> None:
    """Existing entry guards prevent work after expiry/taint/exhaustion."""
    cases = [
        (_ctx([(10, 1)]), owner.PathMemory8616(tainted=True)),
        (_ctx([(10, 1)], deadline=time.monotonic() - 1), owner.PathMemory8616()),
        (_ctx([(10, 1)], limit=-1), owner.PathMemory8616()),
    ]
    for ctx, memory in cases:
        with segment_call_dependency_traversal_scope_8616():
            assert not owner._feasibility_code_unmodified_8616(ctx, memory)
        assert ctx.work_units == 0


def test_nonpositive_extents_protect_no_bytes() -> None:
    """Original empty Python ranges remain empty, without inventing protection."""
    ctx = _ctx([(10, 0), (10, -2)])
    with segment_call_dependency_traversal_scope_8616():
        assert owner._feasibility_code_unmodified_8616(ctx, owner.PathMemory8616({10: 0}))
    assert ctx.work_units == 2


def test_total_work_reduces_duplicate_native_spans() -> None:
    """Saved byte visits exceed all charged insertion/merge construction work."""
    ctx = _ctx([(0x1000, 3)] * 100 + [(0x1002, 4)] * 80 + [(0x1010, 2)] * 3)
    with segment_call_dependency_traversal_scope_8616():
        assert owner._feasibility_code_unmodified_8616(ctx, owner.PathMemory8616())
    # 183 input insertions + 3 unique merges; the clean overlay needs no queries.
    assert ctx.work_units == 186
