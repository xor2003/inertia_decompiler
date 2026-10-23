"""Deterministic invocation-order projection tests for the path census.

Layer: Tests.
Responsibility: pin the contract of ``acyclic_invocation_order_8616`` and
``invocation_transfer_order_8616`` — sorted default traversal, exact
unique-coverage acceptance, refusal on malformed proposals, predecessor-first
heap order including backwards-address joins, refusal on cycles, and honest
charged-work reporting on deadline/work exhaustion. Pure-geometry inputs
only; no native runner required.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.decompiler

from inertia.ir.real16_edge_feasibility8616 import (
    Real16InvocationOrder8616,
    acyclic_invocation_order_8616,
    invocation_transfer_order_8616,
)

# ``time.monotonic()`` is always positive and always finite, so these bounds
# deterministically never / always trip the deadline check.
_NO_DEADLINE = float("inf")
_EXPIRED_DEADLINE = -1.0
_AMPLE_WORK = 1_000_000


def test_transfer_order_defaults_to_sorted_scope() -> None:
    """No proposal means the sorted scope traversal, including empty scope."""
    scope = frozenset({0x30, 0x10, 0x20})
    assert invocation_transfer_order_8616(scope, None) == (0x10, 0x20, 0x30)
    assert invocation_transfer_order_8616(frozenset(), None) == ()


def test_transfer_order_preserves_exact_coverage() -> None:
    """A proposal covering the scope exactly is kept in the caller's order."""
    scope = frozenset({0x10, 0x20})
    assert invocation_transfer_order_8616(scope, (0x20, 0x10)) == (0x20, 0x10)


@pytest.mark.parametrize(
    "proposed",
    [(0x10,), (0x10, 0x20, 0x30), (0x10, 0x10), (0x10, 0x99), ()],
    ids=["missing", "extra", "duplicate", "substituted", "empty"],
)
def test_transfer_order_malformed_proposal_refuses(proposed: tuple[int, ...]) -> None:
    """Missing, extra, duplicate, or substituted blocks refuse outright."""
    assert invocation_transfer_order_8616(frozenset({0x10, 0x20}), proposed) is None


def test_acyclic_order_empty_scope() -> None:
    """An empty scope publishes an empty order with no work charged."""
    result = acyclic_invocation_order_8616(
        frozenset(), {}, deadline=_NO_DEADLINE, work_limit=_AMPLE_WORK
    )
    assert result == Real16InvocationOrder8616((), 0)


def test_acyclic_order_independent_blocks_sorted() -> None:
    """Blocks with no predecessors pop the ready heap in address order."""
    result = acyclic_invocation_order_8616(
        frozenset({0x30, 0x10, 0x20}), {},
        deadline=_NO_DEADLINE, work_limit=_AMPLE_WORK,
    )
    assert result.blocks == (0x10, 0x20, 0x30)


def test_acyclic_order_predecessors_first_backwards_join() -> None:
    """A join at a lower address than its predecessors still orders them
    first: the walk is predecessor-driven and heap-stable, never
    address-sorted."""
    scope = frozenset({0x10, 0x20, 0x30, 0x40})
    predecessors = {0x10: (0x30, 0x20), 0x40: (0x10,)}
    first = acyclic_invocation_order_8616(
        scope, predecessors, deadline=_NO_DEADLINE, work_limit=_AMPLE_WORK
    )
    second = acyclic_invocation_order_8616(
        scope, predecessors, deadline=_NO_DEADLINE, work_limit=_AMPLE_WORK
    )
    assert first == second
    assert first.blocks == (0x20, 0x30, 0x10, 0x40)


def test_acyclic_order_diamond_smallest_ready_first() -> None:
    """When two successors become ready together the heap picks the smaller
    address regardless of predecessor listing order."""
    scope = frozenset({0x10, 0x20, 0x30, 0x40})
    forward = {0x20: (0x10,), 0x30: (0x10,), 0x40: (0x30, 0x20)}
    reversed_listing = {0x20: (0x10,), 0x30: (0x10,), 0x40: (0x20, 0x30)}
    for predecessors in (forward, reversed_listing):
        result = acyclic_invocation_order_8616(
            scope, predecessors, deadline=_NO_DEADLINE, work_limit=_AMPLE_WORK
        )
        assert result.blocks == (0x10, 0x20, 0x30, 0x40)


def test_forward_graph_needs_only_one_node_and_edge_walk() -> None:
    """Strictly increasing edges prove the sorted order without heap replay."""
    scope = frozenset(range(24))
    predecessors = {address: (address - 1,) for address in range(1, 24)}
    result = acyclic_invocation_order_8616(
        scope, predecessors, deadline=_NO_DEADLINE, work_limit=47,
    )
    assert result == Real16InvocationOrder8616(tuple(range(24)), 47)


def test_acyclic_order_outside_predecessors_charged_not_counted() -> None:
    """Out-of-scope predecessors are visited and charged one work unit but
    cannot raise the in-scope degree. Work: node 0x10 (1), node 0x20 (2),
    pred 0x99 (3), pred 0x10 (4). Increasing edges need no heap walk."""
    scope = frozenset({0x10, 0x20})
    predecessors = {0x20: (0x99, 0x10)}
    result = acyclic_invocation_order_8616(
        scope, predecessors, deadline=_NO_DEADLINE, work_limit=_AMPLE_WORK
    )
    assert result == Real16InvocationOrder8616((0x10, 0x20), 4)


def test_acyclic_order_work_limit_exact_boundary() -> None:
    """The forward chain needs exactly two nodes and one predecessor visit."""
    scope = frozenset({0x10, 0x20})
    predecessors = {0x20: (0x10,)}
    exact = acyclic_invocation_order_8616(
        scope, predecessors, deadline=_NO_DEADLINE, work_limit=3
    )
    assert exact == Real16InvocationOrder8616((0x10, 0x20), 3)


@pytest.mark.parametrize("work_limit", [0, 1, 2])
def test_acyclic_order_work_limit_refuses_with_charged_work(work_limit: int) -> None:
    """Every cut below the exact 3-unit boundary refuses on the next charge,
    reporting the charged unit count as ``work_limit + 1``."""
    result = acyclic_invocation_order_8616(
        frozenset({0x10, 0x20}), {0x20: (0x10,)},
        deadline=_NO_DEADLINE, work_limit=work_limit,
    )
    assert result.blocks is None
    assert result.work_units == work_limit + 1


@pytest.mark.parametrize("work_limit", range(6))
def test_backward_chain_keeps_heap_budget(work_limit: int) -> None:
    """A backwards edge cannot use address order or waive the heap work."""
    result = acyclic_invocation_order_8616(
        frozenset({0x10, 0x20}), {0x10: (0x20,)},
        deadline=_NO_DEADLINE, work_limit=work_limit,
    )
    assert result == Real16InvocationOrder8616(None, work_limit + 1)


def test_self_loop_never_uses_forward_order() -> None:
    """A single block pointing to itself remains cyclic."""
    result = acyclic_invocation_order_8616(
        frozenset({0x10}), {0x10: (0x10,)},
        deadline=_NO_DEADLINE, work_limit=_AMPLE_WORK,
    )
    assert result == Real16InvocationOrder8616(None, 2)


def test_acyclic_order_expired_deadline_refuses_first_charge() -> None:
    """An already-expired deadline refuses after the first charged unit."""
    result = acyclic_invocation_order_8616(
        frozenset({0x10, 0x20}), {0x20: (0x10,)},
        deadline=_EXPIRED_DEADLINE, work_limit=_AMPLE_WORK,
    )
    assert result == Real16InvocationOrder8616(None, 1)


def test_acyclic_order_cycle_refuses() -> None:
    """Cycles never publish an order; a partial walk over the acyclic cone
    is still refused rather than published incomplete."""
    pure = acyclic_invocation_order_8616(
        frozenset({0x10, 0x20}), {0x10: (0x20,), 0x20: (0x10,)},
        deadline=_NO_DEADLINE, work_limit=_AMPLE_WORK,
    )
    assert pure == Real16InvocationOrder8616(None, 4)
    # 0x05 feeds a 0x10<->0x30 cycle that also gates 0x20; the lone popped
    # source is a partial walk. Work: 4 node visits + 4 predecessor visits
    # + 1 pop + 1 edge relax = 10.
    scope = frozenset({0x05, 0x10, 0x20, 0x30})
    predecessors = {0x10: (0x05, 0x30), 0x30: (0x10,), 0x20: (0x10,)}
    partial = acyclic_invocation_order_8616(
        scope, predecessors, deadline=_NO_DEADLINE, work_limit=_AMPLE_WORK
    )
    assert partial == Real16InvocationOrder8616(None, 10)
