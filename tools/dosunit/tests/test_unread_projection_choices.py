"""Unread projection retains visible differences through frames and choices."""
from __future__ import annotations

import pytest
import z3

from tools.dosunit.ssa.z3_ops import _z3_memory_preserve as preserve
from tools.dosunit.ssa.z3_ops import _z3_memory_read_projection as project

pytestmark = [pytest.mark.ssa_z3, pytest.mark.runtime]

M = z3.Array("projection_test_m", z3.BitVecSort(32), z3.BitVecSort(8))
N = z3.Array("projection_test_n", z3.BitVecSort(32), z3.BitVecSort(8))
a = z3.BitVec("projection_test_address", 32)
c = z3.Bool("projection_test_choice")


def b(value: int) -> z3.BitVecRef:
    return z3.BitVecVal(value, 32)


def v(value: int) -> z3.BitVecRef:
    return z3.BitVecVal(value, 8)


def p(memory: z3.ExprRef) -> z3.ExprRef:
    # Preserve the public lowering API's existing requirement for an ArrayRef.
    identity = z3.Store(memory, b(99), z3.Select(memory, b(99)))
    return project(0, [identity, b(100), b(103)], z3)


def f(memory: z3.ExprRef) -> z3.ExprRef:
    return preserve(0, [N, memory, b(90), b(110)], z3)


s1 = z3.Store(M, b(101), v(1))
s2 = z3.Store(M, b(101), v(2))
CASES = [
 ("hidden_store_through_frame",p(f(s1)),p(f(s2)),[],z3.unsat),
 ("observable_store_through_frame",p(f(z3.Store(M,b(105),v(1)))),p(f(z3.Store(M,b(105),v(2)))),[],z3.sat),
 ("symbolic_hidden_store",p(f(z3.Store(M,a,v(1)))),p(f(z3.Store(M,a,v(2)))),[z3.UGE(a,100),z3.ULE(a,103)],z3.unsat),
 ("unknown_address_not_hidden",p(f(z3.Store(M,a,v(1)))),p(f(z3.Store(M,a,v(2)))),[],z3.sat),
 ("array_ite_hidden_store",p(z3.If(c,s1,N)),p(z3.If(c,s2,N)),[],z3.unsat),
 ("array_ite_keeps_branch",p(z3.If(c,M,N)),p(z3.If(c,N,M)),[],z3.sat),
 ("nested_frame_hidden_store",p(f(f(s1))),p(f(f(s2))),[],z3.unsat),
 ("empty_frame_ignores_original",p(preserve(0,[N,s1,b(110),b(90)],z3)),p(N),[],z3.unsat),
]

@pytest.mark.parametrize("name,left,right,assumptions,expected", CASES)
def test_projection_retains_observable_differences(
    name: str, left: z3.ExprRef, right: z3.ExprRef,
    assumptions: list[z3.BoolRef], expected: z3.CheckSatResult,
) -> None:
    solver = z3.Solver()
    solver.set(timeout=2000)
    solver.add(*assumptions, left != right)
    assert solver.check() == expected, name


def test_bound_index_dependent_arrays_are_not_distributed() -> None:
    index = z3.BitVec("captured_index", 32)
    dependent = z3.Store(M, index, v(1))
    memory = z3.Lambda(index, z3.If(index == b(101),
                                 z3.Select(dependent, index), z3.Select(N, index)))
    result = p(memory)
    # The base UF must still receive this entire Lambda: distributing would
    # incorrectly move an array depending on its index outside the binder.
    seen: set[int] = set()
    pending = [result]
    found = False
    while pending:
        node = pending.pop()
        if node.get_id() in seen:
            continue
        seen.add(node.get_id())
        if z3.is_quantifier(node):
            pending.append(node.body())
        elif z3.is_app(node):
            if str(node.decl().name()).startswith("unread_projection_"):
                found |= node.arg(0).eq(z3.simplify(memory))
            pending.extend(node.children())
    assert found


def test_outer_bound_guard_is_not_distributed() -> None:
    from tools.dosunit.ssa.z3_unread_projection import _Projection

    index = z3.BitVec("guard_local_index", 32)
    # Explicit de Bruijn index 1 refers beyond this single local binder.
    outer = z3.Var(1, z3.BitVecSort(32))
    memory = z3.Lambda(index, z3.If(index == outer,
                                  z3.Select(M, index), z3.Select(N, index)))
    projection = _Projection(M, 100, 110, z3)
    result = projection.pointwise(memory, 0)
    assert result.eq(projection.base(memory))


def test_closedness_cache_distinguishes_binder_depth() -> None:
    from tools.dosunit.ssa.z3_unread_projection import _Projection

    projection = _Projection(M, 100, 110, z3)
    outer = z3.Var(0, z3.BitVecSort(32))
    assert not projection.closed(outer, 0)
    assert projection.closed(outer, 1)
    assert not projection.closed(outer, 0)


def test_closedness_visits_shared_subexpressions_once(monkeypatch: pytest.MonkeyPatch) -> None:
    from tools.dosunit.ssa.z3_unread_projection import _Projection

    term = z3.Bool("shared_closed_guard")
    for _ in range(14):
        term = z3.And(term, term)
    original = z3.ExprRef.children
    calls = 0

    def bounded_children(node: z3.ExprRef) -> list[z3.ExprRef]:
        nonlocal calls
        calls += 1
        assert calls <= 100, "shared DAG was traversed repeatedly"
        return original(node)

    monkeypatch.setattr(z3.ExprRef, "children", bounded_children)
    assert _Projection(M, 100, 110, z3).closed(term)
