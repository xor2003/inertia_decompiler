"""Identity removes only a second already-authenticated native comparison."""

import sys
from dataclasses import replace
from time import monotonic
from types import SimpleNamespace

import pytest

from inertia.ir import real16_invocation_domain as owner
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616

pytestmark = pytest.mark.decompiler


def bound(block, native, root, *, limit=1000, deadline=None):
    """Observe actual canonical comparisons with their unchanged charged budget."""
    ctx = SimpleNamespace(native_blocks={1: {1: native}}, work_units=0,
                          accounted_work_units=0, work_limit=limit,
                          deadline=monotonic() + 10 if deadline is None else deadline)
    data = SimpleNamespace(artifact=IRFunctionArtifact(1, (block,)))
    calls = []

    def trace(frame, event, arg):
        if event == "call" and frame.f_code is owner._native_block_bound_8616.__code__:
            calls.append(frame.f_locals["block"])
        return None

    previous = sys.gettrace()
    with segment_call_dependency_traversal_scope_8616() as traversal:
        sys.settrace(trace)
        try:
            result = owner._prefix_block_facts_bound_8616(ctx, data, {1: root}, 1, 1, block)
        finally:
            sys.settrace(previous)
        return result, ctx.work_units, traversal.census_work_units, calls


def block():
    return IRBlock(1, (IRInstr("NOP", None, (), addr=1), IRInstr("RET", None, (), addr=2)))


def test_identical_root_authenticated_once_and_charged_once():
    current = block()
    result, local, ambient, calls = bound(current, replace(current), current)
    assert result == len(current.instrs)
    assert local == ambient == len(current.instrs) + 1
    assert len(calls) == 1 and calls[0] is current


def test_equal_copy_retains_both_comparisons_and_work():
    current = block()
    root = replace(current)
    result, local, ambient, calls = bound(current, replace(current), root)
    assert result == len(current.instrs)
    assert local == ambient == 2 * (len(current.instrs) + 1)
    assert len(calls) == 2 and calls[0] is current and calls[1] is root


@pytest.mark.parametrize("mutation", ["retained", "root", "missing"])
def test_mutated_or_missing_owner_never_bypasses_validation(mutation):
    native = block()
    current = replace(native)
    root = current
    expected_comparisons = 1
    if mutation == "retained":
        object.__setattr__(current.instrs[0], "addr", 99)
        # Detached native rows model an independent current native reimport.
        native = block()
    elif mutation == "root":
        root = replace(current, instrs=(replace(current.instrs[0], addr=99), current.instrs[1]))
        expected_comparisons = 2
    else:
        root = None
        expected_comparisons = 2
    result, local, ambient, calls = bound(current, native, root)
    assert result is None
    assert len(calls) == expected_comparisons
    assert local == ambient == expected_comparisons * (len(current.instrs) + 1)


@pytest.mark.parametrize("limit,deadline", [(0, None), (1000, 0)])
def test_failed_first_resource_check_never_compares(limit, deadline):
    current = block()
    result, local, ambient, calls = bound(current, replace(current), current, limit=limit, deadline=deadline)
    assert result is None and calls == []
    assert local == ambient == len(current.instrs) + 1


def test_different_root_second_comparison_still_exhausts_budget():
    current = block()
    result, local, ambient, calls = bound(current, replace(current), replace(current), limit=3)
    assert result is None and len(calls) == 1
    assert local == ambient == 2 * (len(current.instrs) + 1)


def test_identical_owner_keeps_postcomparison_deadline_check(monkeypatch):
    current = block()
    clocks = iter((1, 101))
    monkeypatch.setattr(owner.time, "monotonic", lambda: next(clocks, 101))
    result, local, ambient, calls = bound(current, replace(current), current, deadline=100)
    assert result is None and len(calls) == 1
    assert local == ambient == len(current.instrs) + 1
