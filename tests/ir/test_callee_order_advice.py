"""Optional callee ordering must not repeatedly scan cyclic graphs."""

import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import FrameType

import pytest

from inertia.ir import real16_edge_feasibility8616 as edge
from inertia.ir import real16_invocation_domain as owner
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616
from tests.ir import test_callee_local_feasibility as fixture

pytestmark = pytest.mark.decompiler

CYCLIC = bytes.fromhex("83f80075fbc3")  # cmp ax,0; jne entry; ret


@contextmanager
def order_observations() -> Iterator[list[edge.Real16InvocationOrder8616]]:
    """Count genuine producer calls without replacing proof-bound functions."""
    observations: list[edge.Real16InvocationOrder8616] = []
    previous = sys.getprofile()

    def observe(frame: FrameType, event: str, arg: object) -> None:
        if event == "return" and frame.f_code is edge.acyclic_invocation_order_8616.__code__:
            assert isinstance(arg, edge.Real16InvocationOrder8616)
            observations.append(arg)

    sys.setprofile(observe)
    try:
        yield observations
    finally:
        sys.setprofile(previous)


def seed() -> owner._PathState8616:
    """Provide a terminating invocation of the native cyclic fixture."""
    return owner._PathState8616(
        {"ax": 0, "cs": fixture.native.LOAD_SEGMENT,
         "ss": fixture.native.LOAD_SEGMENT + 0x10, "esp": 0x100},
        owner.PathMemory8616(),
    )


def test_cyclic_order_attempt_is_not_repeated(tmp_path: Path) -> None:
    """Negative scheduling advice skips only the optional ordering attempt."""
    ctx, proof = fixture.world(tmp_path, CYCLIC)
    with segment_call_dependency_traversal_scope_8616(), order_observations() as calls:
        first = owner._simulate_callee_8616(ctx, proof, seed())
        second = owner._simulate_callee_8616(ctx, proof, seed())
    assert isinstance(first, dict), first
    assert second == first
    assert len(calls) == 1
    assert calls[0].blocks is None


def test_positive_orders_are_fresh(tmp_path: Path) -> None:
    """A successful scheduling projection is never reused as advice."""
    ctx, proof = fixture.world(tmp_path, fixture.SHARED)
    with segment_call_dependency_traversal_scope_8616(), order_observations() as calls:
        first = owner._simulate_callee_8616(ctx, proof, seed())
        second = owner._simulate_callee_8616(ctx, proof, seed())
    assert isinstance(first, dict), first
    assert second == first
    assert len(calls) == 2
    assert all(call.blocks is not None for call in calls)


def test_advice_expires_with_traversal(tmp_path: Path) -> None:
    """Independent requests must not share an ordering decision."""
    ctx, proof = fixture.world(tmp_path, CYCLIC)
    with order_observations() as calls:
        for _ in range(2):
            with segment_call_dependency_traversal_scope_8616():
                result = owner._simulate_callee_8616(ctx, proof, seed())
                assert isinstance(result, dict), result
    assert len(calls) == 2


@pytest.mark.parametrize("exhausted", ["deadline", "local_work", "shared_work"])
def test_advice_cannot_bypass_resource_limits(tmp_path: Path, exhausted: str) -> None:
    """Skipping optional ordering cannot turn exhausted resources into proof."""
    ctx, proof = fixture.world(tmp_path, CYCLIC)
    artifact = proof.callee.coverage.artifact
    with segment_call_dependency_traversal_scope_8616() as traversal:
        assert owner._callee_transfer_order_8616(ctx, artifact) is None
        assert artifact.function_addr in traversal.callee_default_order
        if exhausted == "deadline":
            ctx.deadline = 0
        elif exhausted == "local_work":
            ctx.work_limit = ctx.work_units - 1
        else:
            traversal.census_work_units = owner._CENSUS_WORK_LIMIT_8616 + 1
        result = owner._callee_transfer_order_8616(ctx, artifact)
    expected = (owner.Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
                if exhausted == "deadline" else owner.Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED)
    assert result is expected


def test_exhausted_attempt_does_not_publish_advice(tmp_path: Path) -> None:
    """Truncated preparation is never recorded as a completed cyclic attempt."""
    ctx, proof = fixture.world(tmp_path, CYCLIC)
    ctx.work_limit = ctx.work_units + 1
    with segment_call_dependency_traversal_scope_8616() as traversal:
        result = owner._callee_transfer_order_8616(ctx, proof.callee.coverage.artifact)
        assert not traversal.callee_default_order
    assert result is owner.Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED


def test_custom_producer_remains_observable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Existing advice must not bypass a replaced ordering callback."""
    ctx, proof = fixture.world(tmp_path, CYCLIC)
    artifact = proof.callee.coverage.artifact
    original = owner.acyclic_invocation_order_8616
    calls = []

    def observe(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    with segment_call_dependency_traversal_scope_8616():
        assert owner._callee_transfer_order_8616(ctx, artifact) is None
        monkeypatch.setattr(owner, "acyclic_invocation_order_8616", observe)
        assert owner._callee_transfer_order_8616(ctx, artifact) is None
        assert owner._callee_transfer_order_8616(ctx, artifact) is None
    assert len(calls) == 2


def test_advice_retains_native_authentication(tmp_path: Path) -> None:
    """A changed native instruction still refuses after negative advice is installed."""
    ctx, proof = fixture.world(tmp_path, CYCLIC)
    head = proof.callee.coverage.artifact.function_addr
    with segment_call_dependency_traversal_scope_8616():
        first = owner._simulate_callee_8616(ctx, proof, seed())
        assert isinstance(first, dict), first
        native = ctx.native_blocks[head]
        native[head] = replace(native[head], instrs=native[head].instrs[:-1])
        result = owner._simulate_callee_8616(ctx, proof, seed())
    assert result is owner.Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN


def test_changed_geometry_uses_ordinary_fixpoint(tmp_path: Path) -> None:
    """Advice from another graph at the same address can only select the ordinary path."""
    ctx, proof = fixture.world(tmp_path, fixture.SHARED)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        baseline = owner._simulate_callee_8616(ctx, proof, seed())
        traversal.callee_default_order.add(proof.callee.coverage.artifact.function_addr)
        result = owner._simulate_callee_8616(ctx, proof, seed())
    assert isinstance(baseline, dict), baseline
    assert result == baseline
