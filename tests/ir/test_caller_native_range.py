"""Closed native bounds protect expanded IR without scanning its rows."""

import time
from dataclasses import replace
from types import SimpleNamespace
from typing import cast

import pytest

from inertia.ir import real16_invocation_domain as owner
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616

pytestmark = pytest.mark.decompiler


def _world(rows: int = 9, limit: int = 10000) -> tuple:
    """Use one three-byte native extent with arbitrary IR expansion count."""
    project = object()
    ctx = cast(
        owner._PathCensusContext8616,
        SimpleNamespace(
            project=project,
            manifest=set(),
            callsite_addr=200,
            work_units=0,
            accounted_work_units=0,
            work_limit=limit,
            deadline=time.monotonic() + 10,
        ),
    )
    call = IRInstr("CALL", None, (), addr=100, size=3)
    block = IRBlock(100, (call, *(IRInstr("MOV", None, (), addr=100, size=3) for _ in range(rows - 1))))
    artifact = IRFunctionArtifact(100, (block,))
    native = SimpleNamespace(addr=100, size=3)
    boundary = owner.ExactFunctionRangeBoundary8616(project, 100, 3, frozenset({100}), frozenset({100}), (), (native,))
    return ctx, artifact, boundary, call, {id(call): (block, call)}


def test_no_ir_expansion_scan() -> None:
    """4096 expanded rows cost four actual native/preparation operations."""
    ctx, artifact, boundary, _call, rows = _world(4096)
    with segment_call_dependency_traversal_scope_8616():
        assert owner._feasibility_call_handler_8616(ctx, artifact, boundary, rows) is not None
    assert ctx.work_units == 4


@pytest.mark.parametrize(("limit", "allowed", "units"), [(4, True, 4), (3, False, 4)])
def test_native_exact_limit(limit: int, allowed: bool, units: int) -> None:
    """Equality remains admitted; the first excess operation refuses."""
    ctx, artifact, boundary, _call, rows = _world(limit=limit)
    with segment_call_dependency_traversal_scope_8616():
        assert (owner._feasibility_call_handler_8616(ctx, artifact, boundary, rows) is not None) is allowed
    assert ctx.work_units == units


@pytest.mark.parametrize("kind", ["no-callsite", "expired", "work", "empty"])
def test_early_admission(kind: str) -> None:
    """Disabled or exhausted lanes never extract a native range."""
    ctx, artifact, boundary, _call, rows = _world()
    if kind == "no-callsite":
        ctx.callsite_addr = None
    if kind == "expired":
        ctx.deadline = time.monotonic() - 1
    if kind == "work":
        ctx.work_limit = -1
    with segment_call_dependency_traversal_scope_8616():
        assert owner._feasibility_call_handler_8616(ctx, artifact, boundary, {} if kind == "empty" else rows) is None
    assert ctx.work_units == 0


@pytest.mark.parametrize(
    "kind",
    [
        "foreign-project",
        "foreign-root",
        "shrunk-end",
        "outside-block",
        "duplicate-native",
        "duplicate-ir",
        "mismatched-heads",
    ],
)
def test_closed_native_frame_rejects_corruption(kind: str) -> None:
    """Native extents and complete unique block ownership must fit the bound."""
    ctx, artifact, boundary, _call, rows = _world()
    if kind == "foreign-project":
        boundary = replace(boundary, project=object())
    if kind == "foreign-root":
        boundary = replace(boundary, addr=99)
    if kind == "shrunk-end":
        boundary = replace(boundary, size=2)
    if kind == "outside-block":
        boundary = replace(boundary, blocks=(SimpleNamespace(addr=101, size=3),))
    if kind == "duplicate-native":
        boundary = replace(boundary, blocks=(*boundary.blocks, *boundary.blocks))
    if kind == "duplicate-ir":
        artifact = replace(artifact, blocks=(*artifact.blocks, *artifact.blocks))
    if kind == "mismatched-heads":
        boundary = replace(boundary, block_addrs_set=frozenset({101}))
    with segment_call_dependency_traversal_scope_8616():
        assert owner._feasibility_call_handler_8616(ctx, artifact, boundary, rows) is None


@pytest.mark.parametrize("kind", ["size", "floor", "blocks", "project"])
def test_mutated_boundary_after_capture_never_crosses(kind: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Changed owning range metadata is rejected before scratch effects."""
    ctx, artifact, boundary, call, rows = _world()

    def forbidden(*_args: object) -> bool:
        raise AssertionError("stale boundary must not cross")

    monkeypatch.setattr(owner, "_feasibility_call_scratch_8616", forbidden)
    with segment_call_dependency_traversal_scope_8616():
        apply = owner._feasibility_call_handler_8616(ctx, artifact, boundary, rows)
        assert apply is not None
        if kind == "size":
            object.__setattr__(boundary, "size", 4)
        if kind == "floor":
            object.__setattr__(boundary, "decode_lower_bound", 99)
        if kind == "blocks":
            object.__setattr__(boundary, "blocks", (*boundary.blocks,))
        if kind == "project":
            object.__setattr__(boundary, "project", object())
        assert not apply(call, {}, owner.PathMemory8616())
