"""Native call evidence must retain raw CFG authentication during selector induction."""

import time
from dataclasses import replace

import pytest

from inertia.ir import declared_selector_invariant as selector
from inertia.ir.entry_domain_call_preservation import EntryDomainCallPreservationFailure8616
from tests.ir.test_forward_declared_call_scope import _collect, _forward_world

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("mutation", ["none", "failed_record", "foreign_artifact", "stale_native"])
def test_native_callee_record_keeps_raw_cfg_proof(mutation: str) -> None:
    """A native RET callee needs no conditional view; invalid records still refuse."""
    world = _forward_world(helper_bytes=b"\xb8\x07\x00\xc3")
    record = _collect(world)[0]
    assert record.complete_for(record.required_scope)
    callee = record.callee
    assert callee is not None
    assert callee.coverage.scoped_view is None
    artifact = callee.coverage.artifact
    boundary = callee.coverage.boundary
    if mutation == "failed_record":
        record = replace(record, failure=EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE)
    elif mutation == "foreign_artifact":
        artifact = replace(artifact)
    elif mutation == "stale_native":
        world[0].loader.memory.store(artifact.function_addr, b"\x90")
    projection = selector._scoped_native_projection_8616(
        artifact.function_addr, artifact, boundary, record)
    if mutation != "none":
        assert isinstance(projection, selector.Obligation)
        assert projection.kind is selector.ObligationKind.CFG_INCOMPLETE
        return
    assert projection is False
    surface = selector._native_blocks(
        world[0], artifact.function_addr, selector._Budget(time.monotonic() + 20, 20000),
        supplied=(boundary, artifact), scoped=record)
    assert not isinstance(surface, selector.Obligation), surface
    obligations = []
    cfg = selector._induction_cfg_8616(
        artifact.function_addr, artifact, boundary, record, obligations)
    assert not obligations
    assert cfg is not None
    blocks, edges = cfg
    assert blocks == {block.addr: block for block in artifact.blocks}
    assert edges == boundary.successor_edges
