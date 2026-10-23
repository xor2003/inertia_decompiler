"""Layer: IR tests.
Responsibility: bound pure CALL membership seals without weakening ownership.
"""
from __future__ import annotations

from dataclasses import replace

import pytest

import tests.ir.test_declared_selector_batch as batch_tests
from inertia.ir import entry_domain_call_preservation as caller
from inertia.ir.core import IRFunctionArtifact
from inertia.semantics import direct_near_call_target_binding as binding

pytestmark = pytest.mark.decompiler


def test_pending_coordinates_do_not_rescan_instruction_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    """The retained slot is checked directly, while graph sealing stays separate."""
    pending = batch_tests._pending(batch_tests._wrap_fixture())

    def scan(*args: object) -> bool:
        pytest.fail("final coordinate check rescanned the instruction stream")

    monkeypatch.setattr(binding, "any", scan, raising=False)
    assert binding._pending_coordinate_facts_8616(pending)


@pytest.mark.parametrize("mutation", ["replace", "reorder", "remove", "stream"])
def test_pending_coordinates_reject_changed_stream(mutation: str) -> None:
    """Even equal replacement streams cannot replace the retained owner."""
    pending = batch_tests._pending(batch_tests._wrap_fixture())
    rows = pending.block.instrs
    if mutation == "replace":
        changed = tuple(replace(row) if row is pending.instruction else row for row in rows)
    elif mutation == "reorder":
        changed = tuple(reversed(rows))
    elif mutation == "remove":
        changed = tuple(row for row in rows if row is not pending.instruction)
    else:
        changed = tuple(row for row in rows)
    object.__setattr__(pending.block, "instrs", changed)
    assert not binding._pending_coordinate_facts_8616(pending)


def test_caller_membership_position_rejects_foreign_or_replaced_owner() -> None:
    """A location is an identity witness, never reusable proof authority."""
    fixture = batch_tests._wrap_fixture()
    artifact = IRFunctionArtifact(fixture.block.addr, (fixture.block,))
    position = caller._capture_caller_instruction_position_8616(artifact, fixture.block, fixture.call)
    assert position is not None
    assert position.matches(artifact, fixture.block, fixture.call)
    assert not position.matches(replace(artifact), fixture.block, fixture.call)
    assert not position.matches(artifact, replace(fixture.block), fixture.call)
    assert not position.matches(artifact, fixture.block, replace(fixture.call))
    object.__setattr__(artifact, "blocks", tuple(block for block in artifact.blocks))
    assert not position.matches(artifact, fixture.block, fixture.call)
