"""Conditional indirect control needs fresh invocation, byte and target geometry proof."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from inertia.frontend.x86_16.control_transfer_geometry import ControlKind8616, ControlVerdict8616
from inertia.ir import declared_selector_control_binding as binding
from inertia.ir import declared_selector_invariant as selector
from inertia.ir.vex_import import IRImportRefusalReason8616
from tests.ir.test_scoped_indirect_target_view import _native_view

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("mutation", [
    "none", "selector", "short_bytes", "receipt", "scope", "block", "target_census", "native",
])
def test_native_indirect_control_requires_exact_scoped_authority(mutation: str) -> None:
    """Retain native indirect bytes and reject each broken binding independently."""
    view, scope = _native_view()
    assert view.failure is None
    receipt = view.discovery
    block = next(row for row in view.source_artifact.blocks if row.addr == receipt.block_addr)
    instruction = block.instrs[-1]
    encoded = dict(receipt.native_spans)[receipt.instruction_addr]
    census = {row.addr for raw in view.source_artifact.blocks for row in raw.instrs}
    cs = scope.entry_segment
    assert binding.check_bound_control_8616(
        block, instruction, encoded, cs, None, census).verdict is ControlVerdict8616.REFUSED
    if mutation == "selector":
        cs = scope.minimum_selector - 1
    elif mutation == "short_bytes":
        encoded = encoded[:-1]
    elif mutation == "receipt":
        view = replace(view, discovery=replace(receipt, target=receipt.target + 1))
    elif mutation == "scope":
        scope = replace(scope, project=object())
    elif mutation == "block":
        block = replace(block)
    elif mutation == "target_census":
        census.remove(receipt.target)
    elif mutation == "native":
        view.project.loader.memory.store(receipt.instruction_addr, b"\x90")
    result = binding.check_scoped_indirect_control_8616(
        view, scope, block, instruction, encoded, cs, census)
    if mutation == "none":
        assert result.verdict is ControlVerdict8616.CLOSED, result
        assert result.kind is ControlKind8616.JMP
        assert result.target == receipt.target
        assert result.fallthrough is None
    else:
        assert result.verdict is ControlVerdict8616.REFUSED, result


def test_pending_marker_discharge_matches_authenticated_block() -> None:
    """Only the proved indirect block's native pending marker can be discharged."""
    view, scope = _native_view()
    assert view.cfg_projection_for(scope) is not None
    block = next(row for row in view.source_artifact.blocks if row.addr == view.discovery.block_addr)
    marker = next(row for row in block.refusals if row.kind == IRImportRefusalReason8616.INDIRECT_TERMINAL_PENDING)
    # This pure marker filter consumes an already authenticated view; call
    # preservation authentication belongs to the preceding production gate.
    record = SimpleNamespace(callee=SimpleNamespace(coverage=SimpleNamespace(scoped_view=view)))
    assert selector._scoped_refusal_discharged_8616(record, block, marker)
    assert not selector._scoped_refusal_discharged_8616(
        record, block, replace(marker, block_addr=block.addr + 1))
    assert not selector._scoped_refusal_discharged_8616(
        record, block, replace(marker, kind="unrelated_effect"))
    assert not selector._scoped_refusal_discharged_8616(
        record, replace(block, addr=block.addr + 1), marker)
