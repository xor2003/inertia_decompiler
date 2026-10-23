"""Native conditional segment transport controls.

Layer: tests.
Responsibility: preserve scoped CS identity without claiming universal state.
"""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from inertia.ir.entry_jump_domain import prove_entry_jump_domains_8616
from inertia.ir.scoped_function_ir_view import prove_scoped_function_ir_view_8616
from inertia.ir.segment_state import apply_x86_16_segment_state_artifact, build_x86_16_segment_state_artifact
from inertia.ir.segment_state_transfer import architectural_live_in_state
from tests.ir.test_near_call_jump_scope import _scoped_loop

pytestmark = pytest.mark.decompiler


def test_native_scoped_segment_state():
    surface, scope, pending = _scoped_loop()
    proof = prove_entry_jump_domains_8616(surface.artifact, pending, project=surface.project, near_call_scope=scope)
    view = prove_scoped_function_ir_view_8616(surface.artifact, surface.boundary, proof, near_call_scope=scope)
    before = surface.artifact.to_dict()
    state = build_x86_16_segment_state_artifact(surface.artifact, scoped_view=view, near_call_scope=scope)
    assert state.near_call_scope is scope
    assert state.invocation_scope is None
    assert state.summary["classified_call_count"] == 1
    codegen = SimpleNamespace(_inertia_vex_ir_artifact=surface.artifact, _inertia_segment_state_artifact=state)
    apply_x86_16_segment_state_artifact(surface.project, codegen)
    assert codegen._inertia_segment_state_artifact.near_call_scope is scope
    assert state.state_after_instruction(0x1010, "cs") == architectural_live_in_state("cs")
    assert surface.artifact.to_dict() == before
    for supplied in (None, replace(scope)):
        with pytest.raises(ValueError):
            build_x86_16_segment_state_artifact(surface.artifact, scoped_view=view, near_call_scope=supplied)
    surface.project.loader.memory.store(0x1011, b"\x00")
    with pytest.raises(ValueError):
        build_x86_16_segment_state_artifact(surface.artifact, scoped_view=view, near_call_scope=scope)


def test_conditional_segment_effect_drops_gp_proxy():
    from inertia.ir.core import IRBlock, IRInstr, IRValue, MemSpace
    from inertia.ir.segment_state_transfer import transfer_block_with_instruction_states
    call = IRInstr("CALL", None, (), addr=0x10)
    # DX is a proxy of DS before CALL. Only segment registers may survive.
    before = {"cs": architectural_live_in_state("cs"), "ds": architectural_live_in_state("ds"), "dx": architectural_live_in_state("ds")}
    copy_dx = IRInstr("MOV", dst=IRValue(MemSpace.REG, name="es"), args=(IRValue(MemSpace.REG, name="dx"),), addr=0x13)
    block = IRBlock(0x10, instrs=(call, copy_dx))
    result, _, _ = transfer_block_with_instruction_states(block, before, near_call_effects={id(call): frozenset({"cs", "ds"})})
    assert result["cs"] == architectural_live_in_state("cs")
    assert result["es"] != architectural_live_in_state("ds")
