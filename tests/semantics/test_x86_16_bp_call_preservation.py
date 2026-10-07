"""Bind leaf BP preservation to real call bytes before consuming it."""

import io
from dataclasses import replace

import angr
import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import CallsiteMachineFrameKind8616, CallsiteSummary8616
from inertia.ir import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace

from inertia.semantics.bp_call_preservation import prove_direct_bp_call_preservation_8616
from inertia.semantics.call_stack_effects import materialize_call_stack_effects_8616


def _project(body: bytes):
    """Load real call/callee bytes and independently bounded function ranges."""
    code = bytes.fromhex("e8 01 00 c3") + body
    project = angr.Project(io.BytesIO(code), main_opts={
        "backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000,
    }, auto_load_libs=False)
    project._inertia_caller_function_ranges_8616 = ((0x1000, 0x1004), (0x1004, 0x1000 + len(code)))
    return project


@pytest.mark.parametrize("body,accepted", (("55 89 e5 89 ec 5d c3", True), ("bd 12 34 c3", False)))
def test_real_leaf_call_preservation_and_production_projection(body: str, accepted: bool) -> None:
    """Production effects derive BP preservation from the body, not a compiler ABI."""
    project = _project(bytes.fromhex(body))
    proof = prove_direct_bp_call_preservation_8616(project, 0x1000, 0x1003, 0x1004, CallsiteMachineFrameKind8616.NEAR)
    assert proof.complete is accepted
    assert proof.classified_fact_count == proof.materialized_count == int(accepted)
    assert proof.failure_count == int(not accepted)
    summary = CallsiteSummary8616(callsite_addr=0x1000, target_addr=0x1004, return_addr=0x1003,
                                 kind="direct_near", arg_count=0, arg_widths=(), stack_cleanup=0,
                                 return_register=None, return_used=False)
    caller = IRFunctionArtifact(0x1000, (IRBlock(0x1000, instrs=(
        IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=0x1004, size=2),), addr=0x1000),
    )),))
    effects = materialize_call_stack_effects_8616(caller, {0x1000: summary}, project=project)
    assert effects.facts[0].effect.bp_preserved is accepted
    if accepted:
        assert effects.facts[0].bp_preservation is not None
        assert effects.facts[0].bp_preservation.complete
        assert not replace(proof, target_addr=0x1005).complete
        assert not replace(proof, return_addr=0x1004).complete
        assert not replace(proof, project=_project(bytes.fromhex(body))).complete


@pytest.mark.parametrize("target,return_addr,frame", (
    (0x1005, 0x1003, CallsiteMachineFrameKind8616.NEAR),
    (0x1004, 0x1004, CallsiteMachineFrameKind8616.NEAR),
    (0x1004, 0x1003, CallsiteMachineFrameKind8616.FAR),
))
def test_real_call_target_and_frame_must_match(target: int, return_addr: int, frame: CallsiteMachineFrameKind8616) -> None:
    """A valid preserving body cannot authorize a different transfer."""
    project = _project(bytes.fromhex("55 5d c3"))
    assert not prove_direct_bp_call_preservation_8616(project, 0x1000, return_addr, target, frame).complete


def test_bp_effect_refuses_disagreeing_ir_call_target() -> None:
    """Mapped summary bytes must also agree with the CALL being enriched."""
    project = _project(bytes.fromhex("55 5d c3"))
    summary = CallsiteSummary8616(0x1000, 0x1004, 0x1003, "direct_near", 0, (), 0, None, False)
    caller = IRFunctionArtifact(0x1000, (IRBlock(0x1000, instrs=(
        IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=0x1005, size=2),), addr=0x1000),
    )),))
    effects = materialize_call_stack_effects_8616(caller, {0x1000: summary}, project=project)
    assert not effects.facts[0].effect.bp_preserved


def test_bp_call_proof_does_not_require_optional_function_ranges() -> None:
    """The exact real CALL target and closed binary reachability suffice."""
    project = _project(bytes.fromhex("55 89 e5 89 ec 5d c3"))
    del project._inertia_caller_function_ranges_8616
    proof = prove_direct_bp_call_preservation_8616(project, 0x1000, 0x1003, 0x1004, CallsiteMachineFrameKind8616.NEAR)
    assert proof.complete, proof.failure
