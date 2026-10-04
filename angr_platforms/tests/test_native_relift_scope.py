"""Consume exact leaf evidence without retaining GP proxies or guessing effects."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
    DecodedDirectCallsiteIndexStats8616,
)
from angr_platforms.X86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from angr_platforms.X86_16.ir import (
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
    build_x86_16_segment_state_artifact,
)
from angr_platforms.X86_16.ir.function_ir_registry import (
    publish_function_ir_artifact_8616,
)
from angr_platforms.X86_16.ir.ir_boundary_cfg import prove_ir_boundary_coverage_8616
from angr_platforms.X86_16.ir.segment_call_preservation import prove_segment_call_preservation_8616
from angr_platforms.X86_16.ir.segment_effect_closure import prove_segment_effect_closure_8616


@pytest.fixture
def leaf_proof():
    project = SimpleNamespace()
    caller = IRFunctionArtifact(0x1000, (IRBlock(0x1000, instrs=(
        IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2),
                (IRValue(MemSpace.REG, name="ds", size=2),), addr=0x1000),
        IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=0x2000, size=2),), addr=0x1002),
        IRInstr("MOV", IRValue(MemSpace.REG, name="es", size=2),
                (IRValue(MemSpace.REG, name="ax", size=2),), addr=0x1005),
        IRInstr("RET", None, (), addr=0x1007),
    )),))
    callee = IRFunctionArtifact(0x2000, (IRBlock(0x2000, instrs=(
        IRInstr("MOV", IRValue(MemSpace.REG, name="es", size=2),
                (IRValue(MemSpace.CONST, const=0xB800, size=2),), addr=0x2000),
        IRInstr("RET", None, (), addr=0x2003),
    )),))
    publish_function_ir_artifact_8616(project, caller)
    publish_function_ir_artifact_8616(project, callee)
    caller_boundary = ExactFunctionRangeBoundary8616(
        project, 0x1000, 8, frozenset({0x1000}), frozenset({0x1000, 0x1002, 0x1005, 0x1007}), (),
    )
    callee_boundary = ExactFunctionRangeBoundary8616(
        project, 0x2000, 4, frozenset({0x2000}), frozenset({0x2000, 0x2003}), (),
    )
    caller_coverage = prove_ir_boundary_coverage_8616(project, caller_boundary, caller)
    callee_coverage = prove_ir_boundary_coverage_8616(project, callee_boundary, callee)
    closure = prove_segment_effect_closure_8616(callee_coverage, build_x86_16_segment_state_artifact(callee))
    entry = DecodedDirectCallsite8616(0x1000, (SimpleNamespace(address=0x1002),), 0, 0x1002, 0x2000)
    index = DecodedDirectCallsiteIndex8616({0x2000: (entry,)}, DecodedDirectCallsiteIndexStats8616(1, 1, 1, 1, 0))
    proof = prove_segment_call_preservation_8616(caller_coverage, closure, index, 0x1002)
    return project, caller, callee, proof


def test_adjacent_proof_selection_and_projection_validate_once(leaf_proof, monkeypatch):
    """One CALL transfer consumes one validation snapshot; later calls start fresh."""
    from angr_platforms.X86_16.ir import segment_call_preservation as owner
    from angr_platforms.X86_16.ir.segment_state_transfer import (
        SEGMENT_REGISTERS,
        architectural_live_in_state,
        transfer_block_with_instruction_states,
    )
    _, caller, _, proof = leaf_proof
    original = owner._preservation_result_verdict_8616
    observed = []

    def counted(result, traversal, offered=None):
        if result is proof:
            observed.append(result)
        return original(result, traversal, offered)

    monkeypatch.setattr(owner, "_preservation_result_verdict_8616", counted)
    entry = {name: architectural_live_in_state(name) for name in SEGMENT_REGISTERS}
    for expected_count in (1, 2):
        state, _, _ = transfer_block_with_instruction_states(
            caller.blocks[0], entry, call_preservations=(proof,), source_artifact=caller,
        )
        assert state["ds"].origin is SegmentOrigin.PROVEN
        assert len(observed) == expected_count


@pytest.mark.parametrize("mutation", ("registry", "exit_state", "accounting"))
def test_mutation_between_transfers_is_revalidated(leaf_proof, mutation):
    """No validation verdict survives a transfer into a later mutable snapshot."""
    from angr_platforms.X86_16.ir.segment_state_transfer import (
        SEGMENT_REGISTERS,
        architectural_live_in_state,
        transfer_block_with_instruction_states,
        unknown_segment_state,
    )
    project, caller, callee, proof = leaf_proof
    entry = {name: architectural_live_in_state(name) for name in SEGMENT_REGISTERS}

    def transfer():
        state, _, _ = transfer_block_with_instruction_states(
            caller.blocks[0], entry, call_preservations=(proof,), source_artifact=caller,
        )
        return state

    assert transfer()["ds"].origin is SegmentOrigin.PROVEN
    if mutation == "registry":
        publish_function_ir_artifact_8616(project, replace(callee))
    elif mutation == "exit_state":
        proof.callee.state.exit_states[callee.function_addr]["ds"] = unknown_segment_state("ds")
    else:
        proof = replace(proof, materialized_count=0)
    assert transfer()["ds"].origin is SegmentOrigin.UNKNOWN


@pytest.fixture
def native_leaf_transfer():
    """Fresh project and symbolic native CALL evidence for each mutation control."""
    from angr_platforms.X86_16.ir.segment_state_transfer import (
        SEGMENT_REGISTERS,
        architectural_live_in_state,
        transfer_block_with_instruction_states,
    )
    from test_x86_16_direct_call_segment_context import _context
    context = _context()
    assert context.complete
    caller = context.caller.artifact
    callee = context.callee.artifact
    closure = prove_segment_effect_closure_8616(
        context.callee, build_x86_16_segment_state_artifact(callee),
    )
    block = next(block for block in caller.blocks if any(i.op == "CALL" for i in block.instrs))
    call = next(i for i in block.instrs if i.op == "CALL")
    assert call.args[0].space is not MemSpace.CONST
    proof = prove_segment_call_preservation_8616(context.caller, closure, context.index, call.addr)
    assert proof.complete
    assert proof.preserved_registers == SEGMENT_REGISTERS
    entry = {name: architectural_live_in_state(name) for name in SEGMENT_REGISTERS}

    def transfer():
        return transfer_block_with_instruction_states(
            block, entry, restore_sources=context.restore_sources,
            call_preservations=(proof,), source_artifact=caller,
        )

    return context.caller.boundary.project, block, call, proof, transfer


def test_native_transfer_relifts_once_per_fresh_snapshot(native_leaf_transfer, monkeypatch):
    """Count actual factory requests; the paired projection reuses only this walk."""
    project, block, call, _, transfer = native_leaf_transfer
    original = project.factory.block
    lifts = []

    def counted(address, *args, **kwargs):
        if (address == block.addr and kwargs.get("size") == call.addr + 3 - block.addr
                and kwargs.get("opt_level") == 0 and kwargs.get("collect_data_refs") is True):
            lifts.append(address)
        return original(address, *args, **kwargs)

    monkeypatch.setattr(project.factory, "block", counted)
    first = transfer()
    assert len(lifts) == 1  # Baseline is expected to make two real requests here.
    second = transfer()
    assert len(lifts) == 2
    assert second == first  # Exit and every before/after instruction projection.
    assert first[0]["ds"].origin is SegmentOrigin.PROVEN


@pytest.mark.parametrize("mutation", ("displacement", "control_domain"))
def test_native_mutation_after_transfer_refuses_and_restore_revalidates(
    native_leaf_transfer, mutation, monkeypatch,
):
    """Native freshness survives paired reads and restored bytes trigger a new lift."""
    from angr_platforms.X86_16.control_coordinates import ControlAddressDomain
    from angr_platforms.X86_16.ir.segment_state_transfer import SEGMENT_REGISTERS
    project, block, call, proof, transfer = native_leaf_transfer
    original = project.factory.block
    lifts = []

    def counted(address, *args, **kwargs):
        if (address == block.addr and kwargs.get("size") == call.addr + 3 - block.addr
                and kwargs.get("opt_level") == 0 and kwargs.get("collect_data_refs") is True):
            lifts.append(address)
        return original(address, *args, **kwargs)

    monkeypatch.setattr(project.factory, "block", counted)
    accepted = transfer()
    assert all(accepted[0][name].origin is SegmentOrigin.PROVEN for name in SEGMENT_REGISTERS)
    assert lifts  # The fixture must really exercise native validation.
    before_mutation = len(lifts)
    original_bytes = project.loader.memory.load(call.addr, 3)
    original_domain = project.arch.control_address_domain
    try:
        if mutation == "displacement":
            project.loader.memory.store(call.addr + 1, bytes([original_bytes[1] ^ 1]))
        else:
            project.arch.control_address_domain = ControlAddressDomain.ARCHITECTURAL_OFFSET
        refused = transfer()
        assert all(refused[0][name].origin is SegmentOrigin.UNKNOWN for name in SEGMENT_REGISTERS)
        assert not proof.complete
        # Refusal may happen before relifting; do not require costly work after
        # a conclusive byte/domain mismatch. No cached pass may escape either.
    finally:
        project.loader.memory.store(call.addr, original_bytes)
        project.arch.control_address_domain = original_domain
    before_restore = len(lifts)
    restored = transfer()
    assert restored == accepted
    assert len(lifts) > before_restore >= before_mutation
