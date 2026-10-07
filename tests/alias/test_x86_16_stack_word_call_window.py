"""Binary-backed local stack word lifetime controls."""

from dataclasses import replace

import pytest
from inertia.ir.core import AddressStatus, IRAddress, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.ir.logical_constant_word_receipt import (
    LogicalConstantWordReceipt8616,
    prove_logical_constant_word_write_8616,
)
from inertia.ir.logical_memory_contracts import IRMemoryAccessKind8616
from inertia.ir.ssa_function import build_x86_16_function_ssa
from tests.fixtures.x86_16_logical_memory_fixtures import lift_ir_artifact

from inertia.alias.stack_word_call_window import (
    StackWordCallWindowFailure8616,
    prove_stack_word_call_window_8616,
)


def _receipt() -> tuple[IRFunctionArtifact, LogicalConstantWordReceipt8616]:
    """Lift a real count PUSH, second argument and near CALL envelope."""
    raw = lift_ir_artifact(bytes.fromhex("b8 03 00 50 b8 01 00 50 e8 00 00 c3"))
    artifact = build_x86_16_function_ssa(raw)
    assert artifact.logical_memory is not None
    access = next(item for item in artifact.logical_memory.accesses
                  if item.kind is IRMemoryAccessKind8616.WRITE and item.address.size == 2)
    return raw, prove_logical_constant_word_write_8616(artifact, access)


def test_disjoint_push_and_call_envelope_preserve_word() -> None:
    raw, receipt = _receipt()
    proof = prove_stack_word_call_window_8616(raw, receipt, 0x1008)
    assert proof.complete and proof.constant == 3
    assert proof.call_boundary_offsets == (4, 5)
    assert len(proof.checked_store_indices) == 4
    assert not replace(proof, checked_store_indices=()).complete
    assert not replace(proof, call_boundary_offsets=(6, 7)).complete
    assert not replace(proof, stats=replace(proof.stats, materialized_count=0)).complete
    assert not replace(proof, source_ir=replace(raw, function_addr=0x2000)).complete


@pytest.mark.parametrize("corruption", ("overlap", "unknown_ss", "unknown_store", "selector", "call", "opaque"))
def test_unproved_window_effects_refuse(corruption: str) -> None:
    raw, receipt = _receipt()
    block = raw.blocks[0]
    assert block is not None
    index = max(lane.instr_index for lane in receipt.access.execution_slices) + 1
    if corruption in {"overlap", "unknown_ss"}:
        address = block.instrs[receipt.access.execution_slices[0].instr_index].args[0]
        assert isinstance(address, IRAddress)
        if corruption == "unknown_ss":
            address = replace(address, offset=address.offset + 16, status=AddressStatus.UNKNOWN)
        instruction = IRInstr("STORE", None, (address, IRValue(MemSpace.CONST, const=0, size=1)),
                              size=1, addr=0x1004)
    elif corruption == "unknown_store":
        instruction = IRInstr("STORE", None,
                              (IRAddress(MemSpace.DS, offset=0, size=1), IRValue(MemSpace.CONST, const=0, size=1)),
                              size=1, addr=0x1004)
    elif corruption == "selector":
        instruction = IRInstr("MOV", IRValue(MemSpace.REG, name="ss", size=2),
                              (IRValue(MemSpace.CONST, const=0, size=2),), size=2, addr=0x1004)
    else:
        instruction = IRInstr("CALL" if corruption == "call" else "DIRTY", None, (), addr=0x1004)
    changed = replace(block, instrs=(*block.instrs[:index], instruction, *block.instrs[index:]))
    raw = replace(raw, blocks=(changed,))
    artifact = build_x86_16_function_ssa(raw)
    current = prove_logical_constant_word_write_8616(artifact, receipt.access)
    assert current.complete
    proof = prove_stack_word_call_window_8616(raw, current, 0x1008)
    expected = {
        "overlap": StackWordCallWindowFailure8616.OVERLAPPING_WRITE,
        "unknown_ss": StackWordCallWindowFailure8616.ADDRESS_UNPROVEN,
        "unknown_store": StackWordCallWindowFailure8616.ADDRESS_UNPROVEN,
        "selector": StackWordCallWindowFailure8616.SELECTOR_CHANGED,
        "call": StackWordCallWindowFailure8616.EFFECT_UNPROVEN,
        "opaque": StackWordCallWindowFailure8616.EFFECT_UNPROVEN,
    }
    assert not proof.complete and proof.failure is expected[corruption]
    assert proof.constant is None and proof.stats.failure_count == 1


def test_missing_selected_call_refuses() -> None:
    """A missing boundary cannot be inferred from a nearby CALL."""
    raw, receipt = _receipt()
    proof = prove_stack_word_call_window_8616(raw, receipt, 0x1009)
    assert not proof.complete and proof.failure is StackWordCallWindowFailure8616.CALL_UNPROVEN


def test_equal_but_foreign_temporary_provenance_refuses() -> None:
    """IR equality excludes source_tmp, but the retained theorem must not."""
    raw, receipt = _receipt()
    artifact = receipt.artifact
    block = artifact.blocks[0]
    index = receipt.access.execution_slices[0].instr_index
    instruction = block.instrs[index]
    address = instruction.args[0]
    assert isinstance(address, IRAddress) and address.base_values
    forged_base = replace(address.base_values[0], source_tmp=99999)
    forged_address = replace(address, base_values=(forged_base,))
    assert forged_address == address
    forged_instruction = replace(instruction, args=(forged_address, instruction.args[1]))
    changed_block = replace(block, instrs=(*block.instrs[:index], forged_instruction, *block.instrs[index + 1:]))
    changed_artifact = replace(artifact, blocks=(changed_block,))
    current = prove_logical_constant_word_write_8616(changed_artifact, receipt.access)
    proof = prove_stack_word_call_window_8616(raw, current, 0x1008)
    assert not proof.complete and proof.failure is StackWordCallWindowFailure8616.SOURCE_UNPROVEN
