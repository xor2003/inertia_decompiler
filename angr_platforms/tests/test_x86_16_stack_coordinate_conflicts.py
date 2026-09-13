"""Do not merge BP-relative storage across contradictory captured BP values."""

import pytest
from angr_platforms.X86_16.alias.logical_stack_storage_identity import LogicalStackStorageIdentityFailure8616
from angr_platforms.X86_16.alias.stack_memory_ssa import build_x86_16_stack_memory_ssa_alias_artifact
from angr_platforms.X86_16.analysis.stack_frame_ir import (
    FrameCoordinateStatus8616,
    build_x86_16_ir_frame_access_artifact,
)
from angr_platforms.X86_16.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
)
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.ir.ssa_memory_ranges import StackCoordinateAgreement8616
from x86_16_logical_memory_fixtures import lift_ir_artifact


@pytest.mark.parametrize("rebase", ["", "83c502", "bd0020"])
def test_frame_coordinate_refuses_later_contradictory_bp_access(rebase: str) -> None:
    # Establish BP from entry SP, then access the frame before and after rebase.
    source = lift_ir_artifact(bytes.fromhex("558bec83ec04c746fc1704" + rebase + "8b46fec3"))
    evidence = build_x86_16_ir_frame_access_artifact(source).bp_coordinate
    assert evidence.complete
    if rebase:
        assert evidence.status is FrameCoordinateStatus8616.CONFLICT
        assert evidence.bp_entry_sp_delta is None
        assert evidence.stats.failure_count > 0
    else:
        assert evidence.status is FrameCoordinateStatus8616.PROVEN
        saved_bp_size = 2
        assert evidence.bp_entry_sp_delta == -saved_bp_size


@pytest.mark.parametrize("rebase", ["bd0020", "83c502"])
def test_rebased_bp_does_not_publish_one_stack_storage(rebase: str) -> None:
    # MOV BP,1000h; MOV word [BP-2],1234h; rebase BP; MOV AX,[BP-2]; RET.
    source = lift_ir_artifact(bytes.fromhex("bd0010c746fe3412" + rebase + "8b46fec3"))
    ssa = build_x86_16_function_ssa(source)
    alias = build_x86_16_stack_memory_ssa_alias_artifact(ssa)
    assert ssa.memory_stats.complete
    assert alias.complete
    assert not ssa.memory_accesses
    assert not ssa.memory_bindings
    assert not ssa.memory_overlaps
    assert not alias.facts
    assert not alias.logical_accesses
    assert not alias.logical_storage_identities
    assert alias.stats.failure_count > 0
    assert any(item.kind is StackCoordinateAgreement8616.CONFLICT for item in ssa.memory_refusals)
    assert any(item.failure is LogicalStackStorageIdentityFailure8616.COORDINATE_CONFLICT
               for item in alias.logical_storage_refusals)


def test_repeated_bp_reads_without_rebase_keep_exact_stack_storage() -> None:
    source = lift_ir_artifact(bytes.fromhex("bd0010c746fe34128b46fec3"))
    ssa = build_x86_16_function_ssa(source)
    alias = build_x86_16_stack_memory_ssa_alias_artifact(ssa)
    assert ssa.memory_stats.complete and alias.complete
    assert ssa.memory_accesses
    assert alias.facts
    assert alias.logical_storage_identities


@pytest.mark.parametrize("captured", [False, True])
@pytest.mark.parametrize("offset", [-2, -32])
def test_coordinate_conflicts_follow_captured_definitions_not_current_bp(captured: bool, offset: int) -> None:
    bp = IRValue(MemSpace.REG, name="bp", size=2)
    saved = IRValue(MemSpace.REG, name="bp", size=2, source_tmp=7)
    temporary = IRValue(MemSpace.TMP, name="t7", size=2, source_tmp=7)
    first = IRAddress(MemSpace.SS, base=("bp",), offset=-2, size=2,
                      status=AddressStatus.STABLE, base_values=(saved,))
    second = IRAddress(MemSpace.SS, base=("bp",), offset=offset, size=2,
                       status=AddressStatus.STABLE, base_values=(saved if captured else bp,))
    block = IRBlock(0x1000, instrs=(
        IRInstr("MOV", temporary, (bp,)),
        IRInstr("STORE", None, (first, IRValue(MemSpace.CONST, const=5, size=2))),
        IRInstr("MOV", bp, (IRValue(MemSpace.CONST, const=0x2000, size=2),)),
        IRInstr("LOAD", IRValue(MemSpace.REG, name="ax", size=2), (second,)),
    ))
    ssa = build_x86_16_function_ssa(IRFunctionArtifact(0x1000, blocks=(block,)))
    assert ssa.memory_stats.complete
    assert bool(ssa.memory_accesses) is captured
    assert bool(ssa.memory_refusals) is not captured
