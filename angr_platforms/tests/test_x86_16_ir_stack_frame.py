from dataclasses import replace

import pytest
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
from x86_16_logical_memory_fixtures import lift_ir_artifact


def test_ir_stack_frame_artifact_classifies_bp_args_and_locals():
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr(
                        "LOAD",
                        IRValue(MemSpace.REG, name="ax", size=2),
                        (IRAddress(MemSpace.SS, base=("bp",), offset=4, size=2, status=AddressStatus.PROVISIONAL),),
                        size=2,
                    ),
                    IRInstr(
                        "STORE",
                        None,
                        (
                            IRAddress(MemSpace.SS, base=("bp",), offset=-2, size=2, status=AddressStatus.PROVISIONAL),
                            IRValue(MemSpace.CONST, const=1),
                        ),
                        size=2,
                    ),
                ),
            ),
        ),
    )

    frame = build_x86_16_ir_frame_access_artifact(artifact)

    assert [(slot.offset, slot.role) for slot in frame.slots] == [(-2, "local"), (4, "arg")]
    assert frame.bp_coordinate.status is FrameCoordinateStatus8616.UNKNOWN


def test_ir_stack_frame_artifact_proves_bp_entry_sp_coordinate() -> None:
    """Typed SP and BP effects prove the coordinate used by Lowering."""
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="sp", size=2),
                        (IRValue(MemSpace.REG, name="sp", offset=-2, size=2),),
                        size=2,
                        addr=0x1000,
                    ),
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="bp", size=2),
                        (IRValue(MemSpace.REG, name="sp", size=2),),
                        size=2,
                        addr=0x1001,
                    ),
                    IRInstr(
                        "STORE",
                        None,
                        (
                            IRAddress(MemSpace.SS, base=("bp",), offset=-2, size=2),
                            IRValue(MemSpace.REG, name="ax", size=2),
                        ),
                        size=2,
                        addr=0x1003,
                    ),
                ),
            ),
        ),
    )

    frame = build_x86_16_ir_frame_access_artifact(artifact)

    assert frame.bp_coordinate.status is FrameCoordinateStatus8616.PROVEN
    assert frame.bp_coordinate.bp_entry_sp_delta == -2
    assert frame.bp_coordinate.complete is True
    assert frame.bp_coordinate.stats.to_dict() == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
    }


@pytest.mark.parametrize("code,expected_delta", [
    ("89e589c58b46fec3", None),  # MOV BP,SP; MOV BP,AX; load [BP-2].
    ("89e5bd34128b46fec3", None),  # A constant BP is not entry-SP-relative.
    ("89e589c489e58b46fec3", None),  # SP becomes unknown before BP is reset.
    ("89e589c589e58b46fec3", 0),  # A later proven write replaces the unknown BP.
    ("89e589c48b46fec3", 0),  # Changing SP alone does not invalidate the saved BP relation.
    ("5589e583ec0289e58b46fec3", -4),  # Only the reaching frame setup applies.
    ("5589e58b46fec3", -2),
    ("c80000008b46fec3", -2),  # ENTER saves BP before allocating locals.
    ("c80200008b46fec3", -2),
    ("c81000008b46fec3", -2),
    ("5589e089c58b46fec3", -2),  # SP reaches BP through AX.
    ("89e083e80289c489e58b46fec3", -2),  # A proven AX expression restores SP's origin.
])
def test_frame_coordinate_uses_reaching_bp_write(code, expected_delta):
    """Overwritten frame candidates cannot prove or conflict with the live BP."""
    frame = build_x86_16_ir_frame_access_artifact(lift_ir_artifact(bytes.fromhex(code)))
    proof = frame.bp_coordinate

    assert proof.complete
    assert proof.bp_entry_sp_delta == expected_delta
    assert proof.status is (
        FrameCoordinateStatus8616.UNKNOWN if expected_delta is None else FrameCoordinateStatus8616.PROVEN
    )
    assert proof.stats.normalized_fact_count == proof.stats.classified_fact_count == 1
    assert proof.stats.materialized_count == (expected_delta is not None)
    assert proof.stats.failure_count == (expected_delta is None)


def test_reentered_setup_does_not_prove_function_entry_sp():
    artifact = lift_ir_artifact(bytes.fromhex("5589e089c58b46fec3"))
    entry = replace(artifact.blocks[0], successor_addrs=(artifact.function_addr,))
    frame = build_x86_16_ir_frame_access_artifact(replace(artifact, blocks=(entry,)))
    assert frame.bp_coordinate.status is FrameCoordinateStatus8616.UNKNOWN
    assert frame.bp_coordinate.bp_entry_sp_delta is None
