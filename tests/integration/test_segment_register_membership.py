"""Equivalent segment-register membership must preserve exact stack facts."""

import pytest
from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.segment_state_transfer import SEGMENT_REGISTERS

from inertia.alias.segment_stack_restore import (
    SegmentStackRestoreVerdict8616,
    build_x86_16_segment_stack_restore_artifact,
    build_x86_16_stack_register_restore_artifact_8616,
)


def _constant_restore(register):
    address = IRAddress(MemSpace.SS, ("sp",), 0, 2, AddressStatus.STABLE, SegmentOrigin.PROVEN)
    loaded = IRValue(MemSpace.TMP, name="saved_word", size=2)
    return IRFunctionArtifact(function_addr=0x1000, blocks=(IRBlock(addr=0x1000, instrs=(
        IRInstr("STORE", None, (address, IRValue(MemSpace.CONST, const=0x1234, size=2)), addr=0x1000),
        IRInstr("LOAD", loaded, (address,), addr=0x1002),
        IRInstr("MOV", IRValue(MemSpace.REG, name=register, size=2), (loaded,), addr=0x1002),
    )),))


@pytest.mark.parametrize("register", SEGMENT_REGISTERS)
def test_explicit_segment_membership_preserves_constant_restore(register):
    artifact = _constant_restore(register)
    default = build_x86_16_segment_stack_restore_artifact(artifact)
    explicit = build_x86_16_stack_register_restore_artifact_8616(
        artifact, tracked_registers=frozenset(SEGMENT_REGISTERS),
    )

    assert default.facts == explicit.facts
    assert explicit.summary == default.summary
    assert explicit.summary["materialized_count"] == 1
    assert explicit.summary["failure_count"] == 0
    assert explicit.facts[0].constant_value == 0x1234
    assert explicit.facts[0].stack_offsets == (0, 1)
    assert explicit.facts[0].verdict is SegmentStackRestoreVerdict8616.PROVEN


def test_general_register_tracking_does_not_enable_segment_constant_rules():
    artifact = build_x86_16_stack_register_restore_artifact_8616(
        _constant_restore("ax"), tracked_registers=frozenset({"ax"}),
    )
    assert artifact.summary["failure_count"] == 1
    assert artifact.summary["materialized_count"] == 0
    assert artifact.facts[0].verdict is SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE
