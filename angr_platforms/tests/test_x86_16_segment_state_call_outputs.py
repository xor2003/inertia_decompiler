"""Keep CALL target operands separate from unproved output values."""

from __future__ import annotations

import pytest
from angr_platforms.X86_16.ir.core import (
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from angr_platforms.X86_16.ir.segment_state import build_x86_16_segment_state_artifact


def _reg(name: str) -> IRValue:
    return IRValue(MemSpace.REG, name=name, size=2)


@pytest.mark.parametrize("output_register", ["ax", "ds", "es", "ss", "cs"])
def test_call_output_cannot_reprove_segment_from_target(output_register: str) -> None:
    """A CALL's target is not an assignment to its result carrier."""
    artifact = IRFunctionArtifact(0x1000, (IRBlock(0x1000, (
        IRInstr("CALL", _reg(output_register),
                (IRValue(MemSpace.CONST, const=0x2000, size=2),), addr=0x1000),
        IRInstr("MOV", _reg("ds"), (_reg(output_register),), addr=0x1003),
    )),))
    state = build_x86_16_segment_state_artifact(artifact)
    after = state.state_after_instruction(0x1003, "ds")
    assert after is not None and after.origin is SegmentOrigin.UNKNOWN
    assert after.source is None


@pytest.mark.parametrize("output_register", ["ds", "es", "ss", "cs"])
def test_call_segment_output_counts_as_one_refused_boundary(output_register: str) -> None:
    """An unproved CALL result is not a separate explicit segment write."""
    artifact = IRFunctionArtifact(0x1000, (IRBlock(0x1000, (
        IRInstr("CALL", _reg(output_register),
                (IRValue(MemSpace.CONST, const=0x2000, size=2),), addr=0x1000),
    )),))
    state = build_x86_16_segment_state_artifact(artifact)
    assert state.summary["explicit_write_count"] == 0
    assert state.summary["call_boundary_count"] == 1
    assert tuple(state.summary[key] for key in (
        "raw_fact_count", "normalized_fact_count", "classified_fact_count",
        "materialized_count", "failure_count",
    )) == (1, 1, 0, 0, 1)
