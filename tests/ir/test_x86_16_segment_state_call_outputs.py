"""Keep CALL target operands separate from unproved output values."""

from __future__ import annotations

import pytest
from inertia.ir.core import (
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.segment_state import build_x86_16_segment_state_artifact
from inertia.ir.segment_state_transfer import transfer_block_with_instruction_states


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


TARGET_ADDR = 0x8123
CALLSITE_ADDR = 0x100
RETURN_BLOCK_ADDR = 0x103


def _enriched_return_block() -> IRBlock:
    """One enriched return block: CALL_OUTPUT prefix then ``mov ds, ax``."""
    return IRBlock(
        addr=RETURN_BLOCK_ADDR,
        instrs=(
            IRInstr(
                "CALL_OUTPUT",
                IRValue(MemSpace.REG, name="ax", size=2),
                (IRValue(MemSpace.CONST, const=TARGET_ADDR, size=4),),
                size=2,
                addr=CALLSITE_ADDR,
            ),
            IRInstr(
                "MOV",
                IRValue(MemSpace.REG, name="ds", size=2),
                (IRValue(MemSpace.REG, name="ax", size=2),),
                size=2,
                addr=RETURN_BLOCK_ADDR,
            ),
        ),
    )


def test_call_output_does_not_fabricate_ds_provenance() -> None:
    """CALL_OUTPUT output registers must not carry proven CONST provenance."""
    exit_state, _entries, _exits = transfer_block_with_instruction_states(
        _enriched_return_block(), {}
    )
    ds_state = exit_state.get("ds")
    assert ds_state is None or ds_state.origin is not SegmentOrigin.PROVEN, (
        f"ds acquired fabricated provenance: {ds_state!r}"
    )


def test_call_output_does_not_fabricate_segment_const_write() -> None:
    """A CALL_OUTPUT writing a segment register directly is not a CONST_WRITE."""
    block = IRBlock(
        addr=RETURN_BLOCK_ADDR,
        instrs=(
            IRInstr(
                "CALL_OUTPUT",
                IRValue(MemSpace.REG, name="ds", size=2),
                (IRValue(MemSpace.CONST, const=TARGET_ADDR, size=4),),
                size=2,
                addr=CALLSITE_ADDR,
            ),
        ),
    )
    exit_state, _entries, _exits = transfer_block_with_instruction_states(
        block, {}
    )
    ds_state = exit_state.get("ds")
    assert ds_state is None or ds_state.origin is not SegmentOrigin.PROVEN, (
        f"ds acquired fabricated provenance: {ds_state!r}"
    )


def test_call_output_uses_a_synthetic_snapshot_key() -> None:
    """A return-block marker cannot overwrite the original CALL's snapshots."""
    _state, entries, exits = transfer_block_with_instruction_states(_enriched_return_block(), {})
    assert CALLSITE_ADDR not in entries and CALLSITE_ADDR not in exits
    assert (RETURN_BLOCK_ADDR, 0) in entries and (RETURN_BLOCK_ADDR, 0) in exits
    assert RETURN_BLOCK_ADDR in entries and RETURN_BLOCK_ADDR in exits


def test_real_constant_move_still_has_proven_provenance() -> None:
    """Actual MOV operands retain their value meaning."""
    block = IRBlock(RETURN_BLOCK_ADDR, (
        IRInstr("MOV", IRValue(MemSpace.REG, name="ds", size=2),
                (IRValue(MemSpace.CONST, const=0x2345, size=2),), addr=RETURN_BLOCK_ADDR),
    ))
    state, _entries, _exits = transfer_block_with_instruction_states(block, {})
    assert state["ds"].origin is SegmentOrigin.PROVEN
    assert state["ds"].constant_value() == 0x2345
