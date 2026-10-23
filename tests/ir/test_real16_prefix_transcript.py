"""Detached census data capture never supplies proof or reuse authority."""

from dataclasses import replace
from time import monotonic

import pytest

from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr
from inertia.ir.real16_path_memory8616 import PathMemory8616
from inertia.ir.real16_prefix_transcript import (
    PrefixCaptureBinding8616,
    PrefixCaptureBudget8616,
    PrefixCaptureFailure8616,
    PrefixCaptureInput8616,
    PrefixCaptureOrigin8616,
    PrefixCaptureRow8616,
    PrefixCaptureState8616,
    capture_prefix_transcript_8616,
)

pytestmark = pytest.mark.decompiler


def source():
    instruction = IRInstr("CALL", None, (), addr=10)
    block = IRBlock(1, (instruction,))
    artifact = IRFunctionArtifact(1, (block,))
    binding = PrefixCaptureBinding8616(
        object(), object(), object(), object(), artifact, object(), object(),
        object(), object(), object(), (), (), (),
    )
    state = PrefixCaptureState8616({"ax": 7}, PathMemory8616({100: 3}, {101}), False,
                                 {2: 7}, {"ax"}, {"ax": 6}, 10)
    row = PrefixCaptureRow8616(artifact, block, 0, instruction, block, instruction)
    return PrefixCaptureInput8616(
        binding, PrefixCaptureOrigin8616.CURRENT_CANONICAL, state, state, row,
        {(1, 0)}, {(1, 0)}, {(1, 0)}, {(1, 0)}, (1, 1, 1, 1, 0),
        (row,), {(10, 3)}, {10: b"abc"},
    )


def capture(value, units=10000, deadline=None):
    return capture_prefix_transcript_8616(
        value, budget=PrefixCaptureBudget8616(units, monotonic() + 10 if deadline is None else deadline),
    )


def test_detached_data_and_exact_owners():
    value = source()
    result = capture(value)
    assert result.failure is None
    assert not result.authorizes_reuse
    payload = result.payload
    assert payload.binding is value.binding
    assert payload.rows[0].row is value.rows[0].row
    assert payload.raw_facts == frozenset({(1, 0)})
    assert payload.call_state.registers == (("ax", 7),)
    value.call_state.registers["ax"] = 99
    value.call_state.memory.apply_write(100, 1, b"x")
    value.call_state.tmps.clear()
    value.call_state.dirty.clear()
    value.call_state.instruction_entry.clear()
    value.raw_facts.clear()
    value.machine_bytes[10] = b"changed"
    assert payload.call_state.registers == (("ax", 7),)
    assert payload.call_state.memory.known == ((100, 3),)
    assert payload.call_state.tmps == ((2, 7),)
    assert payload.call_state.dirty == ("ax",)
    assert payload.call_state.instruction_entry == (("ax", 6),)
    assert payload.call_state.current_addr == 10
    assert payload.raw_facts == frozenset({(1, 0)})
    assert payload.machine_bytes == ((10, b"abc"),)


@pytest.mark.parametrize("origin", [
    PrefixCaptureOrigin8616.FAILED, PrefixCaptureOrigin8616.PARTIAL,
    PrefixCaptureOrigin8616.CACHED, PrefixCaptureOrigin8616.TRANSPORTED,
])
def test_noncurrent_claims_refuse(origin):
    result = capture(replace(source(), origin=origin))
    assert result.failure is PrefixCaptureFailure8616.ORIGIN
    assert result.payload is None
    assert not result.authorizes_reuse


def test_current_claim_is_data_not_seal():
    result = capture(source())
    assert result.payload is not None
    assert result.authorizes_reuse is False


def test_tainted_memory_refuses():
    value = source()
    value.call_state.memory.taint()
    assert capture(value).failure is PrefixCaptureFailure8616.MEMORY


def test_seed_taint_refuses():
    value = source()
    value.seed.memory.taint()
    assert capture(value).failure is PrefixCaptureFailure8616.MEMORY


def test_duplicate_rows_refuse():
    value = source()
    assert capture(replace(value, rows=value.rows * 2)).failure is PrefixCaptureFailure8616.ROWS


def test_native_row_identity_refuses_equal_copy():
    value = source()
    forged = replace(value.call_row, native_row=replace(value.call_row.native_row))
    assert capture(replace(value, rows=(forged,), call_row=forged)).failure is PrefixCaptureFailure8616.ROWS


@pytest.mark.parametrize("counts", [(1, 1, 1, 0, 1), (2, 1, 1, 1, 0), (True, 1, 1, 1, 0)])
def test_invalid_counts(counts):
    assert capture(replace(source(), counts=counts)).failure is PrefixCaptureFailure8616.FACTS


def test_same_counts_foreign_fact_keys_refuse():
    value = replace(source(), materialized_facts={(2, 0)})
    assert capture(value).failure is PrefixCaptureFailure8616.FACTS


def test_conflicting_memory_refuses():
    value = source()
    value.call_state.memory.unknown.add(100)
    assert capture(value).failure is PrefixCaptureFailure8616.MEMORY


def test_foreign_selected_row_refuses():
    value = source()
    foreign = replace(value.call_row, row=replace(value.call_row.row))
    assert capture(replace(value, call_row=foreign)).failure is PrefixCaptureFailure8616.ROWS


def test_budget_and_deadline_refuse():
    assert capture(source(), units=0).failure is PrefixCaptureFailure8616.WORK
    assert capture(source(), deadline=0).failure is PrefixCaptureFailure8616.DEADLINE


def test_capture_deterministic():
    value = source()
    assert capture(value).payload == capture(value).payload


def test_all_work_cutoffs_leave_census_unchanged():
    value = source()
    required = capture(value).work_units
    for units in range(required):
        result = capture(value, units=units)
        assert result.failure is PrefixCaptureFailure8616.WORK
        assert result.payload is None
        assert result.work_units <= units
        assert value.counts == (1, 1, 1, 1, 0)
        assert value.raw_facts == {(1, 0)}
        assert value.call_state.registers == {"ax": 7}


def test_realistic_fact_capture_work():
    value = source()
    instructions = tuple(IRInstr("CALL" if index == 1671 else "TMP", None, (), addr=10 + index)
                         for index in range(1672))
    block = IRBlock(1, instructions)
    artifact = IRFunctionArtifact(1, (block,))
    rows = tuple(PrefixCaptureRow8616(artifact, block, index, instruction, block, instruction)
                 for index, instruction in enumerate(instructions))
    keys = {(1, index) for index in range(1672)}
    value = replace(value, binding=replace(value.binding, artifact=artifact), rows=rows,
                    call_row=rows[-1], raw_facts=keys, normalized_facts=keys,
                    classified_facts=keys, materialized_facts=keys,
                    counts=(1672, 1672, 1672, 1672, 0))
    result = capture(value, units=20000)
    assert result.failure is None
    assert len(result.payload.raw_facts) == 1672
    assert result.work_units < 20000
