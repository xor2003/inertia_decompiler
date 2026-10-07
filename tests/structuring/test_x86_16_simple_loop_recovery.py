from __future__ import annotations

from types import SimpleNamespace

import pytest
import inertia.structuring.simple_loop_recovery as simple_loop_recovery

from inertia.structuring.simple_loop_recovery import (
    InsnSummary8616,
    recover_counted_stack_loop_c_8616,
    recover_counted_stack_loop_from_summaries_8616,
)


def test_recover_counted_stack_loop_from_bp_operand_evidence():
    summaries = [
        InsnSummary8616("mov", "bp_mem", -2, "imm", 0, op0_size=2, op1_size=2),
        InsnSummary8616("mov", "bp_mem", -4, "imm", 0, op0_size=2, op1_size=2),
        InsnSummary8616("inc", "bp_mem", -4, op0_size=2),
        InsnSummary8616("mov", "reg", "ax", "bp_mem", 4, op0_size=2, op1_size=2),
        InsnSummary8616("cmp", "bp_mem", -4, "reg", "ax", op0_size=2, op1_size=2),
        InsnSummary8616("test", "bp_mem", -4, "imm", 1, op0_size=1, op1_size=1),
        InsnSummary8616("mov", "reg", "ax", "bp_mem", -4, op0_size=2, op1_size=2),
        InsnSummary8616("add", "bp_mem", -2, "reg", "ax", op0_size=2, op1_size=2),
        InsnSummary8616("dec", "bp_mem", -2, op0_size=2),
        InsnSummary8616("mov", "reg", "ax", "bp_mem", -2, op0_size=2, op1_size=2),
    ]

    recovered = recover_counted_stack_loop_from_summaries_8616(summaries)

    assert recovered is not None
    assert recovered.induction_disp == -4
    assert recovered.accumulator_disp == -2
    assert recovered.limit_disp == 4
    assert recovered.parity_mask == 1


def test_recover_counted_stack_loop_refuses_without_accumulator_return_load():
    summaries = [
        InsnSummary8616("mov", "bp_mem", -2, "imm", 0, op0_size=2, op1_size=2),
        InsnSummary8616("mov", "bp_mem", -4, "imm", 0, op0_size=2, op1_size=2),
        InsnSummary8616("inc", "bp_mem", -4, op0_size=2),
        InsnSummary8616("mov", "reg", "ax", "bp_mem", 4, op0_size=2, op1_size=2),
        InsnSummary8616("cmp", "bp_mem", -4, "reg", "ax", op0_size=2, op1_size=2),
        InsnSummary8616("test", "bp_mem", -4, "imm", 1, op0_size=1, op1_size=1),
        InsnSummary8616("mov", "reg", "ax", "bp_mem", -4, op0_size=2, op1_size=2),
        InsnSummary8616("add", "bp_mem", -2, "reg", "ax", op0_size=2, op1_size=2),
        InsnSummary8616("dec", "bp_mem", -2, op0_size=2),
    ]

    assert recover_counted_stack_loop_from_summaries_8616(summaries) is None


def test_source_recovery_does_not_decode_after_authoritative_inventory_miss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        simple_loop_recovery,
        "_function_instruction_summaries_8616",
        lambda *_args: [],
    )

    def reject_duplicate_decode(*_args: object, **_kwargs: object) -> list[InsnSummary8616]:
        raise AssertionError("authoritative instruction summaries must not be decoded again")

    monkeypatch.setattr(
        simple_loop_recovery,
        "_linear_instruction_summaries_8616",
        reject_duplicate_decode,
    )

    result = recover_counted_stack_loop_c_8616(
        object(),
        SimpleNamespace(addr=0x1000, name="no_loop"),
    )

    assert result is None
