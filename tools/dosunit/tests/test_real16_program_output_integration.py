"""Declared byte-stream execution controls, separate from universal proof."""

from dataclasses import replace

from tools.dosunit.tests.test_real16_program_replay import environment, mz

from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.reporting.real16_program_manifest import parse_program_manifest
from tools.dosunit.runtime.real16_program_model import ProgramAgreement, ProgramStatus, compare_programs
from tools.dosunit.runtime.real16_program_replay import replay_program


def stream_environment(*, handles=(1, 2), cap=32):
    base = environment()
    return parse_program_manifest({
        "schema": "dosunit.real16_program_environment.v1",
        "environment": {"psp_segment": base.psp_segment, "allocation_hex": base.allocation.hex(),
                        "registers": dict(base.registers), "fs": 0, "gs": 0,
                        "output_streams": {"handles": list(handles), "max_call_bytes": cap, "max_total_bytes": cap}},
    }).environment


def execute(code, *, enabled=True, cap=32):
    env = stream_environment(cap=cap) if enabled else environment()
    return replay_program(program_from_mz_bytes(mz(bytes.fromhex(code)), env), instruction_limit=100)


# PSP:0200 contains 03 A5; the explicit stream writes these existing bytes.
WRITE_TWO = "bb0100ba0002b90200b440cd21b8004ccd21"
SPLIT_TWO = "bb0100ba0002b90100b440cd2142b90100b440cd21b8004ccd21"


def test_output_is_opt_in_and_does_not_promote_replay_to_proof():
    refused = execute(WRITE_TWO, enabled=False)
    accepted = execute(WRITE_TWO)
    assert refused.status is ProgramStatus.UNSUPPORTED
    assert accepted.status is ProgramStatus.TERMINATED
    assert compare_programs(accepted, accepted) is ProgramAgreement.AGREED
    assert compare_programs(refused, accepted) is ProgramAgreement.INCOMPLETE


def test_split_writes_agree_but_changed_stream_bytes_or_handle_mismatch():
    original = execute(WRITE_TWO)
    assert compare_programs(original, execute(SPLIT_TWO)) is ProgramAgreement.AGREED
    changed = execute(WRITE_TWO.replace("ba0002", "ba0102"))
    assert compare_programs(original, changed) is ProgramAgreement.MISMATCHED
    other = execute(WRITE_TWO.replace("bb0100", "bb0200"))
    assert compare_programs(original, other) is ProgramAgreement.MISMATCHED


def test_unknown_handle_outside_buffer_and_aggregate_budget_stay_incomplete():
    for code, cap in ((WRITE_TWO.replace("bb0100", "bb0300"), 32),
                      (WRITE_TWO.replace("ba0002", "ba0020"), 32), (SPLIT_TWO, 1)):
        result = execute(code, cap=cap)
        assert result.status is ProgramStatus.UNSUPPORTED
        assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE


def test_service_preserves_unowned_state_and_returns_ax_count_cf_clear():
    # After write, trap at a bare RET preserves the service return diagnostics.
    result = execute("66b800400040bb0100ba0002b90200f9cd21c3")
    regs = dict(result.registers)
    assert result.status is ProgramStatus.UNSUPPORTED
    assert regs["eax"] == 0x40000002
    assert regs["eflags"] & 1 == 0
    assert (regs["bx"], regs["cx"], regs["dx"]) == (1, 2, 0x200)


def test_missing_exit_and_undeclared_service_receipts_never_agree():
    complete = execute(WRITE_TWO)
    assert compare_programs(complete, replace(complete, events=complete.events[:-1])) is ProgramAgreement.INCOMPLETE


def test_output_policy_changes_boot_and_environment_identity():
    narrow = execute(WRITE_TWO, cap=2)
    wide = execute(WRITE_TWO, cap=32)
    assert narrow.boot_identity != wide.boot_identity
    assert narrow.environment_identity != wide.environment_identity
    assert compare_programs(narrow, wide) is ProgramAgreement.INCOMPLETE


def test_zero_write_does_not_dereference_an_outside_pointer():
    result = execute("bb0100baffff31c9b440cd21b8004ccd21")
    assert result.status is ProgramStatus.TERMINATED
    empty = execute("b8004ccd21")
    assert compare_programs(empty, result) is ProgramAgreement.AGREED


def test_public_report_records_output_contract_and_receipts(tmp_path):
    import json

    from tools.dosunit.tests.test_real16_program_cli import arguments, document

    from tools.dosunit.reporting.real16_program_cli import cmd_replay_program16

    args = arguments(tmp_path)
    args.oracle_exe.write_bytes(mz(bytes.fromhex(WRITE_TWO)))
    args.candidate_exe.write_bytes(mz(bytes.fromhex(SPLIT_TWO)))
    declared = document()
    declared["environment"]["output_streams"] = {"handles": [1, 2], "max_call_bytes": 32, "max_total_bytes": 32}
    args.environment.write_text(json.dumps(declared))
    assert cmd_replay_program16(args) == 0
    report = json.loads(args.out.read_text())
    assert report["proof_status"] == "not_established_by_execution"
    assert report["contract"]["services"]["output_streams"]["handles"] == [1, 2]
    assert report["oracle"]["requested_streams"] == [1, 2]
    assert report["oracle"]["events"][0]["bytes"] == "01a5a5"


def test_parent_review_rejects_bool_handles_and_unrepresentable_ax():
    import pytest

    from tools.dosunit.runtime.real16_program_output import OutputAccepted, OutputRefusal, OutputRefused

    for handle in (True, 1.0):
        with pytest.raises(ValueError):
            OutputAccepted(handle, b"", 0, False)
        with pytest.raises(ValueError):
            OutputRefused(handle, OutputRefusal.UNSUPPORTED_HANDLE)
    with pytest.raises(ValueError):
        OutputAccepted(1, bytes(0x10000), 0x10000, False)
