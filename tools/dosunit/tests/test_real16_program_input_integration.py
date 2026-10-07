"""Actual initialized MZ file-input controls; agreement is concrete only."""

from tools.dosunit.tests.test_real16_program_replay import environment, mz

from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.reporting.real16_program_manifest import parse_program_manifest
from tools.dosunit.runtime.real16_program_model import ProgramAgreement, ProgramObservation, ProgramStatus, compare_programs
from tools.dosunit.runtime.real16_program_replay import replay_program
from tools.dosunit.runtime.real16_replay_model import LinearRange


def input_environment(*, data="41424344", cursor=0, cap=32):
    base = environment()
    return parse_program_manifest({
        "schema": "dosunit.real16_program_environment.v1",
        "environment": {"psp_segment": base.psp_segment, "allocation_hex": base.allocation.hex(),
                        "registers": dict(base.registers), "fs": 0, "gs": 0,
                        "input_files": {"files": [{"handle": 5, "bytes": data, "cursor": cursor}],
                                        "max_call_bytes": cap, "max_total_bytes": cap}},
    }).environment


def execute(code, *, env=None):
    boot = program_from_mz_bytes(mz(bytes.fromhex(code)), input_environment() if env is None else env)
    return replay_program(boot, observations=(ProgramObservation("buffer", LinearRange(0x10200, 4)),),
                          instruction_limit=100)


READ_TWO = "bb0500ba0002b90200b43fcd21b8004ccd21"
READ_FOUR = READ_TWO.replace("b90200", "b90400")
SPLIT_FOUR = "bb0500ba0002b90200b43fcd21ba0202b90200b43fcd21b8004ccd21"


def test_declared_file_read_terminates_and_materializes_exact_bytes():
    result = execute(READ_FOUR)
    assert result.status is ProgramStatus.TERMINATED
    assert result.observations == (("buffer", b"ABCD"),)
    assert result.writes == ((0x10200, b"ABCD"), (0x110FA, bytes.fromhex("120010100200")))
    assert compare_programs(result, result) is ProgramAgreement.AGREED


def test_split_reads_agree_but_changed_buffer_pointer_mismatches():
    original = execute(READ_FOUR)
    assert compare_programs(original, execute(SPLIT_FOUR)) is ProgramAgreement.AGREED
    assert compare_programs(original, execute(READ_FOUR.replace("ba0002", "ba0102"))) is ProgramAgreement.MISMATCHED


def test_default_environment_does_not_invent_file_handles():
    result = execute(READ_TWO, env=environment())
    assert result.status is ProgramStatus.UNSUPPORTED
    assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE


def test_file_payload_and_cursor_change_boot_and_environment_identities():
    original = execute(READ_TWO)
    for env in (input_environment(data="41424345"), input_environment(cursor=1)):
        changed = execute(READ_TWO, env=env)
        assert original.boot_identity != changed.boot_identity
        assert original.environment_identity != changed.environment_identity
        assert compare_programs(original, changed) is ProgramAgreement.INCOMPLETE


def test_short_read_and_eof_do_not_touch_unreturned_buffer_bytes():
    partial = execute(READ_FOUR, env=input_environment(data="4142"))
    assert partial.status is ProgramStatus.TERMINATED
    assert partial.observations == (("buffer", b"AB\xa5\xa5"),)
    assert partial.writes == ((0x10200, b"AB"), (0x110FA, bytes.fromhex("120010100200")))
    empty = execute(READ_FOUR.replace("ba0002", "baffff"), env=input_environment(data="", cursor=10))
    assert empty.status is ProgramStatus.TERMINATED
    assert empty.writes == ((0x110FA, bytes.fromhex("120010100200")),)


def test_seek_changes_explicit_cursor_and_returns_full_dx_ax_position():
    # Seek absolute1, then read two bytes into the named buffer.
    code = "bb050031c9ba0100b80042cd21ba0002b90200b43fcd21b8004ccd21"
    result = execute(code)
    assert result.status is ProgramStatus.TERMINATED
    assert result.observations == (("buffer", b"BC\xa5\xa5"),)


def test_input_service_refuses_unknown_handle_budget_and_code_destination():
    for code, env in ((READ_TWO.replace("bb0500", "bb0600"), input_environment()),
                      (READ_TWO, input_environment(cap=1)),
                      (READ_TWO.replace("ba0002", "ba0001"), input_environment())):
        result = execute(code, env=env)
        assert result.status is ProgramStatus.UNSUPPORTED
        # INT entry happened, but no file bytes or file cursor were committed.
        assert result.writes == ((0x110FA, bytes.fromhex("0d0010100200")),)
        assert result.input_file_positions == result.requested_input_files
        assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE


def test_read_preserves_upper_register_halves_and_clears_only_carry():
    # AH3F in the lowword of a full386 EAX; the refused RET captures returned AX.
    result = execute("66b8003f0040bb0500ba0002b90200f9cd21c3")
    regs = dict(result.registers)
    assert result.status is ProgramStatus.UNSUPPORTED
    assert regs["eax"] == 0x40000002
    assert (regs["bx"], regs["cx"], regs["dx"]) == (5, 2, 0x200)
    assert regs["eflags"] & 1 == 0


def test_missing_or_discontinuous_file_projection_cannot_agree():
    from dataclasses import replace

    from tools.dosunit.runtime.real16_program_file_receipts import FileOperation, FileReceipt

    base = execute("b8004ccd21", env=environment())
    receipt = FileReceipt(FileOperation.READ, 5, 0, 2, b"AB")
    complete = replace(base, requested_input_files=((5, 0),), input_file_positions=((5, 2),),
                       file_receipts=(receipt,))
    assert compare_programs(complete, complete) is ProgramAgreement.AGREED
    for invalid in (replace(complete, file_receipts=()),
                    replace(complete, input_file_positions=()),
                    replace(complete, file_receipts=(receipt, receipt)),
                    replace(complete, requested_input_files=((5, 1),)),
                    replace(complete, input_file_positions=((5, 2), (5, 2)))):
        assert compare_programs(complete, invalid) is ProgramAgreement.INCOMPLETE
    moved = replace(base, requested_input_files=((5, 0),), input_file_positions=((5, 3),),
                    file_receipts=(FileReceipt(FileOperation.SEEK, 5, 0, 3),))
    assert compare_programs(complete, moved) is ProgramAgreement.MISMATCHED


def test_file_receipt_rejects_malformed_state_and_payload_contracts():
    import pytest

    from tools.dosunit.runtime.real16_program_file_receipts import FileOperation, FileReceipt

    for values in ((FileOperation.READ, True, 0, 0, b""),
                   (FileOperation.READ, 5, False, 0, b""),
                   (FileOperation.READ, 5, 0, 2, b"A"),
                   (FileOperation.SEEK, 5, 0, 2, b"A"),
                   ("read", 5, 0, 0, b"")):
        with pytest.raises(ValueError):
            FileReceipt(*values)


def test_parent_review_seek_rejects_corrupt_served_budget():
    import pytest

    from tools.dosunit.runtime.real16_program_input import (
        InputFile,
        InputPolicy,
        SeekOrigin,
        program_input_runtime,
        program_input_seek,
    )

    policy = InputPolicy((InputFile(5, b"AB", 0),), 2, 2)
    for served in (True, -1, 3):
        runtime = program_input_runtime(policy)
        runtime.served = served
        with pytest.raises(ValueError):
            program_input_seek(policy, runtime, handle=5, origin=SeekOrigin.BEGIN, distance=0)


def test_parent_review_success_records_cannot_admit_predefined_handles():
    import pytest

    from tools.dosunit.runtime.real16_program_input import ReadAccepted, SeekAccepted
    from tools.dosunit.runtime.real16_replay_model import SegOffset

    for handle in (0, 4):
        with pytest.raises(ValueError):
            ReadAccepted(handle, SegOffset(0x1000, 0x200), b"", 0, False, 0)
        with pytest.raises(ValueError):
            SeekAccepted(handle, 0, 0, False, 0)


def test_parent_review_read_receipt_rejects_bool_segment_coordinates():
    import pytest

    from tools.dosunit.runtime.real16_program_input import ReadAccepted
    from tools.dosunit.runtime.real16_replay_model import SegOffset

    with pytest.raises(ValueError):
        ReadAccepted(5, SegOffset(True, 0), b"", 0, False, 0)


def test_actual_seek_reports_full_dx_ax_cursor_and_negative_relative_offsets():
    result = execute("66b800420040bb0500b90100ba4523f9cd21c3")
    regs = dict(result.registers)
    assert result.status is ProgramStatus.UNSUPPORTED
    assert regs["eax"] == 0x40002345 and regs["dx"] == 1
    assert result.input_file_positions == ((5, 0x12345),)
    # END-1 gives position3, followed by a read at the last byte.
    relative = execute("bb0500b9ffffbaffffb80242cd21ba0002b90200b43fcd21b8004ccd21")
    assert relative.status is ProgramStatus.TERMINATED
    assert relative.observations == (("buffer", b"D\xa5\xa5\xa5"),)
    assert relative.input_file_positions == ((5, 4),)


def test_public_file_declaration_and_receipts_validate_against_schemas(tmp_path):
    import json
    from pathlib import Path

    from jsonschema import Draft202012Validator
    from tools.dosunit.tests.test_real16_program_cli import arguments, document

    from tools.dosunit.reporting.real16_program_cli import cmd_replay_program16

    args = arguments(tmp_path)
    args.oracle_exe.write_bytes(mz(bytes.fromhex(READ_FOUR)))
    args.candidate_exe.write_bytes(mz(bytes.fromhex(SPLIT_FOUR)))
    declared = document()
    declared["observations"] = [{"name": "buffer", "size": 4,
                                 "oracle_address": 0x10200, "candidate_address": 0x10200}]
    declared["environment"]["input_files"] = {"files": [{"handle": 5, "bytes": "41424344", "cursor": 0}],
                                              "max_call_bytes": 32, "max_total_bytes": 32}
    args.environment.write_text(json.dumps(declared))
    assert cmd_replay_program16(args) == 0
    report = json.loads(args.out.read_text())
    assert report["proof_status"] == "not_established_by_execution"
    assert report["oracle"]["requested_input_files"] == [{"handle": 5, "cursor": 0}]
    assert report["oracle"]["input_file_positions"] == [{"handle": 5, "cursor": 4}]
    assert len(report["candidate"]["file_receipts"]) == 2
    assert report["contract"]["services"]["input_files"]["files"][0]["size"] == 4
    schemas = Path(__file__).resolve().parents[3] / "tools/dosunit/schemas"
    for name, data in (("dosunit.real16_program_environment.v1", declared),
                       ("dosunit.real16_program_replay.v1", report)):
        Draft202012Validator(json.loads((schemas / f"{name}.schema.json").read_text())).validate(data)


def test_malformed_input_declaration_prevents_binary_reads(tmp_path):
    import json

    import pytest
    from tools.dosunit.tests.test_real16_program_cli import arguments, document

    from tools.dosunit.contracts.model import DosUnitError
    from tools.dosunit.reporting.real16_program_cli import cmd_replay_program16

    args = arguments(tmp_path)
    declared = document()
    declared["environment"]["input_files"] = {"files": [{"handle": True, "bytes": "4142", "cursor": 0}],
                                              "max_call_bytes": 32, "max_total_bytes": 32}
    args.environment.write_text(json.dumps(declared))
    args.oracle_exe.unlink()
    with pytest.raises(DosUnitError, match="invalid program environment"):
        cmd_replay_program16(args)
    assert not args.out.exists()


def test_parent_review_runtime_requires_the_complete_exact_handle_set():
    import pytest

    from tools.dosunit.runtime.real16_program_input import (
        InputFile,
        InputPolicy,
        InputRuntime,
        SeekOrigin,
        program_input_read,
        program_input_seek,
    )

    policy = InputPolicy((InputFile(5, b"AB", 0), InputFile(6, b"CD", 0)), 2, 4)
    for cursors in ({5: 0}, {5: 0, 6: 0, 7: 0}, {5.0: 0, 6: 0}, {5: 0, 6: True}):
        runtime = InputRuntime(cursors.copy())
        with pytest.raises(ValueError):
            program_input_read(policy, runtime, handle=5, segment=0x1000, offset=0x200,
                               count=2, allocation=LinearRange(0x10000, 0x2000))
        assert runtime.cursors == cursors and runtime.served == 0
        with pytest.raises(ValueError):
            program_input_seek(policy, runtime, handle=5, origin=SeekOrigin.BEGIN, distance=0)
