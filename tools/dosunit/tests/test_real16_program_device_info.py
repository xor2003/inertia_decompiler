"""Device queries require explicit responses, preserved state and complete receipts."""

import argparse
import json
from dataclasses import replace
from pathlib import Path

import jsonschema
import pytest
from tools.dosunit.tests.test_real16_program_replay import environment, mz

from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.reporting.real16_program_cli import cmd_replay_program16
from tools.dosunit.runtime.real16_program_device_info import (
    DeviceInfoPolicy,
    DeviceInformation,
    device_info_policy_document,
    parse_device_info_policy,
)
from tools.dosunit.runtime.real16_program_model import (
    ProgramAgreement,
    ProgramEvent,
    ProgramEventKind,
    ProgramStatus,
    compare_programs,
)
from tools.dosunit.runtime.real16_program_replay import replay_program


def execute(code, *, policy=None):
    env = replace(environment(), device_info_policy=policy)
    return replay_program(program_from_mz_bytes(mz(bytes.fromhex(code)), env))


def policy():
    return DeviceInfoPolicy((DeviceInformation(4, 0x8002), DeviceInformation(1, 0x80A0)))


def test_device_query_preserves_upper_registers_and_only_clears_carry():
    result = execute("66b80044adde66bb0400edfe66ba3412efbef9cd2189c6b8004ccd21", policy=policy())
    assert result.status is ProgramStatus.TERMINATED
    registers = dict(result.registers)
    assert (registers["eax"], registers["ebx"], registers["edx"], registers["eflags"]) == (
        0xDEAD4C00, 0xFEED0004, 0xBEEF8002, 2,
    )
    assert result.events[0].data == bytes.fromhex("21440004000280")
    assert registers["si"] == 0x4400  # AX survives the query before the exit assignment.
    assert compare_programs(result, result) is ProgramAgreement.AGREED


@pytest.mark.parametrize(("selector", "handle", "reason"), [
    (0, 7, b"undeclared_device_information_handle"),
    (1, 4, b"unsupported_device_information_subfunction"),
    (8, 4, b"unsupported_device_information_subfunction"),
])
def test_undeclared_handles_and_other_ioctl_functions_refuse(selector, handle, reason):
    code = bytes((0xB8, selector, 0x44, 0xBB, handle, 0, 0xCD, 0x21, 0xB8, 0, 0x4C, 0xCD, 0x21))
    result = execute(code.hex(), policy=policy())
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.events[-1].data == reason
    assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE


def test_device_queries_without_a_policy_remain_unsupported():
    result = execute("b80044bb0400cd21b8004ccd21")
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.writes == ()


def test_device_query_preserves_noncarry_flags_and_architectural_entry_frame():
    env = environment()
    incoming_flags = 0xA47
    env = replace(env, registers=tuple((name, incoming_flags if name == "eflags" else value)
                                      for name, value in env.registers), device_info_policy=policy())
    code = bytes.fromhex("b80044bb0400cd21b8004ccd21")
    boot = program_from_mz_bytes(mz(code), env)
    # Stop immediately after the query, before the exit overwrites the frame.
    result = replay_program(boot, instruction_limit=3)
    assert result.status is ProgramStatus.BUDGET_EXHAUSTED
    assert dict(result.registers)["eflags"] == incoming_flags & ~1
    frame = b"\x08\x00\x10\x10" + incoming_flags.to_bytes(2, "little")
    assert any(data == frame for _, data in result.writes)


def test_policy_inventory_is_strict_bounded_and_canonically_ordered():
    assert parse_device_info_policy(device_info_policy_document(policy())) == policy()
    assert policy().handles[0].handle == 1
    for declaration in ({}, {"handles": []}, {"handles": [{"handle": True, "information": 2}]},
                        {"handles": [{"handle": 4, "information": 65536}]},
                        {"handles": [{"handle": 4, "information": 2}] * 2},
                        {"handles": [{"handle": i, "information": 2} for i in range(257)]}):
        with pytest.raises(ValueError):
            parse_device_info_policy(declaration)


def test_policy_response_and_even_unqueried_handles_bind_both_identities():
    code = mz(bytes.fromhex("b8004ccd21"))
    env = replace(environment(), device_info_policy=policy())
    base = program_from_mz_bytes(code, env)
    altered = DeviceInfoPolicy((DeviceInformation(4, 0x8003), DeviceInformation(1, 0x80A0)))
    other = program_from_mz_bytes(code, replace(env, device_info_policy=altered))
    assert base.boot_sha256 != other.boot_sha256
    left, right = replay_program(base), replay_program(other)
    assert left.environment_identity != right.environment_identity
    assert compare_programs(left, right) is ProgramAgreement.INCOMPLETE


def test_changed_query_handle_is_observable_even_when_final_dx_is_overwritten():
    code = "b80044bb0400cd21ba0000bb0000b8004ccd21"
    left = execute(code, policy=policy())
    right = execute(code.replace("bb0400", "bb0100"), policy=policy())
    assert left.status is right.status is ProgramStatus.TERMINATED
    assert dict(left.registers) == dict(right.registers)
    assert compare_programs(left, right) is ProgramAgreement.MISMATCHED


def test_corrupt_device_receipts_and_foreign_exit_cannot_publish_agreement():
    base = execute("b80044bb0400cd21b8004ccd21", policy=policy())
    event = base.events[0]
    for data in (event.data[:-1], event.data + b"x", bytes.fromhex("21440104000280")):
        broken = replace(base, events=(replace(event, data=data), base.events[-1]))
        assert compare_programs(broken, broken) is ProgramAgreement.INCOMPLETE
    forged = replace(base, events=(event, ProgramEvent(ProgramEventKind.PE_EXIT, 0, bytes(4))))
    assert compare_programs(forged, forged) is ProgramAgreement.INCOMPLETE


@pytest.mark.parametrize("changed", [False, True])
def test_public_device_policy_and_receipts_validate_against_schemas(tmp_path: Path, changed: bool):
    env = environment()
    manifest = {"schema": "dosunit.real16_program_environment.v1", "environment": {
        "psp_segment": env.psp_segment, "allocation_hex": env.allocation.hex(),
        "registers": dict(env.registers), "fs": env.fs, "gs": env.gs,
        "dos_device_info": device_info_policy_document(policy()),
    }}
    schemas = Path(__file__).resolve().parents[3] / "tools/dosunit/schemas"
    jsonschema.validate(manifest, json.loads((schemas / "dosunit.real16_program_environment.v1.schema.json").read_text()))
    declaration = tmp_path / "environment.json"
    declaration.write_text(json.dumps(manifest))
    original, candidate = tmp_path / "oracle.exe", tmp_path / "candidate.exe"
    code = "b80044bb0400cd21b8004ccd21"
    original.write_bytes(mz(bytes.fromhex(code)))
    candidate.write_bytes(mz(bytes.fromhex(code.replace("bb0400", "bb0100") if changed else code)))
    output = tmp_path / "result.json"
    assert cmd_replay_program16(argparse.Namespace(
        oracle_exe=original, candidate_exe=candidate, environment=declaration,
        instruction_limit=100, out=output,
    )) == int(changed)
    result = json.loads(output.read_text())
    jsonschema.validate(result, json.loads((schemas / "dosunit.real16_program_replay.v1.schema.json").read_text()))
    assert result["contract"]["services"]["dos_device_info"] == device_info_policy_document(policy())
    assert result["proof_status"] == "not_established_by_execution"
