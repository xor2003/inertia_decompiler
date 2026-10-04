"""Real-MZ video queries retain full state, vector guards and observable receipts."""

import argparse
import json
from dataclasses import replace
from pathlib import Path

import jsonschema
import pytest
from test_real16_program_replay import environment, mz

from tools.dosunit.real16_program_boot import program_from_mz_bytes
from tools.dosunit.real16_program_cli import cmd_replay_program16
from tools.dosunit.real16_program_memory import InitialMemoryRegion
from tools.dosunit.real16_program_model import ProgramAgreement, ProgramEventKind, ProgramStatus, compare_programs
from tools.dosunit.real16_program_replay import replay_program
from tools.dosunit.real16_program_vectors import VectorPolicy, vector_bytes
from tools.dosunit.real16_program_video import VideoQueryPolicy, video_policy_document
from tools.dosunit.real16_replay_model import SegOffset


def video_environment(*, entry=None):
    entry = entry or SegOffset(0xF000, 0)
    env = environment()
    ivt = bytearray(1024)
    ivt[0x40:0x44] = vector_bytes(entry)
    dos = SegOffset(0xF000, 0x100)
    ivt[0x84:0x88] = vector_bytes(dos)
    return replace(env, extra_memory=(InitialMemoryRegion(SegOffset(0, 0), bytes(ivt)),),
                   vector_policy=VectorPolicy(dos),
                   video_policy=VideoQueryPolicy(mode=3, columns=80, page=2, entry=entry))


def execute(code, *, env=None, limit=100):
    return replay_program(program_from_mz_bytes(mz(bytes.fromhex(code)), env or video_environment()),
                          instruction_limit=limit)


def test_video_query_preserves_unowned_bits_and_interrupt_frame():
    env = video_environment()
    flags = 0xA47
    env = replace(env, registers=tuple((name, flags if name == "eflags" else value)
                                      for name, value in env.registers))
    code = "66b8220fadde66bb3412efbecd10b8004ccd21"
    result = execute(code, env=env, limit=3)
    assert result.status is ProgramStatus.BUDGET_EXHAUSTED
    registers = dict(result.registers)
    assert registers["eax"] == 0xDEAD5003
    assert registers["ebx"] == 0xBEEF0234
    assert registers["eflags"] == flags
    assert result.events[0].kind is ProgramEventKind.BIOS_VIDEO_QUERY
    assert result.events[0].data == bytes.fromhex("100f035002")
    assert any(data == bytes.fromhex("0e001010") + flags.to_bytes(2, "little")
               for _, data in result.writes)


def test_video_query_is_observable_after_result_overwrite():
    left = execute("b8000fcd1031c031dbb8004ccd21")
    right = execute("31c031dbb8004ccd21")
    assert left.status is right.status is ProgramStatus.TERMINATED
    assert compare_programs(left, left) is ProgramAgreement.AGREED
    assert compare_programs(left, right) is ProgramAgreement.MISMATCHED


@pytest.mark.parametrize("subfunction", [0, 2, 0x0E, 0x10, 0xFF])
def test_other_video_services_stay_unsupported(subfunction):
    result = execute((bytes((0xB8, 0, subfunction, 0xCD, 0x10)) + bytes.fromhex("b8004ccd21")).hex())
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.writes == ()


def test_missing_policy_stays_unsupported():
    result = execute("b8000fcd10b8004ccd21", env=replace(video_environment(), video_policy=None))
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.writes == ()


def test_changed_live_vector_refuses():
    result = execute("31c08ec026c70640003412b8000fcd10b8004ccd21")
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.events[-1].data == b"video_vector_redirected"
    assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE


def test_program_owned_video_handler_is_not_summarized():
    result = execute("b8000fcd10b8004ccd21", env=video_environment(entry=SegOffset(0x1010, 0)))
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.events[-1].data == b"video_vector_points_to_program_code"


@pytest.mark.parametrize("service", ["b8000fcd10", "b8004ccd21"])
def test_interrupt_frame_must_not_overwrite_declared_video_vector(service):
    result = execute("31c08ed0bc4600" + service)
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.events[-1].data == b"interrupt_frame_overlaps_video_vector"
    assert result.writes == ()


def test_changed_video_policy_binds_environment_and_boot():
    env = video_environment()
    assert env.video_policy is not None
    code = mz(bytes.fromhex("b8000fcd10b8004ccd21"))
    base = program_from_mz_bytes(code, env)
    other = program_from_mz_bytes(code, replace(env, video_policy=replace(env.video_policy, page=3)))
    assert base.boot_sha256 != other.boot_sha256
    left, right = replay_program(base), replay_program(other)
    assert left.environment_identity != right.environment_identity
    assert compare_programs(left, right) is ProgramAgreement.INCOMPLETE


def test_bad_video_receipt_cannot_publish_agreement():
    result = execute("b8000fcd10b8004ccd21")
    event = result.events[0]
    for data in (event.data[:-1], b"\x10\x0e" + event.data[2:]):
        broken = replace(result, events=(replace(event, data=data), result.events[-1]))
        assert compare_programs(broken, broken) is ProgramAgreement.INCOMPLETE
    foreign = replace(result, events=(event, replace(result.events[-1], kind=ProgramEventKind.PE_EXIT, data=bytes(4))))
    assert compare_programs(foreign, foreign) is ProgramAgreement.INCOMPLETE


def test_video_policy_requires_initialized_vector_bytes():
    with pytest.raises(ValueError, match="complete declared INT10 vector"):
        replace(video_environment(), extra_memory=(), vector_policy=None)


@pytest.mark.parametrize("prefix", ["66", "67", "f3"])
def test_prefixed_video_interrupt_keeps_bounded_entry_scope(prefix):
    result = execute("b8000f" + prefix + "cd10b8004ccd21")
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.writes == ()


@pytest.mark.parametrize("changed", [False, True])
def test_video_contract_and_receipt_validate_through_public_cli(tmp_path: Path, changed: bool):
    env = video_environment()
    manifest = {"schema": "dosunit.real16_program_environment.v1", "environment": {
        "psp_segment": env.psp_segment, "allocation_hex": env.allocation.hex(),
        "registers": dict(env.registers), "fs": env.fs, "gs": env.gs,
        "extra_memory": [{"segment": 0, "offset": 0, "data_hex": env.extra_memory[0].data.hex()}],
        "dos_vectors": {"dos_entry": {"segment": 0xF000, "offset": 0x100}},
        "bios_video": video_policy_document(env.video_policy),
    }}
    schemas = Path(__file__).resolve().parents[2] / "tools/dosunit/schemas"
    jsonschema.validate(manifest, json.loads((schemas / "dosunit.real16_program_environment.v1.schema.json").read_text()))
    declaration = tmp_path / "environment.json"
    declaration.write_text(json.dumps(manifest))
    original = tmp_path / "oracle.exe"
    original.write_bytes(mz(bytes.fromhex("b8000fcd10b8004ccd21")))
    candidate = tmp_path / "candidate.exe"
    candidate.write_bytes(mz(bytes.fromhex("b8004ccd21")) if changed else original.read_bytes())
    output = tmp_path / "result.json"
    assert cmd_replay_program16(argparse.Namespace(
        oracle_exe=original, candidate_exe=candidate, environment=declaration,
        instruction_limit=100, out=output,
    )) == int(changed)
    result = json.loads(output.read_text())
    jsonschema.validate(result, json.loads((schemas / "dosunit.real16_program_replay.v1.schema.json").read_text()))
    assert result["contract"]["services"]["bios_video"] == video_policy_document(env.video_policy)
    assert result["contract"]["interrupt_entry"] == "real16_int21_int10_stack_v2"
    assert result["proof_status"] == "not_established_by_execution"
