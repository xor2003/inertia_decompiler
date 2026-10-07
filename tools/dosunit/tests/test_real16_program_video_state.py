"""Initialized MZ functionality-state calls retain complete observable effects."""

import argparse
import json
from dataclasses import replace
from pathlib import Path

import jsonschema
import pytest
from tools.dosunit.tests.test_real16_program_replay import environment, mz

from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.reporting.real16_program_cli import cmd_replay_program16
from tools.dosunit.runtime.real16_program_memory import InitialMemoryRegion
from tools.dosunit.runtime.real16_program_model import ProgramAgreement, ProgramEventKind, ProgramStatus, compare_programs
from tools.dosunit.runtime.real16_program_replay import replay_program
from tools.dosunit.runtime.real16_program_vectors import VectorPolicy, vector_bytes
from tools.dosunit.runtime.real16_program_video import VideoQueryPolicy
from tools.dosunit.runtime.real16_program_video_state import VideoStatePolicy, video_state_document
from tools.dosunit.runtime.real16_replay_model import SegOffset


def state_environment():
    bios = SegOffset(0xF000, 0x100)
    dos = SegOffset(0xF000, 0x200)
    low = bytearray(0x500)
    low[0x40:0x44] = vector_bytes(bios)
    low[0x84:0x88] = vector_bytes(dos)
    low[0x449:0x467] = bytes(range(30))
    low[0x484:0x487] = bytes((24, 16, 0))
    policy = VideoStatePolicy(static_state=SegOffset(0xC000, 0x2A66), dcc=8, colours=16,
                              pages=8, scanline=2, misc=0x21, memory=3, entry=bios)
    return replace(environment(), extra_memory=(InitialMemoryRegion(SegOffset(0, 0), bytes(low)),),
                   vector_policy=VectorPolicy(dos), video_state_policy=policy)


def execute(prefix="", *, env=None, bx=0, destination=0x400, limit=100):
    # ES starts at PSP; table target lies beyond the tiny code, inside the arena.
    code = bytes.fromhex(prefix) + bytes.fromhex("66b8021badde")
    code += b"\xBB" + bx.to_bytes(2, "little") + b"\xBF" + destination.to_bytes(2, "little")
    code += bytes.fromhex("cd10b8004ccd21")
    return replay_program(program_from_mz_bytes(mz(code), env or state_environment()), instruction_limit=limit)


def test_state_table_changes_only_al_and_keeps_complete_receipt():
    result = execute(limit=4)
    assert result.status is ProgramStatus.BUDGET_EXHAUSTED
    assert dict(result.registers)["eax"] == 0xDEAD1B1B
    assert dict(result.registers)["bx"] == 0
    event = result.events[0]
    assert event.kind is ProgramEventKind.BIOS_VIDEO_STATE
    assert len(event.data) == 68
    table = event.data[-64:]
    assert table[:4] == bytes.fromhex("662a00c0")
    assert table[4:34] == bytes(range(30))
    assert table[34:37] == bytes((25, 16, 0))
    assert any(address <= 0x10400 and address + len(data) >= 0x10440
               and data[0x10400-address:0x10440-address] == table for address, data in result.writes)


def test_complete_termination_compares_and_truncated_receipt_refuses():
    result = execute()
    assert result.status is ProgramStatus.TERMINATED
    assert compare_programs(result, result) is ProgramAgreement.AGREED
    event = result.events[0]
    broken = replace(result, events=(replace(event, data=event.data[:-1]), *result.events[1:]))
    assert compare_programs(broken, broken) is ProgramAgreement.INCOMPLETE


def test_live_bda_change_is_visible_even_after_register_overwrite():
    before = execute()
    # Change physical449 through DS=0, then restore loader DS.
    after = execute("1e31c08ed8c6064904091f")
    assert after.status is ProgramStatus.TERMINATED
    assert compare_programs(before, after) is ProgramAgreement.MISMATCHED


@pytest.mark.parametrize("bx", [1, 0xFFFF])
def test_unmodeled_selector_refuses_without_table_write(bx):
    result = execute(bx=bx)
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.writes == ()


def test_missing_policy_refuses():
    result = execute(env=replace(state_environment(), video_state_policy=None))
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.writes == ()


def test_program_owned_handler_refuses_even_with_matching_vector():
    env = state_environment()
    entry = SegOffset(0x1000, 0x1800)
    low = bytearray(env.extra_memory[0].data)
    low[0x40:0x44] = vector_bytes(entry)
    env = replace(env, video_state_policy=replace(env.video_state_policy, entry=entry),
                  extra_memory=(InitialMemoryRegion(SegOffset(0, 0), bytes(low)),))
    result = execute(env=env)
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.writes == ()


def test_output_code_alias_refuses():
    result = execute(destination=0x100)
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.events[-1].data == b"video_state_code_write"
    assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE


def test_redirected_vector_refuses():
    result = execute("1e31c08ed8c706400034121f")
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.events[-1].data == b"video_vector_redirected"


def test_disagreeing_service_entries_reject_at_boot():
    with pytest.raises(ValueError, match="same INT10 entry"):
        replace(state_environment(), video_policy=VideoQueryPolicy(3, 80, 0, SegOffset(0xF000, 0x101)))


def test_missing_bda_declaration_rejects_at_boot():
    env = state_environment()
    with pytest.raises(ValueError, match="complete INT10 vector and BDA"):
        replace(env, extra_memory=(InitialMemoryRegion(SegOffset(0, 0), env.extra_memory[0].data[:1024]),))


@pytest.mark.parametrize("changed", [False, True])
def test_public_state_contract_and_receipt_schema(tmp_path, changed):
    env = state_environment()
    manifest = {"schema": "dosunit.real16_program_environment.v1", "environment": {
        "psp_segment": env.psp_segment, "allocation_hex": env.allocation.hex(),
        "registers": dict(env.registers), "fs": env.fs, "gs": env.gs,
        "extra_memory": [{"segment": 0, "offset": 0, "data_hex": env.extra_memory[0].data.hex()}],
        "dos_vectors": {"dos_entry": {"segment": 0xF000, "offset": 0x200}},
        "bios_video_state": video_state_document(env.video_state_policy),
    }}
    schemas = Path(__file__).resolve().parents[3] / "tools/dosunit/schemas"
    jsonschema.validate(manifest, json.loads((schemas / "dosunit.real16_program_environment.v1.schema.json").read_text()))
    declaration = tmp_path / "environment.json"
    declaration.write_text(json.dumps(manifest))
    original = tmp_path / "oracle.exe"
    original.write_bytes(mz(bytes.fromhex("b8021bbb0000bf0004cd10b8004ccd21")))
    candidate = tmp_path / "candidate.exe"
    candidate.write_bytes(mz(bytes.fromhex("b8004ccd21")) if changed else original.read_bytes())
    output = tmp_path / "result.json"
    assert cmd_replay_program16(argparse.Namespace(
        oracle_exe=original, candidate_exe=candidate, environment=declaration,
        instruction_limit=100, out=output,
    )) == int(changed)
    result = json.loads(output.read_text())
    jsonschema.validate(result, json.loads((schemas / "dosunit.real16_program_replay.v1.schema.json").read_text()))
    assert result["contract"]["services"]["bios_video_state"] == video_state_document(env.video_state_policy)
    assert result["proof_status"] == "not_established_by_execution"
