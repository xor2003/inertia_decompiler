"""ROM declarations grant exact data reads, never writes or executable scope."""

import argparse
import json
from dataclasses import replace
from pathlib import Path

import jsonschema
import pytest
from tools.dosunit.tests.test_real16_program_input_integration import input_environment
from tools.dosunit.tests.test_real16_program_replay import environment, mz
from tools.dosunit.tests.test_real16_program_video_state import execute as execute_video_state
from tools.dosunit.tests.test_real16_program_video_state import state_environment

from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.reporting.real16_program_cli import cmd_replay_program16
from tools.dosunit.runtime.real16_program_model import ProgramAgreement, ProgramEventKind, ProgramStatus, compare_programs
from tools.dosunit.runtime.real16_program_output import OutputPolicy
from tools.dosunit.runtime.real16_program_replay import replay_program
from tools.dosunit.runtime.real16_program_rom import ProgramRom, RomRegion, rom_document
from tools.dosunit.runtime.real16_replay_model import SegOffset


def rom_environment(data=b"\x07", offset=0x20):
    return replace(environment(), rom=ProgramRom((RomRegion(SegOffset(0xC000, offset), data),)))


def execute(code, *, env=None, limit=100):
    return replay_program(program_from_mz_bytes(mz(bytes.fromhex(code)), env or rom_environment()),
                          instruction_limit=limit)


def test_declared_rom_read_reaches_exit_and_changed_binary_differs():
    left = execute("b800c08ed8a02000b44ccd21")
    right = execute("b800c08ed8a02000fec0b44ccd21")
    assert left.status is right.status is ProgramStatus.TERMINATED
    assert (left.exit_code, right.exit_code) == (7, 8)
    assert compare_programs(left, left) is ProgramAgreement.AGREED
    assert compare_programs(left, right) is ProgramAgreement.MISMATCHED


def test_rom_bytes_bind_boot_and_environment_identities():
    left = execute("b800c08ed8a02000b44ccd21")
    right = execute("b800c08ed8a02000b44ccd21", env=rom_environment(b"\x08"))
    assert left.boot_identity != right.boot_identity
    assert left.environment_identity != right.environment_identity
    assert right.exit_code == 8


def test_guest_rom_store_refuses_before_mutating_memory():
    result = execute("b800c08ed8c606200009b8004ccd21")
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.events[-1].kind is ProgramEventKind.READ_ONLY_WRITE
    assert all(address < 0xC0000 for address, _ in result.writes)
    assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE


@pytest.mark.parametrize("offset", [0, 0x21, 0xFFF])
def test_mapping_page_slack_is_not_declared_rom(offset):
    result = execute("b800c08ed8a0" + offset.to_bytes(2, "little").hex() + "b44ccd21")
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.events[-1].kind is ProgramEventKind.UNDECLARED_ACCESS


def test_absent_rom_keeps_read_refusal():
    result = execute("b800c08ed8a02000b44ccd21", env=environment())
    assert result.status is ProgramStatus.UNSUPPORTED


def test_rom_is_not_an_executable_handler():
    result = execute("ea200000c0", env=rom_environment(bytes.fromhex("b8004ccd21")))
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.exit_code is None
    assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE


def test_interrupt_frame_in_rom_refuses():
    result = execute("b800c08ed0bc2600b8004ccd21", env=rom_environment(bytes(6)))
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.events[-1].kind is ProgramEventKind.UNDECLARED_ACCESS
    assert result.writes == ()


def test_adjacent_rom_chunks_allow_word_reads():
    env = replace(environment(), rom=ProgramRom((RomRegion(SegOffset(0xC000, 0x20), b"\x07"),
                                               RomRegion(SegOffset(0xC000, 0x21), b"\x12"))))
    result = execute("b800c08ed88b1e2000b8004ccd21", env=env)
    assert result.status is ProgramStatus.TERMINATED
    assert dict(result.registers)["bx"] == 0x1207


def test_rom_can_supply_a_declared_output_stream():
    env = replace(rom_environment(b"ROM"), output_policy=OutputPolicy(frozenset({1}), 32, 32))
    result = execute("b800c08ed8ba2000b90300bb0100b80040cd21b8004ccd21", env=env)
    assert result.status is ProgramStatus.TERMINATED
    assert result.events[0].kind is ProgramEventKind.OUTPUT_WRITE
    assert result.events[0].data == b"\x01ROM"


def test_file_input_cannot_write_rom_or_advance_cursor():
    env = replace(rom_environment(b"old"), input_policy=input_environment().input_policy)
    result = execute("b800c08ed8ba2000b90200bb0500b8003fcd21b8004ccd21", env=env)
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.input_file_positions == result.requested_input_files
    assert result.file_receipts == ()
    assert all(address < 0xC0000 for address, _ in result.writes)


def test_repeated_execution_does_not_retain_rom_or_register_mutations():
    boot = program_from_mz_bytes(mz(bytes.fromhex("b800c08ed8a02000b44ccd21")), rom_environment())
    left = replay_program(boot)
    right = replay_program(boot)
    assert left == right


def test_summarized_bios_table_cannot_write_rom():
    env = replace(state_environment(), rom=rom_environment(bytes(64), offset=0x400).rom)
    result = execute_video_state("b800c08ec0", env=env)
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.events[-1].data == b"video_state_destination_undeclared"
    assert all(address < 0xC0000 for address, _ in result.writes)


@pytest.mark.parametrize("changed,write", [(False, False), (True, False), (False, True)])
def test_public_rom_declaration_and_refusal_schema(tmp_path, changed, write):
    env = rom_environment()
    manifest = {"schema": "dosunit.real16_program_environment.v1", "environment": {
        "psp_segment": env.psp_segment, "allocation_hex": env.allocation.hex(),
        "registers": dict(env.registers), "fs": env.fs, "gs": env.gs,
        "rom": rom_document(env.rom),
    }}
    schemas = Path(__file__).resolve().parents[3] / "tools/dosunit/schemas"
    jsonschema.validate(manifest, json.loads((schemas / "dosunit.real16_program_environment.v1.schema.json").read_text()))
    declaration = tmp_path / "environment.json"
    declaration.write_text(json.dumps(manifest))
    operation = "c606200009" if write else "a02000"
    original = tmp_path / "oracle.exe"
    original.write_bytes(mz(bytes.fromhex("b800c08ed8" + operation + "b44ccd21")))
    candidate = tmp_path / "candidate.exe"
    candidate.write_bytes(mz(bytes.fromhex("b800c08ed8a02000fec0b44ccd21")) if changed else original.read_bytes())
    output = tmp_path / "result.json"
    assert cmd_replay_program16(argparse.Namespace(
        oracle_exe=original, candidate_exe=candidate, environment=declaration,
        instruction_limit=100, out=output,
    )) == (2 if write else int(changed))
    result = json.loads(output.read_text())
    jsonschema.validate(result, json.loads((schemas / "dosunit.real16_program_replay.v1.schema.json").read_text()))
    assert result["contract"]["read_only_rom"] == rom_document(env.rom)
    assert result["proof_status"] == "not_established_by_execution"


@pytest.mark.parametrize("field,value", [("chunks", ((0x10000, b"bad"),)), ("pages", (0x10000,)),
                                         ("ranges", ())])
def test_forged_rom_projections_refuse_before_execution(field, value):
    boot = program_from_mz_bytes(mz(bytes.fromhex("b8004ccd21")), rom_environment())
    object.__setattr__(boot.environment.rom, field, value)
    with pytest.raises(ValueError, match="ROM"):
        replay_program(boot)
