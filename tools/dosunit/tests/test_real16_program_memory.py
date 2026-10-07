"""Explicit extra RAM must preserve byte coverage, alias checks and identities."""

import argparse
import json
from dataclasses import replace
from pathlib import Path

import jsonschema
import pytest
from tools.dosunit.tests.test_real16_program_input_integration import input_environment
from tools.dosunit.tests.test_real16_program_replay import environment, mz

from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.reporting.real16_program_cli import cmd_replay_program16
from tools.dosunit.runtime.real16_program_memory import (
    MAX_EXTRA_REGIONS,
    InitialMemoryRegion,
    ProgramMemoryLayout,
    memory_regions_document,
    parse_memory_regions,
)
from tools.dosunit.runtime.real16_program_model import ProgramAgreement, ProgramObservation, ProgramStatus, compare_programs
from tools.dosunit.runtime.real16_program_output import OutputPolicy
from tools.dosunit.runtime.real16_program_replay import replay_program
from tools.dosunit.runtime.real16_replay_model import LinearRange, SegOffset


def region(segment=0x64, offset=0, data=b"\x2a"):
    return InitialMemoryRegion(SegOffset(segment, offset), data)


def execute(code, extra=(), observations=(), output=None):
    declared = replace(environment(), extra_memory=tuple(extra), output_policy=output)
    boot = program_from_mz_bytes(mz(bytes.fromhex(code)), declared)
    return replay_program(boot, observations=tuple(observations), instruction_limit=100)


def test_explicit_environment_bytes_execute_and_are_observable():
    result = execute("b864008ed8a00000b44ccd21", (region(),),
                     (ProgramObservation("environment", LinearRange(0x640, 1)),))
    assert result.status is ProgramStatus.TERMINATED
    assert result.exit_code == 42
    assert result.observations == (("environment", b"\x2a"),)
    assert compare_programs(result, result) is ProgramAgreement.AGREED


def test_extra_ram_writes_survive_in_declared_observations():
    result = execute("b864008ed8c606000063b8004ccd21", (region(),),
                     (ProgramObservation("environment", LinearRange(0x640, 1)),))
    assert result.status is ProgramStatus.TERMINATED
    assert result.observations == (("environment", b"\x63"),)
    assert result.writes == ((0x640, b"\x63"), (0x110FA, bytes.fromhex("0f0010100200")))


def test_undeclared_environment_and_page_padding_still_refuse():
    for extra, offset in (((), "0000"), ((region(),), "0100")):
        result = execute("b864008ed8a0" + offset + "b44ccd21", extra)
        assert result.status is ProgramStatus.UNSUPPORTED
        assert result.detail == "undeclared_access"
        assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE


def test_adjacent_regions_support_cross_boundary_access_but_not_gaps():
    result = execute("b864008ed8a10000b44ccd21", (region(data=b"A"), region(offset=1, data=b"B")))
    assert result.status is ProgramStatus.TERMINATED
    layout = ProgramMemoryLayout(((0x640, b"A"), (0x642, b"B")))
    assert not layout.contains(0x640, 3)
    assert layout.pages == (0,)


@pytest.mark.parametrize("extra", [
    (region(), region(0x60, 0x40)),
    (region(), region(0x60, 0x40, b"B")),
    (region(0x1000),),
])
def test_physical_aliases_and_process_allocation_overlaps_reject(extra):
    with pytest.raises(ValueError, match="overlap or alias"):
        replace(environment(), extra_memory=extra)


@pytest.mark.parametrize("arguments", [
    (0x64, 0, b""), (0x64, 0xFFFF, b"ab"), (0xA000, 0, b"a"),
    (True, 0, b"a"), (0x64, False, b"a"),
])
def test_unbounded_or_implicit_initial_bytes_reject(arguments):
    with pytest.raises(ValueError):
        region(*arguments)


def test_region_limit_and_manifest_roundtrip():
    extras = (region(), region(0x65, data=b"BCD"))
    assert parse_memory_regions(memory_regions_document(extras)) == extras
    for malformed in (None, [None], [{}], memory_regions_document(extras) * MAX_EXTRA_REGIONS):
        with pytest.raises(ValueError):
            parse_memory_regions(malformed)
    with pytest.raises(ValueError, match="at most 32"):
        parse_memory_regions([{}] * (MAX_EXTRA_REGIONS + 1))


def test_extra_bytes_and_coordinates_bind_boot_and_environment_identity():
    code = mz(bytes.fromhex("b8004ccd21"))
    left = program_from_mz_bytes(code, replace(environment(), extra_memory=(region(),)))
    right = program_from_mz_bytes(code, replace(environment(), extra_memory=(region(data=b"B"),)))
    assert left.boot_sha256 != right.boot_sha256
    left_result, right_result = replay_program(left), replay_program(right)
    assert left_result.environment_identity != right_result.environment_identity
    assert compare_programs(left_result, right_result) is ProgramAgreement.INCOMPLETE


def test_stream_service_reads_only_explicit_extra_bytes():
    policy = OutputPolicy(frozenset({1}), 8, 8)
    code = "b864008ed8bb0100b9010031d2b440cd21b8004ccd21"
    result = execute(code, (region(data=b"Z"),), output=policy)
    assert result.status is ProgramStatus.TERMINATED
    assert result.events[0].data == b"\x01Z"
    assert compare_programs(result, result) is ProgramAgreement.AGREED
    refused = execute(code, output=policy)
    assert refused.status is ProgramStatus.UNSUPPORTED


def test_extra_ram_does_not_expand_executable_code_scope():
    result = execute("ea00006400", (region(data=bytes.fromhex("b8004ccd21")),))
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.detail == "control_escape"


def test_file_input_uses_the_same_declared_extra_memory_domain():
    env = replace(input_environment(), extra_memory=(region(data=b"...."),))
    code = bytes.fromhex("b864008ed8bb050031d2b90400b43fcd21b8004ccd21")
    result = replay_program(program_from_mz_bytes(mz(code), env), observations=(
        ProgramObservation("input", LinearRange(0x640, 4)),
    ))
    assert result.status is ProgramStatus.TERMINATED
    assert result.observations == (("input", b"ABCD"),)
    assert result.writes == ((0x640, b"ABCD"), (0x110FA, bytes.fromhex("160010104600")))
    assert compare_programs(result, result) is ProgramAgreement.AGREED


@pytest.mark.parametrize("changed", [False, True])
def test_public_extra_memory_manifest_and_report(tmp_path: Path, changed: bool):
    env = environment()
    manifest = {"schema": "dosunit.real16_program_environment.v1", "environment": {
        "psp_segment": env.psp_segment, "allocation_hex": env.allocation.hex(),
        "registers": dict(env.registers), "fs": env.fs, "gs": env.gs,
        "extra_memory": memory_regions_document((region(),)),
    }, "observations": [{"name": "env", "oracle_address": 0x640, "candidate_address": 0x640, "size": 1}]}
    schemas = Path(__file__).resolve().parents[3] / "tools/dosunit/schemas"
    jsonschema.validate(manifest, json.loads((schemas / "dosunit.real16_program_environment.v1.schema.json").read_text()))
    manifest_path = tmp_path / "environment.json"
    manifest_path.write_text(json.dumps(manifest))
    paths = [tmp_path / "original.exe", tmp_path / "changed.exe"]
    for path, value in zip(paths, (0x2A, 0x2B if changed else 0x2A), strict=True):
        path.write_bytes(mz(bytes.fromhex(f"b864008ed8c6060000{value:02x}b8004ccd21")))
    output = tmp_path / "comparison.json"
    assert cmd_replay_program16(argparse.Namespace(
        oracle_exe=paths[0], candidate_exe=paths[1], environment=manifest_path,
        instruction_limit=100, out=output,
    )) == int(changed)
    result = json.loads(output.read_text())
    assert result["contract"]["interrupt_entry"] == "real16_int21_stack_v1"
    jsonschema.validate(result, json.loads((schemas / "dosunit.real16_program_replay.v1.schema.json").read_text()))
    assert result["agreement"] == ("mismatched" if changed else "agreed")
    assert result["proof_status"] == "not_established_by_execution"
