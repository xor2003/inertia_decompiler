"""Declared live IVT behavior must preserve real bytes and reject DOS redirection."""

import argparse
import json
from dataclasses import replace
from pathlib import Path

import jsonschema
import pytest
from test_real16_program_replay import environment, mz

from tools.dosunit.real16_program_boot import program_from_mz_bytes
from tools.dosunit.real16_program_cli import cmd_replay_program16
from tools.dosunit.real16_program_memory import InitialMemoryRegion, memory_regions_document
from tools.dosunit.real16_program_model import (
    ProgramAgreement,
    ProgramEvent,
    ProgramEventKind,
    ProgramObservation,
    ProgramStatus,
    compare_programs,
)
from tools.dosunit.real16_program_replay import replay_program
from tools.dosunit.real16_program_vectors import (
    VectorPolicy,
    parse_vector_policy,
    vector_bytes,
    vector_policy_document,
    vector_receipt_complete,
)
from tools.dosunit.real16_replay_model import LinearRange, SegOffset


def vector_environment():
    table = b"".join(vector_bytes(SegOffset(0x54, number)) for number in range(256))
    return replace(environment(), extra_memory=(InitialMemoryRegion(SegOffset(0, 0), table),),
                   vector_policy=VectorPolicy(SegOffset(0x54, 0x21)))


def execute(code, *, env=None):
    boot = program_from_mz_bytes(mz(bytes.fromhex(code)), vector_environment() if env is None else env)
    return replay_program(boot, observations=(ProgramObservation("vector0", LinearRange(0, 4)),))


def test_query_preserves_upper_halves_flags_and_returns_live_far_pointer():
    env = vector_environment()
    table = bytearray(env.extra_memory[0].data)
    table[0x200:0x204] = bytes.fromhex("9a785634")
    env = replace(env, extra_memory=(InitialMemoryRegion(SegOffset(0, 0), bytes(table)),))
    result = execute("66b88035adde66bb3412edfef9cd21b8004ccd21", env=env)
    assert result.status is ProgramStatus.TERMINATED
    regs = dict(result.registers)
    assert (regs["ebx"], regs["es"], regs["eax"], regs["eflags"]) == (0xFEED789A, 0x3456, 0xDEAD4C00, 3)
    assert result.events[0].kind is ProgramEventKind.DOS_VECTOR
    assert result.events[0].data == bytes.fromhex("2135809a7856349a785634")
    assert compare_programs(result, result) is ProgramAgreement.AGREED


def test_set_then_query_retains_exact_live_slot_and_changed_target_mismatches():
    code = "0e1fba7856b80025cd21b80035cd21b8004ccd21"
    result = execute(code)
    assert result.status is ProgramStatus.TERMINATED
    assert result.observations == (("vector0", bytes.fromhex("78561010")),)
    regs = dict(result.registers)
    assert (regs["bx"], regs["es"]) == (0x5678, 0x1010)
    assert all(vector_receipt_complete(event.data) for event in result.events[:-1])
    assert compare_programs(result, result) is ProgramAgreement.AGREED
    changed = execute(code.replace("ba7856", "ba7956"))
    assert compare_programs(result, changed) is ProgramAgreement.MISMATCHED


def test_query_reads_direct_guest_writes_instead_of_cached_initial_table():
    result = execute("31c08ec026c7060000341226c70602007856b80035cd21b8004ccd21")
    assert result.status is ProgramStatus.TERMINATED
    regs = dict(result.registers)
    assert (regs["bx"], regs["es"]) == (0x1234, 0x5678)


@pytest.mark.parametrize(("code", "reason"), [
    ("0e1fba7856b82125cd21b8004ccd21", b"dos_vector_update_requires_handler_execution"),
    ("31c08ec026c70684003412b8004ccd21", b"dos_vector_redirected"),
])
def test_dos_redirection_does_not_keep_using_external_service_summaries(code, reason):
    result = execute(code)
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.events[-1].data == reason
    assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE


def test_vector_policy_requires_full_initialized_ivt_and_strict_coordinates():
    with pytest.raises(ValueError, match="1024-byte IVT"):
        replace(environment(), vector_policy=VectorPolicy(SegOffset(0x54, 0x21)))
    policy = vector_environment().vector_policy
    assert parse_vector_policy(vector_policy_document(policy)) == policy
    for bad in ({}, {"dos_entry": {}}, {"dos_entry": {"segment": True, "offset": 33}},
                {"dos_entry": {"segment": -1, "offset": 33}}):
        with pytest.raises(ValueError):
            parse_vector_policy(bad)


def test_vector_policy_and_initial_table_bind_boot_and_execution_identity():
    env = vector_environment()
    code = mz(bytes.fromhex("b8004ccd21"))
    base = program_from_mz_bytes(code, env)
    absent = program_from_mz_bytes(code, replace(env, vector_policy=None))
    assert base.boot_sha256 != absent.boot_sha256
    left, right = replay_program(base), replay_program(absent)
    assert left.environment_identity != right.environment_identity
    table = bytearray(env.extra_memory[0].data)
    table[0x1C] ^= 1  # Even an unqueried declared slot belongs to initial state.
    changed = replace(env, extra_memory=(InitialMemoryRegion(SegOffset(0, 0), bytes(table)),))
    other = replay_program(program_from_mz_bytes(code, changed))
    assert left.status is other.status is ProgramStatus.TERMINATED
    assert compare_programs(left, other) is ProgramAgreement.INCOMPLETE


def test_missing_policy_keeps_vector_services_refused():
    result = execute("b80035cd21b8004ccd21", env=replace(vector_environment(), vector_policy=None))
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.writes == ()


@pytest.mark.parametrize("size", [1, 4])
def test_explicit_dos_vector_bytes_cannot_be_ignored_without_a_policy(size):
    env = replace(environment(), extra_memory=(InitialMemoryRegion(SegOffset(0, 0x84), bytes(size)),))
    result = replay_program(program_from_mz_bytes(mz(bytes.fromhex("b8004ccd21")), env))
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.events[-1].data == b"declared_dos_vector_requires_policy"
    assert result.writes == ()


def test_program_owned_dos_handler_is_not_replaced_by_an_external_summary():
    env = vector_environment()
    table = bytearray(env.extra_memory[0].data)
    table[0x84:0x88] = bytes.fromhex("00001010")
    env = replace(env, extra_memory=(InitialMemoryRegion(SegOffset(0, 0), bytes(table)),),
                  vector_policy=VectorPolicy(SegOffset(0x1010, 0)))
    result = execute("b8004ccd21", env=env)
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.events[-1].data == b"dos_vector_points_to_program_code"
    assert result.writes == ()


def test_narrow_code_ranges_cannot_disguise_a_program_owned_dos_handler():
    env = vector_environment()
    table = bytearray(env.extra_memory[0].data)
    table[0x84:0x88] = bytes.fromhex("20001010")
    env = replace(env, extra_memory=(InitialMemoryRegion(SegOffset(0, 0), bytes(table)),),
                  vector_policy=VectorPolicy(SegOffset(0x1010, 0x20)))
    code = bytes.fromhex("b8004ccd21") + b"\x90" * 32
    boot = program_from_mz_bytes(mz(code), env, code_ranges=(LinearRange(0x10100, 5),))
    result = replay_program(boot)
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.events[-1].data == b"dos_vector_points_to_program_code"
    assert result.writes == ()


@pytest.mark.parametrize(("code", "reason"), [
    ("31c08ed0bc8a00b80035cd21", b"interrupt_frame_overlaps_dos_vector"),
    ("31c08ed0bc4600b81025cd21", b"service_writes_interrupt_frame"),
])
def test_vector_and_interrupt_frame_aliases_keep_control_boundaries(code, reason):
    result = execute(code)
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.events[-1].data == reason
    assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE


def test_query_sees_its_own_entry_frame_in_the_live_table():
    result = execute("31c08ed0bc4600b81035cd21b8004ccd21")
    assert result.status is ProgramStatus.TERMINATED
    regs = dict(result.registers)
    assert (regs["bx"], regs["es"]) == (12, 0x1010)


def test_malformed_vector_receipts_and_pe_exit_cannot_publish_agreement():
    base = execute("b80035cd21b8004ccd21")
    assert base.status is ProgramStatus.TERMINATED
    event = base.events[0]
    for data in (event.data[:-1], event.data[:7] + b"FAIL", bytes.fromhex("2125210000540001005400")):
        changed = replace(base, events=(replace(event, data=data), base.events[-1]))
        assert compare_programs(changed, changed) is ProgramAgreement.INCOMPLETE
    pe_exit = ProgramEvent(ProgramEventKind.PE_EXIT, 0, bytes(4))
    forged = replace(base, events=(event, pe_exit))
    assert compare_programs(forged, forged) is ProgramAgreement.INCOMPLETE


def test_restoring_the_unchanged_dos_vector_is_admitted():
    result = execute("b854008ed8ba2100b82125cd21b8004ccd21")
    assert result.status is ProgramStatus.TERMINATED
    assert result.events[0].data == bytes.fromhex("2125212100540021005400")
    assert compare_programs(result, result) is ProgramAgreement.AGREED


@pytest.mark.parametrize("changed", [False, True])
def test_public_vector_policy_and_event_schema(tmp_path: Path, changed: bool):
    env = vector_environment()
    manifest = {"schema": "dosunit.real16_program_environment.v1", "environment": {
        "psp_segment": env.psp_segment, "allocation_hex": env.allocation.hex(),
        "registers": dict(env.registers), "fs": env.fs, "gs": env.gs,
        "extra_memory": memory_regions_document(env.extra_memory),
        "dos_vectors": vector_policy_document(env.vector_policy),
    }, "observations": [{"name": "vector0", "oracle_address": 0, "candidate_address": 0, "size": 4}]}
    schemas = Path(__file__).resolve().parents[2] / "tools/dosunit/schemas"
    jsonschema.validate(manifest, json.loads((schemas / "dosunit.real16_program_environment.v1.schema.json").read_text()))
    manifest_path = tmp_path / "environment.json"
    manifest_path.write_text(json.dumps(manifest))
    original, candidate = tmp_path / "oracle.exe", tmp_path / "candidate.exe"
    code = "0e1fba7856b80025cd21b80035cd21b8004ccd21"
    original.write_bytes(mz(bytes.fromhex(code)))
    candidate.write_bytes(mz(bytes.fromhex(code.replace("ba7856", "ba7956") if changed else code)))
    output = tmp_path / "result.json"
    assert cmd_replay_program16(argparse.Namespace(
        oracle_exe=original, candidate_exe=candidate, environment=manifest_path,
        instruction_limit=100, out=output,
    )) == int(changed)
    result = json.loads(output.read_text())
    jsonschema.validate(result, json.loads((schemas / "dosunit.real16_program_replay.v1.schema.json").read_text()))
    assert result["contract"]["services"]["dos_vectors"] == vector_policy_document(env.vector_policy)
    assert result["agreement"] == ("mismatched" if changed else "agreed")
    assert result["proof_status"] == "not_established_by_execution"
