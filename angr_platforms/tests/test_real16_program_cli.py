"""Initialized program manifest and public report controls on actual MZ bytes."""

import argparse
import json

import pytest

from tools.dosunit.model import DosUnitError
from tools.dosunit.real16_program_cli import cmd_replay_program16
from tools.dosunit.real16_program_manifest import parse_program_manifest


def document():
    arena = bytearray(b"\xA5" * 0x2000)
    arena[:2] = b"\xCD\x20"
    arena[2:4] = (0x1200).to_bytes(2, "little")
    values = dict.fromkeys(("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"), 0)
    values["eflags"] = 2
    return {"schema": "dosunit.real16_program_environment.v1",
            "environment": {"psp_segment": 0x1000, "allocation_hex": bytes(arena).hex(),
                            "registers": values, "fs": 0, "gs": 0}, "observations": []}


def mz(code):
    header = bytearray(64)
    size = len(header) + len(code)
    header[:2] = b"MZ"
    for offset, value in ((2, size % 512), (4, (size + 511) // 512), (8, 4),
                          (12, 0x400), (16, 0x1000), (24, 0x1C)):
        header[offset:offset + 2] = value.to_bytes(2, "little")
    return bytes(header) + code


def arguments(tmp_path, candidate="b8074ccd21"):
    left, right, manifest, report = (tmp_path / name for name in ("left.exe", "right.exe", "env.json", "report.json"))
    left.write_bytes(mz(bytes.fromhex("b8074ccd21")))
    right.write_bytes(mz(bytes.fromhex(candidate)))
    manifest.write_text(json.dumps(document()))
    return argparse.Namespace(oracle_exe=left, candidate_exe=right, environment=manifest,
                              instruction_limit=100, out=report)


@pytest.mark.parametrize("code,expected,agreement", [("b8074ccd21", 0, "agreed"),
                                                   ("b8084ccd21", 1, "mismatched"),
                                                   ("b409cd21", 2, "incomplete")])
def test_actual_program_report_keeps_execution_separate_from_proof(tmp_path, code, expected, agreement):
    args = arguments(tmp_path, code)
    assert cmd_replay_program16(args) == expected
    report = json.loads(args.out.read_text())
    assert report["schema"] == "dosunit.real16_program_replay.v1"
    assert report["proof_status"] == "not_established_by_execution"
    assert report["agreement"] == agreement
    assert report["oracle"]["status"] == "terminated"
    assert report["oracle"]["events"][0]["bytes"] == "214c07"
    assert len(report["inputs"]) == 3


def test_shared_public_command_executes_initialized_mz(tmp_path):
    from tools.dosunit.dosunit import main

    args = arguments(tmp_path)
    assert main(["replay-program16", "--oracle-exe", str(args.oracle_exe),
                 "--candidate-exe", str(args.candidate_exe), "--environment", str(args.environment),
                 "--instruction-limit", "100", "--out", str(args.out)]) == 0
    assert json.loads(args.out.read_text())["oracle"]["exit_code"] == 7


@pytest.mark.parametrize("field,value", [("allocation_hex", "zz"), ("fs", True),
                                        ("psp_segment", -1), ("registers", {}),
                                        ("allocation_hex", "00")])
def test_bad_environment_never_reads_binaries_or_publishes(tmp_path, field, value):
    args = arguments(tmp_path)
    root = document()
    root["environment"][field] = value
    args.environment.write_text(json.dumps(root))
    args.oracle_exe.unlink()
    with pytest.raises(DosUnitError, match="invalid program environment") as error:
        cmd_replay_program16(args)
    assert error.value.__cause__ is not None
    assert not args.out.exists()


def test_missing_output_range_and_duplicate_names_refuse_before_execution():
    root = document()
    observation = {"name": "buffer", "size": 1, "oracle_address": 0x10200, "candidate_address": 0x10200}
    root["observations"] = [observation, observation]
    with pytest.raises(ValueError, match="unique"):
        parse_program_manifest(root)
    root["observations"] = [{**observation, "candidate_address": 0x12000}]
    with pytest.raises(ValueError, match="inside"):
        parse_program_manifest(root)


@pytest.mark.parametrize("mutated", ["oracle_exe", "candidate_exe", "environment"])
def test_input_mutation_cannot_publish_a_stable_report(tmp_path, monkeypatch, mutated):
    import tools.dosunit.real16_program_cli as owner

    args = arguments(tmp_path)
    original = owner.replay_program
    calls = 0

    def alter(boot, **kwargs):
        nonlocal calls
        result = original(boot, **kwargs)
        calls += 1
        if calls == 2:
            path = vars(args)[mutated]
            path.write_bytes(path.read_bytes() + b" ")
        return result

    monkeypatch.setattr(owner, "replay_program", alter)
    with pytest.raises(DosUnitError, match="changed during"):
        cmd_replay_program16(args)
    assert not args.out.exists()
