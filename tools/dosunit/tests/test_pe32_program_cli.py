"""Public PE32 process report and immutable-input controls on serialized binaries."""

import argparse
import json

import pytest
from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes
from tools.dosunit.tests.test_pe32_program_replay import EXIT, STACK, exit_code

from tools.dosunit.contracts.model import DosUnitError
from tools.dosunit.reporting.pe32_program_cli import cmd_replay_pe_program


def document():
    values = dict.fromkeys(("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"), 0)
    values.update(esp=STACK, eflags=2)
    return {"schema": "dosunit.pe32_program_environment.v1", "environment": {
        "registers": values, "exit_address": EXIT,
        "memory": [{"address": STACK - 0x1000, "bytes": "a5" * 0x2000, "access": ["read", "write"]}],
    }}


def arguments(tmp_path, code=None):
    left, right, manifest, report = (tmp_path / name for name in ("left.exe", "right.exe", "env.json", "report.json"))
    left.write_bytes(pe32_bytes(exit_code()))
    right.write_bytes(pe32_bytes(exit_code() if code is None else code))
    manifest.write_text(json.dumps(document()))
    return argparse.Namespace(oracle_exe=left, candidate_exe=right, environment=manifest,
                              instruction_limit=100, out=report)


@pytest.mark.parametrize("code,expected,agreement", [(exit_code(), 0, "agreed"),
                                                   (exit_code(0x12345679), 1, "mismatched"),
                                                   (b"\xeb\xfe", 2, "incomplete")])
def test_public_report_retains_full_width_exit_and_concrete_scope(tmp_path, code, expected, agreement):
    args = arguments(tmp_path, code)
    assert cmd_replay_pe_program(args) == expected
    result = json.loads(args.out.read_text())
    assert result["schema"] == "dosunit.pe32_program_replay.v1"
    assert result["proof_status"] == "not_established_by_execution"
    assert result["agreement"] == agreement
    assert result["oracle"]["exit_code"] == 0x12345678
    assert result["oracle"]["events"][-1]["kind"] == "pe_exit"
    assert len(result["inputs"]) == 3
    from pathlib import Path

    from jsonschema import Draft202012Validator

    schemas = Path(__file__).resolve().parents[3] / "tools/dosunit/schemas"
    Draft202012Validator(json.loads((schemas / "dosunit.pe32_program_replay.v1.schema.json").read_text())).validate(result)
    Draft202012Validator(json.loads((schemas / "dosunit.pe32_program_environment.v1.schema.json").read_text())).validate(document())


def test_shared_command_dispatches_distinct_pe_program_lane(tmp_path):
    from tools.dosunit.dosunit import main

    args = arguments(tmp_path)
    assert main(["replay-program32", "--oracle-exe", str(args.oracle_exe),
                 "--candidate-exe", str(args.candidate_exe), "--environment", str(args.environment),
                 "--instruction-limit", "100", "--out", str(args.out)]) == 0


@pytest.mark.parametrize("field,value", [("registers", {}), ("exit_address", True), ("memory", [])])
def test_bad_environment_prevents_binary_reads_and_report(tmp_path, field, value):
    args = arguments(tmp_path)
    root = document()
    root["environment"][field] = value
    args.environment.write_text(json.dumps(root))
    args.oracle_exe.unlink()
    with pytest.raises(DosUnitError):
        cmd_replay_pe_program(args)
    assert not args.out.exists()


@pytest.mark.parametrize("mutated", ["oracle_exe", "candidate_exe", "environment"])
def test_input_mutation_during_execution_prevents_publication(tmp_path, monkeypatch, mutated):
    import tools.dosunit.runtime.pe32_program_replay as owner

    args = arguments(tmp_path)
    original = owner.replay_pe_program
    calls = 0

    def alter(boot, **kwargs):
        nonlocal calls
        result = original(boot, **kwargs)
        calls += 1
        if calls == 2:
            path = vars(args)[mutated]
            path.write_bytes(path.read_bytes() + b" ")
        return result

    monkeypatch.setattr(owner, "replay_pe_program", alter)
    with pytest.raises(DosUnitError, match="changed during"):
        cmd_replay_pe_program(args)
    assert not args.out.exists()


def test_invalid_candidate_output_is_checked_before_either_execution(tmp_path, monkeypatch):
    import tools.dosunit.runtime.pe32_program_replay as owner

    args = arguments(tmp_path)
    root = document()
    root["observations"] = [{"name": "stack", "size": 4,
                             "oracle_address": STACK, "candidate_address": 0x12300000}]
    args.environment.write_text(json.dumps(root))

    def forbidden_execution(_boot, **_kwargs):
        raise AssertionError("invalid candidate output must be rejected before oracle executes")

    monkeypatch.setattr(owner, "replay_pe_program", forbidden_execution)
    with pytest.raises(DosUnitError, match="observations require"):
        cmd_replay_pe_program(args)
    assert not args.out.exists()
