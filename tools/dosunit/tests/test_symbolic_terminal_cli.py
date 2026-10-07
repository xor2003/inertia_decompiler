"""Public terminal proof commands must retain conditional scope and freshness."""

import json
from pathlib import Path

import jsonschema
import pytest
from tools.dosunit.tests.test_pe32_program_cli import arguments as pe_arguments
from tools.dosunit.tests.test_pe32_program_replay import exit_code
from tools.dosunit.tests.test_real16_program_cli import arguments as mz_arguments

from tools.dosunit.dosunit import main


def invoke(bits, args, extra=()):
    """Exercise the ordinary public parser and dispatcher."""
    return main([f"compare-terminal{bits}", "--oracle-exe", str(args.oracle_exe),
                 "--candidate-exe", str(args.candidate_exe), "--environment", str(args.environment),
                 "--out", str(args.out), *extra])


@pytest.mark.parametrize("bits", [16, 32])
@pytest.mark.parametrize("changed", [False, True])
def test_native_terminal_report_is_independent_of_execution(tmp_path, bits, changed):
    args = (mz_arguments(tmp_path, "b8084ccd21" if changed else "b8074ccd21") if bits == 16
            else pe_arguments(tmp_path, exit_code(0x12345679) if changed else None))
    assert invoke(bits, args) == (1 if changed else 0)
    result = json.loads(args.out.read_text())
    assert result["schema"] == "dosunit.symbolic_terminal_compare.v1"
    assert result["status"] == ("counterexample" if changed else "conditional")
    assert result["execution_status"] == "not_run"
    assert result["assumptions"]
    assert len(result["inputs"]) == 3
    assert result["oracle"]["source_sha256"] == result["inputs"][0]["sha256"]
    assert result["candidate"]["source_sha256"] == result["inputs"][1]["sha256"]
    assert result["domain"]["faults"] == "not_established"
    schema_path = Path(__file__).resolve().parents[3] / "tools/dosunit/schemas/dosunit.symbolic_terminal_compare.v1.schema.json"
    schema = json.loads(schema_path.read_text())
    jsonschema.validate(result, schema)
    result["status"] = "proved"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(result, schema)



@pytest.mark.parametrize("bits", [16, 32])
def test_stale_binary_prevents_publication(tmp_path, monkeypatch, bits):
    import tools.dosunit.compare.symbolic_terminal as owner

    args = mz_arguments(tmp_path) if bits == 16 else pe_arguments(tmp_path)
    original = owner.compare_symbolic_terminals

    def mutate(*call_args, **kwargs):
        result = original(*call_args, **kwargs)
        args.oracle_exe.write_bytes(args.oracle_exe.read_bytes() + b"changed")
        return result

    monkeypatch.setattr(owner, "compare_symbolic_terminals", mutate)
    assert invoke(bits, args) == 2
    assert not args.out.exists()


@pytest.mark.parametrize("bits", [16, 32])
def test_solver_budget_cannot_silently_grow(tmp_path, bits):
    args = mz_arguments(tmp_path) if bits == 16 else pe_arguments(tmp_path)
    assert invoke(bits, args, ("--solver-timeout-ms", "9999999")) == 2
    assert not args.out.exists()


@pytest.mark.parametrize("bits", [16, 32])
def test_zero_budget_is_visible_unknown(tmp_path, bits):
    args = mz_arguments(tmp_path) if bits == 16 else pe_arguments(tmp_path)
    assert invoke(bits, args, ("--solver-timeout-ms", "0")) == 2
    result = json.loads(args.out.read_text())
    assert result["status"] == "unknown"
    assert result["terminal_status"] == "unknown"
    assert result["execution_status"] == "not_run"


@pytest.mark.parametrize("bits", [16, 32])
def test_replay_observations_are_not_silently_dropped(tmp_path, bits):
    from tools.dosunit.reporting.pe32_program_manifest import parse_pe_program_manifest
    from tools.dosunit.reporting.real16_program_manifest import parse_program_manifest

    args = mz_arguments(tmp_path) if bits == 16 else pe_arguments(tmp_path)
    document = json.loads(args.environment.read_text())
    address = (document["environment"]["psp_segment"] * 16 if bits == 16
               else document["environment"]["memory"][0]["address"])
    document["observations"] = [{"name": "kept", "size": 1, "oracle_address": address,
                                 "candidate_address": address}]
    parsed = parse_program_manifest(document) if bits == 16 else parse_pe_program_manifest(document)
    assert parsed.oracle_observations and parsed.candidate_observations
    args.environment.write_text(json.dumps(document))
    assert invoke(bits, args) == 2
    assert not args.out.exists()


@pytest.mark.parametrize("bits", [16, 32])
@pytest.mark.parametrize("shifted", [False, True])
def test_native_fault_report_retains_site_and_schema(tmp_path, bits, shifted):
    """Real #DE reports expose both fault records and their explicit site relation."""
    from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes
    from tools.dosunit.tests.test_real16_program_cli import mz

    args = mz_arguments(tmp_path) if bits == 16 else pe_arguments(tmp_path)
    encode = mz if bits == 16 else pe32_bytes
    code = bytes.fromhex("31c0f6f0")
    args.oracle_exe.write_bytes(encode(code))
    args.candidate_exe.write_bytes(encode((b"\x90" if shifted else b"") + code))
    assert invoke(bits, args) == (1 if shifted else 0)
    report = json.loads(args.out.read_text())
    assert report["terminal_status"] == ("counterexample" if shifted else "equivalent")
    assert report["execution_status"] == "not_run"
    for side in ("oracle", "candidate"):
        assert report[side]["outcome"] == "processor_fault"
        assert report[side]["site"] is None
        assert report[side]["fault"]["kind"] == "divide_error"
        assert report[side]["fault"]["vector"] == 0
    assert any(item.get("kind") == "fault_site_relation" for item in report["assumptions"])
    if not shifted:
        assert report["domain"]["faults"] == "compared"
    schema_path = Path(__file__).resolve().parents[3] / "tools/dosunit/schemas/dosunit.symbolic_terminal_compare.v1.schema.json"
    jsonschema.validate(report, json.loads(schema_path.read_text()))
