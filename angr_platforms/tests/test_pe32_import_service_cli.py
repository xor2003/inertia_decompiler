"""Public PE32 import-service reports retain conditional scope and typed events.

Layer: tests.
Responsibility: exercise actual PE bytes through the public parser, boot, solver and schemas.
"""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
from test_pe32_import_service import pe32_import_bytes, pe_environment, two_call_code

from tools.dosunit.dosunit import main


@pytest.mark.parametrize("changed", [False, True], ids=["equivalent", "different_occurrence"])
def test_public_import_service_report(tmp_path: Path, changed: bool) -> None:
    """Native service equality is conditional; using another response is a counterexample."""
    environment = pe_environment()
    manifest = {"schema": "dosunit.pe32_program_environment.v1", "environment": {
        "registers": dict(environment.registers), "exit_address": environment.exit_address,
        "memory": [{"address": region.address, "bytes": region.data.hex(), "access": ["read", "write"]}
                   for region in environment.memory],
        "services": [service.declared_fields() for service in environment.services],
    }}
    oracle, candidate = tmp_path / "oracle.exe", tmp_path / "candidate.exe"
    declared, output = tmp_path / "environment.json", tmp_path / "comparison.json"
    oracle.write_bytes(pe32_import_bytes(two_call_code(store="first")))
    candidate.write_bytes(pe32_import_bytes(two_call_code(store="second" if changed else "first")))
    declared.write_text(json.dumps(manifest))
    schema_dir = Path(__file__).resolve().parents[2] / "tools/dosunit/schemas"
    jsonschema.validate(manifest, json.loads((schema_dir / "dosunit.pe32_program_environment.v1.schema.json").read_text()))
    assert main([
        "compare-terminal32", "--oracle-exe", str(oracle), "--candidate-exe", str(candidate),
        "--environment", str(declared), "--out", str(output),
    ]) == (1 if changed else 0)
    report = json.loads(output.read_text())
    jsonschema.validate(report, json.loads((schema_dir / "dosunit.symbolic_terminal_compare.v1.schema.json").read_text()))
    assert report["status"] == ("counterexample" if changed else "conditional")
    assert report["execution_status"] == "not_run"
    assert any(premise.get("kind") == "imported_service_contract" for premise in report["assumptions"])
    for side in ("oracle", "candidate"):
        assert report[side]["native_limits"] == {"max_blocks": 8, "max_block_bytes": 4096, "max_instructions": 256}
        events = report[side]["service_events"]
        assert [event["kind"] for event in events] == ["pe32_import", "pe32_import"]
        assert [event["sequence"] for event in events] == [0, 1]
        assert all(event["service"] == "kernel32.dll!GetTickCount" for event in events)
