"""Layer: Tests.

Responsibility: bind call discharge to closed callee effects, including changed
transitive dependencies; distinguish diagnostic parts from whole-function proof.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from test_dosunit_tool import _edge_function, _mz_exe

from tools.dosunit import straightline_ssa as ssa
from tools.dosunit.real16_binary_compare import compare_binary16


def _chain(tmp_path: Path, changed: bool) -> tuple[Path, Path, dict[str, Any]]:
    """Only the final leaf's AX immediate differs; both caller bodies are identical."""
    paths = []
    for name, value in (("oracle", 1), ("candidate", 2 if changed else 1)):
        body = bytearray(0x300)
        body[0x200:0x204] = bytes.fromhex("e82d00c3")
        body[0x230:0x234] = bytes.fromhex("e82d00c3")
        body[0x260:0x264] = b"\xb8" + value.to_bytes(2, "little") + b"\xc3"
        path = tmp_path / f"{name}.exe"
        path.write_bytes(_mz_exe(bytes(body)))
        paths.append(path)
    catalog = {"schema": "dosunit.functions.v1", "module": "demo.exe", "functions": [
        _edge_function(f"demo.exe:{name}", name, offset=offset, size=4)
        for name, offset in (("caller", 0x200), ("mid", 0x230), ("leaf", 0x260))
    ]}
    return paths[0], paths[1], catalog


def test_changed_transitive_leaf_cannot_discharge_call_part(tmp_path: Path) -> None:
    """Identical middle-function bytes do not prove its different leaf dependency."""
    oracle, candidate, catalog = _chain(tmp_path, changed=True)
    documents = [ssa.lower_straightline_ssa_document(
        exe_path=path, functions_catalog=catalog, output_regs=("ax", "bx"),
        max_blocks_per_function=32,
    ) for path in (oracle, candidate)]
    result = ssa.compare_ssa_documents(
        oracle=documents[0], candidate=documents[1], skip_binary_equal=False,
        semantic_proof_passes=4, timeout_ms=2000,
    )
    rows = result["results"]
    leaf = [row for row in rows if row["function"]["name"] == "leaf"]
    assert leaf and all(row["status"] == "failed" for row in leaf), result
    for name in ("mid", "caller"):
        calls = [row for row in rows if row["function"]["name"] == name and row.get("call_compare")]
        assert calls and all(row["status"] != "passed" for row in calls), result
        assert all(not row["call_compare"]["equivalent"] for row in calls), result


@pytest.mark.parametrize("changed", [False, True])
def test_public_chain_keeps_whole_function_outcome(tmp_path: Path, changed: bool) -> None:
    """Complete composition proves the identical chain and rejects its changed leaf."""
    oracle, candidate, catalog = _chain(tmp_path, changed)
    report = compare_binary16(
        oracle, candidate, catalog, catalog, selected=("caller",),
        solver_timeout_ms=2000, max_function_ms=15000,
    )
    report_path = tmp_path / "comparison-report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    assert report["status"] == ("counterexample" if changed else "proved"), report_path
