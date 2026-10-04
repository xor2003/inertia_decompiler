"""Public binary proof of reblocked loops and deliberately changed effects."""

from __future__ import annotations

import pytest
from test_dosunit_tool import _edge_catalog, _mz_exe
from test_real16_region_proof import GUARD, LOOP, SPLIT, STORE, STRIDE

from tools.dosunit.real16_binary_compare import compare_binary16


@pytest.mark.parametrize("candidate,expected", [(SPLIT, "proved"), (GUARD, "unknown"),
                                                (STORE, "unknown"), (STRIDE, "unknown")],
                         ids=["split", "guard", "hidden_store", "stride"])
def test_public_reblocked_loop_checks_complete_behavior(tmp_path, candidate, expected):
    """Fresh binary evidence, full-state proof and public accounting agree."""
    paths, catalogs = [], []
    for side, code in (("original", LOOP), ("candidate", candidate)):
        path = tmp_path / f"{side}.exe"
        path.write_bytes(_mz_exe(bytes(0x200) + code))
        paths.append(path)
        catalogs.append(_edge_catalog("demo.exe:loop", "loop", offset=0x200, size=len(code)))
    report = compare_binary16(*paths, *catalogs, solver_timeout_ms=60000)
    assert report["status"] == expected, report["proof"]
    if expected == "proved":
        verdict = report["proof"]["verdicts"][0]
        assert verdict["method"] == "ssa_z3_paired_region_induction"
        assert report["backend"]["function_proofs"]["demo.exe:loop"]["paired_regions"]["status"] == "proved"
