"""Actual machine-byte controls for swapped binary branch graph proposals."""
import json
from pathlib import Path

import pytest
from tools.dosunit.tests.test_dosunit_tool import _edge_catalog, _mz_exe
from tools.dosunit.tests.test_real16_region_proof import _document

from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.compare.real16_binary_compare import compare_binary16
from tools.dosunit.compare.real16_region_proof import compare_real16_regions
from tools.dosunit.compare.region_pairing import BranchOrientation

ORIGINAL = "83f90074098d5f01678d49ffebf2c3"
REVERSED = "83f9007501c38d5f01678d49ffebf1"


@pytest.mark.parametrize("candidate,proved", [
    (REVERSED, True),
    (REVERSED.replace("7501", "7401"), False),
    (REVERSED.replace("8d5f01", "8d5f02"), False),
    (REVERSED.replace("8d49ff", "8d4901"), False),
    ("83f9007501c38d5f01678d49ff8907ebef", False),
    ("83f9007502f9c38d5f01678d49ffebf0", False),
])
def test_actual_reversed_branch_complete_state(tmp_path: Path, candidate: str, proved: bool) -> None:
    """Complete SSA state accepts equal arms and refuses each semantic mutation."""
    docs = [_document(tmp_path, bytes.fromhex(code), name)
            for code, name in [(ORIGINAL, "original"), (candidate, "candidate")]]
    proof = compare_real16_regions(*docs, "demo.exe:loop", timeout_ms=30000)
    assert (proof.status is ProofStatus.PROVED) is proved, proof
    assert proof.graph_search is not None, proof
    if proved:
        assert proof.graph_evidence.orientation is BranchOrientation.PERMUTED
        assert proof.counters.failure_count == 0
        assert all(row.status is ProofStatus.PROVED for row in proof.transitions)
        assert proof.attempts[-1].pairs
    else:
        assert proof.counters.failure_count > 0


def test_wrong_ordered_map_is_retained_before_proved_alternative(tmp_path: Path) -> None:
    """Equivalent exchanged arm effects require rejecting a complete wrong map."""
    original = "83f80074048d5f01c38d5f02c3"
    candidate = "83f80075048d5f02c38d5f01c3"
    docs = [_document(tmp_path, bytes.fromhex(code), name)
            for code, name in [(original, "original"), (candidate, "candidate")]]
    proof = compare_real16_regions(*docs, "demo.exe:loop", timeout_ms=30000)
    assert proof.status is ProofStatus.PROVED, proof
    assert proof.graph_evidence.orientation is BranchOrientation.PERMUTED
    assert proof.attempts[0].status is ProofStatus.UNKNOWN
    assert proof.attempts[0].graph_evidence.orientation is BranchOrientation.ORDERED
    assert proof.attempts[0].pairs != proof.attempts[-1].pairs
    assert proof.attempts[0].counters.failure_count > 0
    assert proof.attempts[-1].counters.failure_count == 0


@pytest.mark.parametrize("candidate,expected", [(REVERSED, "proved"),
                                               (REVERSED.replace("7501", "7401"), "unknown")])
def test_public_reversed_branch_report(tmp_path: Path, candidate: str, expected: str) -> None:
    """Sealed actual-MZ reports preserve complete graph search evidence as JSON."""
    paths, catalogs = [], []
    for name, code_hex in (("original", ORIGINAL), ("candidate", candidate)):
        code = bytes.fromhex(code_hex)
        path = tmp_path / f"{name}.exe"
        path.write_bytes(_mz_exe(bytes(0x200) + code))
        paths.append(path)
        catalogs.append(_edge_catalog("demo.exe:loop", "loop", offset=0x200, size=len(code)))
    report = compare_binary16(*paths, *catalogs, solver_timeout_ms=60000)
    assert report["status"] == expected, report["proof"]
    restored = json.loads(json.dumps(report, sort_keys=True))
    if expected == "proved":
        verdict = restored["proof"]["verdicts"][0]
        assert verdict["method"] == "ssa_z3_paired_region_induction"
        region = restored["backend"]["function_proofs"]["demo.exe:loop"]["paired_regions"]
        assert region["graph_search"]["candidates"]
        assert region["attempts"][-1]["graph_evidence"]["orientation"] == "permuted_binary_successors"
