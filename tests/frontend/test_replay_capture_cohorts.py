"""Layer: tests.
Responsibility: replay deterministic emitted cohorts through public CLIs.
"""
import json
from pathlib import Path

import pytest
import tests.fixtures.replay_capture_test_support as m6

pytestmark = pytest.mark.xdist_group("replay_capture_cohorts")

@pytest.fixture(scope="session")
def receipts(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Run the bounded experiment once per test session."""
    out = tmp_path_factory.mktemp("m6-receipts")
    m6.run_experiment(out)
    m6.build_accounting(out)
    return out


def test_experiment_reports_deterministic_and_complete(receipts: Path) -> None:
    """Both tracks repeat byte-identically and every row has a typed status."""
    summary = json.loads((receipts / "run-summary.json").read_text())
    for track in ("real16", "flat32"):
        assert summary["tracks"][track]["determinism"]["orig-mut-1_bytes_equal_orig-mut-2"] is True
        vectors = json.loads((receipts / track / "vectors.json").read_text())["vectors"]
        assert 0 < len(vectors) <= m6.MAX_COHORT_VECTORS
        report = json.loads((receipts / track / "orig-mut-1.json").read_text())
        assert report["proof_status"] == "not_established_by_execution"
        assert {row["id"] for row in report["results"]} == {v["id"] for v in vectors}


def test_orig_orig_has_no_mismatch_and_orig_mut_diverges(receipts: Path) -> None:
    """Original/original agrees; the one-byte mutation diverges observably."""
    for track in ("real16", "flat32"):
        orig = json.loads((receipts / track / "orig-orig.json").read_text())
        assert orig["summary"]["mismatched"] == 0
        mut = json.loads((receipts / track / "orig-mut-1.json").read_text())
        assert mut["summary"]["mismatched"] >= 1
        assert mut["summary"]["incomplete"] >= 1  # typed non-return rows exist


def test_runtime_and_edge_rows_have_expected_typed_outcomes(receipts: Path) -> None:
    """Runtime, cpuid, budget and unmapped rows keep their typed outcomes."""
    ledger = json.loads((receipts / "accounting.json").read_text())
    rows16 = {row["id"]: row for row in ledger["tracks"]["real16"]["vectors"]}
    rows32 = {row["id"]: row for row in ledger["tracks"]["flat32"]["vectors"]}
    for rows, prefix in ((rows16, "r16"), (rows32, "f32")):
        runtime = rows[f"{prefix}-rt-00"]
        assert runtime["provenance"]["kind"] == "runtime_capture"
        assert runtime["provenance"]["capture"]["status"] == "captured"
        replaced = runtime["provenance"]["capture"]["replaced_cells"]
        assert replaced and all(
            "captured_bytes" in cell and "return trap occupies the captured return slot"
            in cell["replacement"]
            for cell in replaced
        )
        windows = runtime["provenance"]["capture"]["windows"]
        assert windows and all(
            window["admission"] == "admitted" and window["provenance"]
            for window in windows
        )
        assert runtime["runs"]["orig-mut"]["agreement"] == "mismatched"
        cpuid = rows[f"{prefix}-edge-cpuid"]
        for run in cpuid["runs"].values():
            assert run["oracle"]["status"] == "unsupported"
            assert run["oracle"]["detail"] == "undeclared_machine_input"
            assert run["agreement"] == "incomplete"
        budget = rows[f"{prefix}-edge-budget"]
        assert budget["runs"]["orig-orig"]["oracle"]["status"] == "budget_exhausted"
        assert budget["runs"]["orig-mut"]["agreement"] == "incomplete"
    unmapped = rows32["f32-edge-unmapped-obs"]
    for run in unmapped["runs"].values():
        assert run["oracle"]["observations"] == [{"address": "0x800000", "status": "unmapped"}]
        assert run["agreement"] == "incomplete"


def test_every_vector_has_hash_provenance_and_typed_row(receipts: Path) -> None:
    """Every emitted vector carries a hash, a provenance kind and typed rows."""
    ledger = json.loads((receipts / "accounting.json").read_text())
    kinds = {"runtime_capture", "deterministic_fuzz", "deterministic_edge"}
    for track in ("real16", "flat32"):
        vectors = ledger["tracks"][track]["vectors"]
        assert vectors and all(len(row["sha256"]) == 64 for row in vectors)
        assert {row["provenance"]["kind"] for row in vectors} <= kinds
        for row in vectors:
            for run in row["runs"].values():
                assert run["agreement"] in {"agreed", "mismatched", "incomplete"}

