"""Public real16 proof discovers saved-register byte invariants from binary SSA."""
from __future__ import annotations

from pathlib import Path

import pytest
from test_real16_binary_compare import _exe, _verdict

from tools.dosunit.binary_initial_state import InitialImageReason
from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.real16_binary_compare import compare_binary16

ORIGINAL = "5589e550515152e30c8d5f01678d49ff894efaebf283c40459585dc3"
SWAPPED = "5589e550515251e30c8d5f01678d49ff894ef8ebf28b46f88946fa8956f883c40459585dc3"


@pytest.mark.parametrize("mutant", [False, True])
@pytest.mark.xdist_group("real16_memory_smt")
def test_public_saved_dx_invariant(tmp_path: Path, mutant: bool) -> None:
    """Complete public evidence accepts the saved DX relation and rejects EBX restoration."""
    candidate = SWAPPED.replace("8956f8", "895ef8") if mutant else SWAPPED
    oracle, oracle_catalog = _exe(tmp_path, "oracle", ORIGINAL, len(bytes.fromhex(ORIGINAL)))
    rebuilt, rebuilt_catalog = _exe(tmp_path, "candidate", candidate, len(bytes.fromhex(candidate)))
    report = compare_binary16(oracle, rebuilt, oracle_catalog, rebuilt_catalog, solver_timeout_ms=60000)
    assert (ProofStatus(_verdict(report)["status"]) is ProofStatus.PROVED) is not mutant, report
    assert report["inputs"]["oracle"]["sha256"] != report["inputs"]["candidate"]["sha256"]
    image = report["initial_image_relation"]
    assert ProofStatus(image["status"]) is ProofStatus.UNKNOWN
    assert InitialImageReason(image["reason"]) is InitialImageReason.RELATION_REQUIRED
    assert ProofStatus(image["initialized_function_status"]) is ProofStatus.UNKNOWN
    assert image["startup_and_environment_proved"] is False
    if not mutant:
        proof = report["backend"]["function_proofs"]["demo.exe:f"]["paired_regions"]
        assert len(proof["invariant"]["facts"]) == 2
        assert proof["counters"]["materialized_count"] == 5
        assert proof["counters"]["failure_count"] == 0
        assert len(proof["attempts"]) >= 2
