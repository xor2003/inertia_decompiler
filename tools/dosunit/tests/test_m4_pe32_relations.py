"""Layer: tests.
Responsibility: prove existing relation fixtures through actual PE public drivers.
"""
from pathlib import Path

import pytest
from tools.dosunit.tests.test_flat32_register_regions import CANDIDATE as REGISTER_CANDIDATE
from tools.dosunit.tests.test_flat32_register_regions import ORACLE as REGISTER_ORACLE
from tools.dosunit.tests.test_m4_exit_controls import _pe32_report, _save
from tools.dosunit.tests.test_relational_saved_public32 import CANDIDATE as STACK_CANDIDATE
from tools.dosunit.tests.test_relational_saved_public32 import ORACLE as STACK_ORACLE

from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus, proof_status_from_legacy

PAIRS = {
    "register": (REGISTER_ORACLE, REGISTER_CANDIDATE),
    "scaled_affine": ("53e3058d5b01e2fb5bc3", "538d5c5b07e3058d5b03e2fb5bc3"),
    "saved_stack": (STACK_ORACLE, STACK_CANDIDATE),
}


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
@pytest.mark.parametrize("relation", list(PAIRS))
def test_actual_pe32_changed_relations_prove(tmp_path: Path, driver: str, relation: str) -> None:
    """Different code must prove with complete outputs and retained relation evidence."""
    left, right = (bytes.fromhex(code) for code in PAIRS[relation])
    assert left != right
    report = _pe32_report(driver, tmp_path, left, right)
    _save(tmp_path, driver, relation, left, right, report)
    row = report["results"][0]
    assert proof_status_from_legacy(row["status"]) is ProofStatus.PROVED, report
    proof = report["proof_evidence"]
    assert ProofStatus(proof["status"]) is ProofStatus.PROVED
    assert len(proof["verdicts"]) == 1
    assert ProofStatus(proof["verdicts"][0]["status"]) is ProofStatus.PROVED
    counters = FactCounters(**proof["counters"])
    assert counters.closed() and counters.materialized_count > 0 and counters.failure_count == 0
    assert row["counters"]["failure_count"] == 0
    if relation == "saved_stack":
        assert len(row["memory_invariant"]["facts"]) == 4
        obligations = row["memory_invariant_proofs"]
        assert len(obligations) == 2
        assert all(ProofStatus(item["status"]) is ProofStatus.PROVED for item in obligations)
        assert row["counters"]["materialized_count"] == 5
    else:
        assert row["register_relation"]
        if relation == "register":
            assert len(row["relation_attempts"]) == 2
        else:
            assert row["register_relation"][0]["multiplier"] == 3
            assert row["register_relation"][0]["offset"] == 7
