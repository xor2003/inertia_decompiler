"""Public real16 macro induction with complete-state and budget controls."""

from __future__ import annotations

from pathlib import Path

import pytest
from test_dosunit_tool import _edge_catalog, _mz_exe
from test_macro_step_proof import (
    CANDIDATE16,
    LOOP16,
    ORACLE16,
    SPLIT16,
    STORE16,
    STRIDE16,
    STUTTER16,
)

from tools.dosunit import real16_binary_compare, real16_macro_retry
from tools.dosunit.macro_step_contracts import MacroProofReason, MacroStepProof
from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.proof_scope import ProofScope

# Original unequal-step family, real16 MZ bytes (owned by test_macro_step_proof).
# stc;ret replaces the final `ret`: a return-flags mutation on the unrolled body.
STC16 = bytes.fromhex("e30c8d5f0149e3068d5f0149ebf2f9c3")
assert CANDIDATE16[:-1] + bytes.fromhex("f9c3") == STC16

FUNCTION_ID = "demo.exe:loop"
TIMEOUT = 60000


def _pair(
    tmp_path: Path, oracle_code: bytes, candidate_code: bytes,
) -> tuple[Path, Path, dict, dict]:
    """Write both MZ images and their matching edge catalogs."""
    outputs: dict[str, tuple[Path, dict]] = {}
    for side, code in (("oracle", oracle_code), ("candidate", candidate_code)):
        path = tmp_path / f"{side}.exe"
        path.write_bytes(_mz_exe(bytes(0x200) + code))
        outputs[side] = (path, _edge_catalog(FUNCTION_ID, "loop", offset=0x200, size=len(code)))
    oracle_path, oracle_catalog = outputs["oracle"]
    candidate_path, candidate_catalog = outputs["candidate"]
    return oracle_path, candidate_path, oracle_catalog, candidate_catalog


def _report(
    tmp_path: Path, oracle_code: bytes, candidate_code: bytes, *, solver_timeout_ms: int = TIMEOUT,
) -> dict:
    """Run the sealed public binary16 comparison for one code pair."""
    oracle_exe, candidate_exe, oracle_catalog, candidate_catalog = _pair(
        tmp_path, oracle_code, candidate_code,
    )
    return real16_binary_compare.compare_binary16(
        oracle_exe, candidate_exe, oracle_catalog, candidate_catalog,
        solver_timeout_ms=solver_timeout_ms,
    )


def _function_backend(report: dict) -> dict:
    """Return the retained backend evidence for the single requested function."""
    return report["backend"]["function_proofs"][FUNCTION_ID]


def test_public_macro_retry_proves_original_unroll2(tmp_path: Path) -> None:
    """Production owner discharges the unequal-step pair via macro method."""
    report = _report(tmp_path, ORACLE16, CANDIDATE16)
    assert report["status"] == "proved", report["proof"]
    verdict = report["proof"]["verdicts"][0]
    assert verdict["status"] == "proved"
    assert verdict["method"] == real16_macro_retry.MACRO_STEP_METHOD
    assert verdict["counters"]["materialized_count"] > 0
    assert verdict["counters"]["failure_count"] == 0
    backend = _function_backend(report)
    assert "paired_regions" in backend
    macro = backend["macro_steps"]
    assert macro["status"] == "proved"
    assert macro["admitted_status"] == "proved"
    assert macro["proof_scope"] == ProofScope.CUTPOINT_SIMULATION.value
    assert macro["transitions"]
    assert any(row["oracle_segments"] != row["candidate_segments"] for row in macro["transitions"])
    assert report["proof_scope"] == "requested_functions_over_shared_input_memory"


@pytest.mark.parametrize(
    "candidate",
    [STC16, STORE16, STRIDE16, STUTTER16],
    ids=["stc_return_flags", "hidden_store", "wrong_stride", "one_sided_stutter"],
)
def test_public_macro_mutations_cannot_prove(
    tmp_path: Path, candidate: bytes,
) -> None:
    """Semantic mutations stay UNKNOWN; a scoped SAT is never a counterexample."""
    report = _report(tmp_path, ORACLE16, candidate)
    assert report["status"] == "unknown", report["proof"]
    verdict = report["proof"]["verdicts"][0]
    assert verdict["status"] == "unknown"
    assert verdict["method"] != real16_macro_retry.MACRO_STEP_METHOD
    macro = _function_backend(report)["macro_steps"]
    assert macro["status"] != "proved"
    assert macro["admitted_status"] != "proved"


def test_zero_budget_never_attempts_macro(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Zero solver budget: no region retry and no macro attempt may run."""
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("zero budget must not invoke either retry engine")

    monkeypatch.setattr(real16_macro_retry, "retry_whole_function", forbidden)
    monkeypatch.setattr(real16_macro_retry, "compare_real16_macro", forbidden)
    report = _report(tmp_path, ORACLE16, CANDIDATE16, solver_timeout_ms=0)
    assert report["status"] == "unknown", report["proof"]
    backend = _function_backend(report)
    assert backend["reason"] == "compose_budget_exceeded"
    assert "paired_regions" not in backend
    assert "macro_steps" not in backend


def test_region_proved_neighbor_never_reaches_macro(tmp_path: Path) -> None:
    """Ordering: a pair the region retry already proves skips the macro stage."""
    report = _report(tmp_path, LOOP16, SPLIT16)
    assert report["status"] == "proved", report["proof"]
    verdict = report["proof"]["verdicts"][0]
    assert verdict["method"] == "ssa_z3_paired_region_induction"
    backend = _function_backend(report)
    assert "paired_regions" in backend
    assert "macro_steps" not in backend


def test_scoped_counterexample_admits_unknown_not_failure() -> None:
    """Owner boundary: a cutpoint-scoped SAT never becomes a counterexample."""
    proof = MacroStepProof(
        ProofStatus.COUNTEREXAMPLE, MacroProofReason.UNPROVED, None, (),
        FactCounters(1, 1, 1, 1, 0), (), None, None, ProofScope.CUTPOINT_SIMULATION,
    )
    assert real16_macro_retry.admit_macro_status(proof) is ProofStatus.UNKNOWN
    proved = MacroStepProof(
        ProofStatus.PROVED, MacroProofReason.PROVED, None, (),
        FactCounters(1, 1, 1, 1, 0), (), None, None, ProofScope.CUTPOINT_SIMULATION,
    )
    assert real16_macro_retry.admit_macro_status(proved) is ProofStatus.PROVED


def test_candidate_resolution_exhaustion_never_starts_macro(monkeypatch: pytest.MonkeyPatch) -> None:
    """The total deadline also charges candidate resolution before solver work."""
    from tools.dosunit.proof_contracts import (
        Architecture,
        ContractIdentity,
        Obligation,
        ObligationEvidence,
        ObligationId,
    )
    from tools.dosunit.real16_call_contracts import Real16CallLimits
    from tools.dosunit.real16_call_retry import FunctionRetryEvidence

    class Clock:
        now = 0.0

        def monotonic(self) -> float:
            return self.now

    clock = Clock()
    obligation = Obligation(ObligationId("function", "f"))
    contract = ContractIdentity(Architecture.REAL16, *("boundary-probe",) * 5)
    prior = FunctionRetryEvidence(ObligationEvidence(obligation.id, contract, ProofStatus.UNKNOWN), {})

    def resolve(*_args: object) -> str:
        clock.now = 1.0
        return "f"

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("expired resolution budget must not start macro proof")

    monkeypatch.setattr(real16_macro_retry, "time", clock)
    monkeypatch.setattr(real16_macro_retry, "retry_whole_function", lambda *_args, **_kwargs: prior)
    monkeypatch.setattr(real16_macro_retry, "_sole_candidate_id", resolve)
    monkeypatch.setattr(real16_macro_retry, "compare_real16_macro", forbidden)
    result = real16_macro_retry.retry_whole_function_with_macro(
        obligation, {"id": "f"}, contract, {}, {}, None,
        timeout_ms=100, limits=Real16CallLimits(),
    )
    assert result is not None
    assert result.evidence.status is ProofStatus.UNKNOWN
    assert result.evidence.reason == "compose_budget_exceeded"
    assert result.backend["macro_steps"]["attempted"] is False
