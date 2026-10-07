"""Real16 public-comparator controls for an AX/CX-permuted counter loop.

Layer: tests.
Responsibility: pin real-MZ fixtures where the candidate permutes the loop
counter AX->CX for the loop body and restores it before RET, so the complete
final machine state is identical to the oracle (ax=0, cx=input cx). The
public proof must retain the rejected identity attempt and discharge the
register relation; same-shape mutations must never prove.

Statuses are consumed only through the ``ProofStatus`` enum; unmapped
verdict strings raise ``ValueError`` loudly. No reason-text inspection and
no rendered-output checks.
Lane helpers are reused from the production public-comparator test module so
MZ image construction and catalog layout stay identical.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from tools.dosunit.tests.test_real16_binary_compare import _compare, _exe, _verdict

from tools.dosunit.contracts.proof_contracts import ProofStatus

# oracle: test ax,ax; jz ret; body: dec ax; jnz body; ret
# Every input ends with AX=0; both binaries have equal final state, including
# the same return-frame consumption and defined flag effects.
ORACLE = "85c074034875fdc3"

# candidate: xchg ax,cx; test cx,cx; jz tail; body: dec cx; jnz body;
# tail: xchg ax,cx; ret
# The counter is permuted AX->CX inside the region and restored before RET,
# so the complete final machine state matches the oracle exactly. Proving it
# requires a non-identity relation between paired cutpoints.
CANDIDATE = "9185c974034975fd91c3"

# oracle padded with leading/trailing NOP so the aligned loop cutpoints sit at
# the same offsets as in CANDIDATE (1..8), isolating the register relation
# from offset-mismatch refusal.
ORACLE_PADDED = "9085c074034875fd90c3"

# Mutations of CANDIDATE; each must never pass.
# no_restore drops the trailing xchg: ax exits holding input cx, not 0.
# wrong_guard pretests bx,bx instead of the permuted counter register.
MUTANTS: dict[str, str] = {
    "no_restore": "9185c974034975fdc3",
    "wrong_guard": "9185db74034975fd91c3",
}


def _run_pair(tmp_path: Path, tag: str, oracle_hex: str, candidate_hex: str) -> dict[str, Any]:
    """Compare exact pairs and retain complete diagnostics for UNKNOWN results."""
    oracle_exe, oracle_catalog = _exe(tmp_path, f"{tag}o", oracle_hex, len(bytes.fromhex(oracle_hex)))
    candidate_exe, candidate_catalog = _exe(tmp_path, f"{tag}c", candidate_hex,
                                            len(bytes.fromhex(candidate_hex)))
    report = _compare(oracle_exe, candidate_exe, oracle_catalog, candidate_catalog)
    if _status(report) is ProofStatus.UNKNOWN:
        (tmp_path / f"{tag}-unknown-report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True), encoding="utf-8",
        )
    return report


def _status(report: dict[str, Any]) -> ProofStatus:
    """Parse the typed verdict row status; unmapped values raise loudly."""
    return ProofStatus(_verdict(report)["status"])


def test_identity_loop_proves(tmp_path: Path) -> None:
    """Green harness control: the oracle compared to itself must prove."""
    report = _run_pair(tmp_path, "id", ORACLE, ORACLE)
    assert _status(report) is ProofStatus.PROVED, report


def test_permuted_counter_loop_proves(tmp_path: Path) -> None:
    """AX/CX-permuted counter loop has identical final machine state.

    Public evidence must discharge the binary-derived register relation.
    """
    report = _run_pair(tmp_path, "perm", ORACLE, CANDIDATE)
    assert _status(report) is ProofStatus.PROVED, report


def test_permuted_counter_padded_loop_proves(tmp_path: Path) -> None:
    """Same relation with NOP padding so paired cutpoint offsets align.

    Offset alignment alone cannot establish the internal register relation.
    """
    report = _run_pair(tmp_path, "pad", ORACLE_PADDED, CANDIDATE)
    assert _status(report) is ProofStatus.PROVED, report


@pytest.mark.parametrize(
    "candidate",
    list(MUTANTS.values()),
    ids=list(MUTANTS),
)
def test_permuted_counter_mutations_never_prove(tmp_path: Path, candidate: str) -> None:
    """Same-shape mutants must never reach a proved verdict."""
    report = _run_pair(tmp_path, "mut", ORACLE_PADDED, candidate)
    assert _status(report) is not ProofStatus.PROVED, report
