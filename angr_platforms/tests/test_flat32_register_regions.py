"""Register-permutation controls for the staged flat32 CFG comparator.

Layer: tests.
Responsibility: pin real-i386-byte loop fixtures whose oracle and candidate
preserve the same complete final register/memory state only through an
interior EAX/ECX permutation. Full-state initiation, preservation and exits
must discharge under that relation; every same-CFG-shape mutation must refuse.

Verdict strings are consumed only through ``proof_status_from_legacy`` /
``ProofStatus`` at the legacy boundary; no reason-text inspection and no
rendered-output checks. Lane helpers are reused from the production
comparator lane test module so MSC8 and BC5 adapter seams, real angr blob
loads at distinct bases and global seam restore stay identical.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from test_flat32_comparator_lane import (
    CANDIDATE_BASE,
    ORACLE_BASE,
    DriverLane,
    _compare_loops,
    _driver_lane,
    _project,
)

from tools.dosunit.proof_contracts import ProofStatus, proof_status_from_legacy

TIMEOUT_MS = 10000

# oracle: test eax,eax; jz ret; body: dec eax; jnz body; ret
# Every input ends with EAX=0; both binaries consume the same return frame
# and produce equal final registers, lazy flags and memory.
ORACLE = "85c074034875fdc3"

# candidate: xchg eax,ecx; test ecx,ecx; jz tail; body: dec ecx; jnz body;
# tail: xchg eax,ecx; ret
# Identical CFG shape. The counter is permuted EAX->ECX inside the region
# and restored before RET, so the complete final machine state matches the
# oracle exactly: eax=0, ecx=input ecx. Proving it requires a non-identity
# relation between paired cutpoints, discharged by the solver.
CANDIDATE = "9185c974034975fd91c3"

# Mutations of CANDIDATE; each keeps the same CFG shape but must never pass.
# no_restore drops the trailing xchg: eax exits holding input ecx, not 0.
# inc_counter loops with inc ecx instead of dec ecx; the body transition no
# longer matches the oracle's decrement under any register permutation.
# wrong_guard pretests ebx,ebx instead of the counter register.
# ret_cleanup returns with ret 4, leaving esp offset from the oracle.
MUTANTS: dict[str, str] = {
    "no_restore": "9185c974034975fdc3",
    "inc_counter": "9185c974034175fd91c3",
    "wrong_guard": "9185db74034975fd91c3",
    "ret_cleanup": "9185c974034975fd91c20400",
}


@pytest.fixture(params=["msc8", "bc5"], ids=["msc8", "bc5"])
def lane(request: pytest.FixtureRequest) -> Iterator[DriverLane]:
    """Run each control once under each staged driver's isolated seams."""
    with _driver_lane(str(request.param)) as installed_lane:
        yield installed_lane


def _status(result: dict[str, Any]) -> ProofStatus:
    """Map the legacy verdict string to the typed status; unmapped is loud."""
    status = proof_status_from_legacy(result.get("status"))
    assert status is not None, result
    return status


def test_identity_loop_still_proves(lane: DriverLane) -> None:
    """Green harness control: the oracle compared to itself must prove."""
    result = _compare_loops(lane, ORACLE, ORACLE, timeout_ms=TIMEOUT_MS,
                            outputs=tuple(name for name, _ in lane.adapter.REG32.values()))
    assert _status(result) is ProofStatus.PROVED, result


def test_permuted_counter_loop_proves(lane: DriverLane) -> None:
    """EAX/ECX-permuted counter loop has identical final machine state.

    The rejected identity attempt remains visible before the proved map.
    """
    result = _compare_loops(lane, ORACLE, CANDIDATE, timeout_ms=TIMEOUT_MS,
                            outputs=tuple(name for name, _ in lane.adapter.REG32.values()))
    assert _status(result) is ProofStatus.PROVED, result
    assert result["register_relation"]
    assert len(result["relation_attempts"]) == 2
    assert result["counters"]["failure_count"] == 0
    json.dumps(result)


@pytest.mark.parametrize(
    "candidate",
    list(MUTANTS.values()),
    ids=list(MUTANTS),
)
def test_permuted_counter_mutations_never_prove(lane: DriverLane, candidate: str) -> None:
    """Same-shape mutants must never reach a proved verdict."""
    result = _compare_loops(lane, ORACLE, candidate, timeout_ms=TIMEOUT_MS,
                            outputs=tuple(name for name, _ in lane.adapter.REG32.values()))
    assert _status(result) is not ProofStatus.PROVED, result


def test_matched_cutpoint_countermodel_does_not_block_register_retry(lane: DriverLane) -> None:
    """An unreachable identity-cutpoint SAT must allow a checked whole-CFG retry."""
    from tools.dosunit.flat32_proof_retry import retry_function_proof
    from tools.dosunit.proof_scope import ProofScope

    padded = "9085c074034875fd90c3"
    oracle = _project(padded, ORACLE_BASE)
    candidate = _project(CANDIDATE, CANDIDATE_BASE)
    outputs = tuple(name for name, _ in lane.adapter.REG32.values())
    ranges = ((ORACLE_BASE, len(bytes.fromhex(padded))),
              (CANDIDATE_BASE, len(bytes.fromhex(CANDIDATE))))
    original = lane.cfg.compare_cfg(oracle, candidate, name="f", oracle_range=ranges[0],
                                    candidate_range=ranges[1], outputs=outputs, timeout_ms=TIMEOUT_MS)
    assert _status(original) is ProofStatus.UNKNOWN, original
    assert original["proof_scope"] is ProofScope.CUTPOINT_SIMULATION
    assert original["backend_status"] is lane.verdict.Status.FAILED
    retried = retry_function_proof("f", original, (oracle, candidate, {"f": ranges[0]}, {"f": ranges[1]}),
                                  outputs, TIMEOUT_MS)
    assert _status(retried) is ProofStatus.PROVED, retried
    assert retried["register_relation"]
    json.dumps(retried)
