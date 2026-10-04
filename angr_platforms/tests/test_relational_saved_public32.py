"""Sealed public actual-ELF32 saved-EDX stack-slot correspondence reports.

Layer: tests.
Responsibility: drive the production MSC8/BC5 ``z3cmp32.compare`` public APIs
over real GNU-``as``/``ld`` ELF32 images — real CLE loading, real ``nm -S``
symbol sizes, real IDA-style ``.lst`` boundary labels — with no loader,
solver, symbol or boundary mocks.  The complete ``REG32`` register file (all
GPRs, lazy flag state, segments and EIP) is demanded through the single
declared ``FULL_REG32_OUTPUTS`` seam, never a narrowed ABI.  The swapped
saved-EDX correspondence must prove through the driver's own invariant
handling; every listed mutation must not.  Code bytes differ, so the
initialized-image and startup relations stay unproved; that scope is
asserted, never weakened.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import test_relational_rotation_public32 as public32
from test_flat32_comparator_lane import DriverLane, _driver_lane

from tools.dosunit.proof_contracts import FactCounters, ProofStatus, proof_status_from_legacy

# Verified against the CS_MODE_32 decoder (see test_stack_slot_flat32 for the
# replay-evidenced reading): push ebp; mov ebp,esp; push eax; push ecx;
# push ecx; push edx.  The loop counts ecx down, strides ebx by one, and
# stores the counter dword into [ebp-0x0c].  The epilogue drops the two
# interior slots, then pops ecx, eax and ebp back.  The pushed edx dword is
# retained at [ebp-0x10]; edx itself is never touched by the loop.
ORACLE = "5589e550515152e30b8d5b018d49ff894df4ebf383c40859585dc3"
# Same correspondence with the counter and saved-EDX stack slots exchanged:
# the push order places edx at [ebp-0x0c] and ecx at [ebp-0x10], the loop
# counter lands on [ebp-0x10], and the epilogue moves the counter dword into
# [ebp-0x0c] before restoring the saved slot from the still-live edx value.
CANDIDATE = "5589e550515251e30b8d5b018d49ff894df0ebf38b45f08945f48955f083c40859585dc3"
# The epilogue restores the saved slot from ebx (loop-clobbered), not edx.
EXIT_MUTATION = "5589e550515251e30b8d5b018d49ff894df0ebf38b45f08945f4895df083c40859585dc3"
# The loop strides ebx by two: observably different whenever it executes.
STRIDE_MUTATION = "5589e550515251e30b8d5b028d49ff894df0ebf38b45f08945f48955f083c40859585dc3"
# The loop counter overwrites the saved-EDX slot itself instead of [ebp-0x10].
SLOT_CLOBBER = "5589e550515251e30b8d5b018d49ff894df4ebf38b45f08945f48955f083c40859585dc3"
# Oracle-side mutation: lea edx,[ebx+1] kills the saved register's live value.
ORACLE_EDX_CLOBBER = "5589e550515152e30b8d53018d49ff894df4ebf383c40859585dc3"


@pytest.fixture(params=["msc8", "bc5"], ids=["msc8", "bc5"])
def lane(request: pytest.FixtureRequest) -> Iterator[DriverLane]:
    """Install each production driver through the shared lane seam."""
    with _driver_lane(str(request.param)) as installed_lane:
        yield installed_lane


@pytest.fixture
def full_reg32_outputs(lane: DriverLane, monkeypatch: pytest.MonkeyPatch) -> tuple[str, ...]:
    """Demand every modeled REG32 output through the declared public seam."""
    names = tuple(name for name, _width in lane.adapter.REG32.values())
    monkeypatch.setattr(public32, "FULL_REG32_OUTPUTS", ",".join(names))
    return names


def _public_report(
    lane: DriverLane, work: Path, oracle_hex: str, candidate_hex: str
) -> dict[str, Any]:
    """Build both real ELF32 inputs and return the sealed public report."""
    oracle_elf = public32._build_elf(work, "oracle", oracle_hex)
    candidate_elf = public32._build_elf(work, "candidate", candidate_hex)
    address, size = public32._nm_function_bounds(oracle_elf)
    assert size == len(bytes.fromhex(oracle_hex))
    lst = public32._write_lst(work / "oracle.lst", "f", address, size)
    return public32._compare_public(lane, oracle_elf, lst, candidate_elf, work / "out")


def _retained_invariant_proofs(row: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the row's memory-invariant obligations when the report exposes them."""
    proofs = row.get("memory_invariant_proofs")
    return proofs if isinstance(proofs, list) else []


def _closed_counters(document: dict[str, Any]) -> FactCounters:
    """Require closed evidence-pipeline counters on a serialized fact record."""
    counters = FactCounters(**document)
    assert counters.closed(), document
    return counters


def test_public32_saved_edx_correspondence_proves(
    lane: DriverLane, full_reg32_outputs: tuple[str, ...], tmp_path: Path
) -> None:
    """The swapped saved-EDX correspondence proves under the full REG32 contract."""
    report = _public_report(lane, tmp_path, ORACLE, CANDIDATE)
    row = public32._single_verdict(report)
    assert lane.verdict.Status(row["status"]) is lane.verdict.Status.PASSED, report
    proof = report["proof_evidence"]
    assert ProofStatus(proof["status"]) is ProofStatus.PROVED
    verdicts = proof["verdicts"]
    assert len(verdicts) == 1 and verdicts[0]["id"]["key"] == "f"
    assert ProofStatus(verdicts[0]["status"]) is ProofStatus.PROVED
    counters = _closed_counters(proof["counters"])
    assert counters.classified_fact_count > 0
    assert counters.materialized_count > 0
    assert counters.failure_count == 0
    contract = proof["contract"]
    assert contract["original_hash"] == hashlib.sha256(
        (tmp_path / "oracle.elf").read_bytes()).hexdigest()
    assert contract["candidate_hash"] == hashlib.sha256(
        (tmp_path / "candidate.elf").read_bytes()).hexdigest()
    assert set(full_reg32_outputs) <= set(report["proof_contract"]["outputs"])
    assert str(lane.directory) in str(report["semantic_sources"])
    assert len(row["memory_invariant"]["facts"]) == 4
    proofs = _retained_invariant_proofs(row)
    assert len(proofs) == 2
    assert all(ProofStatus(retained["status"]) is ProofStatus.PROVED for retained in proofs)
    assert row["counters"]["materialized_count"] == 5
    assert row["counters"]["failure_count"] == 0
    public32._assert_unproved_distinct_images(report)


def _assert_never_proved(report: dict[str, Any]) -> dict[str, Any]:
    """The sealed obligation stays unproved with typed proof state retained."""
    row = public32._single_verdict(report)
    assert proof_status_from_legacy(row["status"]) is not ProofStatus.PROVED, report
    proof = report["proof_evidence"]
    assert ProofStatus(proof["status"]) is not ProofStatus.PROVED
    assert proof["verdicts"], report
    for verdict in proof["verdicts"]:
        assert ProofStatus(verdict["status"]) is not ProofStatus.PROVED
        _closed_counters(verdict["counters"])
    _closed_counters(proof["counters"])
    assert report["summary"]["passed"] == 0
    for retained in _retained_invariant_proofs(row):
        assert ProofStatus(retained["status"]) in set(ProofStatus)
    public32._assert_unproved_distinct_images(report)
    return row


def test_public32_saved_edx_exit_mutation_never_proves(
    lane: DriverLane, full_reg32_outputs: tuple[str, ...], tmp_path: Path
) -> None:
    """Restoring the saved slot from live ebx can never discharge the proof."""
    report = _public_report(lane, tmp_path, ORACLE, EXIT_MUTATION)
    _assert_never_proved(report)
    assert set(full_reg32_outputs) <= set(report["proof_contract"]["outputs"])


def test_public32_saved_edx_stride_mutation_never_proves(
    lane: DriverLane, full_reg32_outputs: tuple[str, ...], tmp_path: Path
) -> None:
    """A stride-2 loop cannot discharge the same proof obligation."""
    report = _public_report(lane, tmp_path, ORACLE, STRIDE_MUTATION)
    _assert_never_proved(report)
    assert set(full_reg32_outputs) <= set(report["proof_contract"]["outputs"])


def test_public32_saved_edx_slot_clobber_never_proves(
    lane: DriverLane, full_reg32_outputs: tuple[str, ...], tmp_path: Path
) -> None:
    """Writing the counter into the saved-EDX slot corrupts the final image."""
    report = _public_report(lane, tmp_path, ORACLE, SLOT_CLOBBER)
    _assert_never_proved(report)
    assert set(full_reg32_outputs) <= set(report["proof_contract"]["outputs"])


def test_public32_saved_edx_oracle_clobber_never_proves(
    lane: DriverLane, full_reg32_outputs: tuple[str, ...], tmp_path: Path
) -> None:
    """An oracle that destroys live edx inside the loop cannot match."""
    report = _public_report(lane, tmp_path, ORACLE_EDX_CLOBBER, CANDIDATE)
    _assert_never_proved(report)
    assert set(full_reg32_outputs) <= set(report["proof_contract"]["outputs"])
