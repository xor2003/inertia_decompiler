"""Binary-derived closed reblocking and deliberate semantic corruption controls."""

import pytest
from tools.dosunit.tests.test_dosunit_tool import _edge_function, _mz_exe
from tools.dosunit.tests.test_real16_call_composition import _lower

from tools.dosunit.compare.paired_region_graph import CollapsedRegion, RegionExitKind
from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.compare.real16_call_contracts import Real16CallLimits, Real16CallRefusal
from tools.dosunit.compare.real16_loop_calls import compare_real16_loop_calls
from tools.dosunit.runtime.real16_mz_load import image_from_mz_bytes
from tools.dosunit.compare.real16_region_proof import compare_real16_regions
from tools.dosunit.compare.real16_region_transitions import related_outputs
from tools.dosunit.runtime.real16_replay import compare_executions, replay
from tools.dosunit.runtime.real16_replay_model import (
    CallerFrame,
    FrameKind,
    Real16Agreement,
    Real16Vector,
    SegOffset,
)

LOOP = bytes.fromhex("85c0 7406 48 894604 75fa c3")
SPLIT = bytes.fromhex("85c0 7408 48 eb00 894604 75f8 c3")
GUARD = bytes.fromhex("85c0 7508 48 eb00 894604 75f8 c3")
STORE = bytes.fromhex("85c0 7408 48 eb00 894606 75f8 c3")
STRIDE = bytes.fromhex("85c0 7408 40 eb00 894604 75f8 c3")


def _document(tmp_path, code, tag):
    image = bytearray(0x300)
    image[0x200:0x200 + len(code)] = code
    return _lower(tmp_path, bytes(image), [_edge_function("demo.exe:loop", "loop", offset=0x200,
                                                        size=len(code))], tag)


def test_split_loop_requires_and_proves_finite_paired_regions(tmp_path):
    left, right = _document(tmp_path, LOOP, "original"), _document(tmp_path, SPLIT, "candidate")
    old = compare_real16_loop_calls(left, right, "demo.exe:loop", timeout_ms=60000)
    assert old.status is ProofStatus.UNKNOWN
    proved = compare_real16_regions(left, right, "demo.exe:loop", timeout_ms=60000)
    assert proved.status is ProofStatus.PROVED, proved
    assert proved.counters.failure_count == 0
    assert any(len(row.oracle_members) != len(row.candidate_members) for row in proved.transitions)
    assert all(row.oracle_members and row.candidate_members for row in proved.transitions)


@pytest.mark.parametrize("candidate", [GUARD, STORE, STRIDE], ids=["guard", "hidden_store", "stride"])
def test_reblocked_semantic_mutations_cannot_pass(tmp_path, candidate):
    left, right = _document(tmp_path, LOOP, "original"), _document(tmp_path, candidate, "candidate")
    proof = compare_real16_regions(left, right, "demo.exe:loop", timeout_ms=60000)
    assert proof.status is ProofStatus.UNKNOWN, proof
    assert proof.counters.failure_count > 0


def test_reblocked_progress_and_budget_cannot_be_assumed(tmp_path):
    cycle = _document(tmp_path, bytes.fromhex("ebfe"), "cycle")
    proof = compare_real16_regions(cycle, cycle, "demo.exe:loop", timeout_ms=60000)
    assert proof.status is ProofStatus.UNKNOWN
    assert proof.detail == "unconditional_chain_cycle"
    left = _document(tmp_path, LOOP, "original")
    proof = compare_real16_regions(left, left, "demo.exe:loop", timeout_ms=60000,
                                  limits=Real16CallLimits(max_compositions=0))
    assert proof.status is ProofStatus.UNKNOWN
    assert proof.counters.failure_count > 0


def test_incoherent_legacy_ip_cannot_be_hidden_by_paired_control():
    state = {"ip": {"op": "const", "width": 16, "value": "0x9999"},
             "control_ip": {"op": "const", "width": 32, "value": "0x1204"}}
    with pytest.raises(Real16CallRefusal, match="legacy_control_projection_unproved"):
        related_outputs(state, CollapsedRegion((0x1200,), (0x1204,), RegionExitKind.BORING), {0x1204: 1}, 3000)


@pytest.mark.parametrize("iterations", [0, 1, 100])
def test_reblocked_loop_matches_independent_guest(iterations):
    images = []
    for code in (LOOP, SPLIT, GUARD, STORE):
        data = bytearray(0x300)
        data[0x200:0x200 + len(code)] = code
        images.append(image_from_mz_bytes(_mz_exe(bytes(data))))
    entry = SegOffset(images[0].load_segment, 0x200)
    vector = Real16Vector(
        registers=(("ax", iterations), ("bp", 0x100), ("sp", 0x1000), ("flags", 2)),
        segments=(("ss", 0x7000), ("ds", entry.segment), ("es", entry.segment)),
        frame=CallerFrame(FrameKind.NEAR16, SegOffset(entry.segment, 0x8000)),
        observations=((SegOffset(0x7000, 0x104), 4),),
    )
    results = [replay(image, entry, vector, instruction_limit=5000) for image in images]
    assert compare_executions(results[0], results[1]).agreement is Real16Agreement.AGREED
    if iterations:
        assert compare_executions(results[0], results[2]).agreement is Real16Agreement.MISMATCHED
        assert compare_executions(results[0], results[3]).agreement is Real16Agreement.MISMATCHED
