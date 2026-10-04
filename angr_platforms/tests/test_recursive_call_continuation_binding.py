"""Per-call metadata must agree with saved words from actual binary effects."""
from __future__ import annotations

import pytest
from recursive_proof_fixtures.call_continuation_inputs import make_two_call_inputs, swap_declared_continuations
from recursive_proof_fixtures.flat_call_continuation_inputs import make_flat_two_call_system
from test_flat32_comparator_lane import _driver_lane

from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.recursive_proofs.real16_image_bound_domain import prove_image_bound_real16_domain
from tools.dosunit.recursive_proofs.recursive_joint_admission import admit_joint_system
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointReason
from tools.dosunit.recursive_proofs.recursive_joint_proof import check_joint_system


@pytest.fixture(scope="module")
def two_call_inputs(tmp_path_factory: pytest.TempPathFactory):
    return make_two_call_inputs(tmp_path_factory.mktemp("per-call-binding"))


def test_actual_two_call_system_preserves_independent_saved_words(two_call_inputs) -> None:
    """A complete generic modeled proof still retains its physical scope limits."""
    report = check_joint_system(two_call_inputs.system, timeout_ms=120000)
    assert report.status is ProofStatus.CONDITIONAL and report.reason is JointReason.CONDITIONAL_MODEL, report
    assert report.frames and all(frame.status is ProofStatus.PROVED for frame in report.frames)


def test_swapped_call_metadata_cannot_reuse_global_return_membership(two_call_inputs) -> None:
    """Fresh source receipts distinguish this from stale-proposal rejection."""
    inputs = two_call_inputs
    corrupted = swap_declared_continuations(inputs.system)
    original_layout = admit_joint_system(inputs.system)
    corrupted_layout = admit_joint_system(corrupted)
    assert corrupted_layout == original_layout
    assert corrupted.expected_nodes == inputs.system.expected_nodes
    receipt = prove_image_bound_real16_domain(corrupted, *inputs[1:])
    assert receipt.status is ProofStatus.PROVED, receipt
    assert receipt.system == corrupted
    report = check_joint_system(corrupted, timeout_ms=120000)
    assert report.status is ProofStatus.UNKNOWN and report.reason is JointReason.COUNTERMODEL, report
    assert report.proof.counters.failure_count > 0


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
@pytest.mark.parametrize("corrupted", [False, True])
def test_both_flat32_drivers_bind_each_actual_call(driver: str, corrupted: bool) -> None:
    """Both native adapters reject metadata swaps that preserve the global set."""
    with _driver_lane(driver) as lane, lane.adapter.installed({}, region=True):
        system = make_flat_two_call_system()
        layout = admit_joint_system(system)
        if corrupted:
            system = swap_declared_continuations(system)
            assert admit_joint_system(system) == layout
        report = check_joint_system(system, timeout_ms=120000)
    if corrupted:
        assert report.status is ProofStatus.UNKNOWN and report.reason is JointReason.COUNTERMODEL, report
        assert report.frames[-1].countermodel
    else:
        assert report.status is ProofStatus.CONDITIONAL and report.reason is JointReason.CONDITIONAL_MODEL, report
        assert report.proof.counters.failure_count == 0
