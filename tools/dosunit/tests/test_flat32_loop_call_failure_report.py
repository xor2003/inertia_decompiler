"""Typed failed-return evidence must survive the loop report boundary."""
import pytest
from tools.dosunit.tests.test_flat32_comparator_lane import DriverLane

import tools.dosunit.compare.flat32_loop_calls as owner
from tools.dosunit.compare.flat32_call_contracts import (
    CallCompositionRefusal,
    CallProofSide,
    ReturnTargetProofFailure,
)
from tools.dosunit.contracts.proof_contracts import ProofStatus

pytest_plugins = ["test_flat32_comparator_lane"]


@pytest.mark.parametrize("retained", [True, False])
def test_loop_refusal_retains_existing_return_failure(lane: DriverLane, monkeypatch, retained: bool) -> None:
    """A refused query keeps exact typed diagnostics without changing its verdict."""
    evidence = ReturnTargetProofFailure(
        status=ProofStatus.UNKNOWN, callsite=0x401010, call_block=0x401000,
        target=0x402000, fallthrough=0x401015,
        solver_result={"status": "refused", "reason": "timeout", "timeout_ms": 1000},
        callee="callee", side=CallProofSide.ORACLE,
    ) if retained else None

    def refuse(*args, **kwargs):
        raise CallCompositionRefusal("call_return_target_unproved:timeout", evidence=evidence)

    monkeypatch.setattr(owner, "_lift_function", refuse)
    with lane.adapter.installed(region=True):
        report = owner.compare_flat32_loop_calls(
            (object(), object()), (0x401000, 1), (0x501000, 1),
            lane.adapter.OUTPUT_REGS, 1000, name="root",
        )
    assert report["function"] == {"name": "root"}
    assert report["status"] is lane.verdict.Status.REFUSED
    assert report["reason"] == "call_return_target_unproved:timeout"
    if evidence is not None:
        assert report["return_proof_failure"] == evidence.to_document()
    else:
        assert "return_proof_failure" not in report
