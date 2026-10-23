"""Relocated loop induction must stay conditional and reject changed effects."""
from typing import Any

import pytest

from tools.dosunit.compare.flat32_loop_calls import compare_flat32_loop_calls
from tools.dosunit.compare.flat32_proof_retry import retry_function_proof
from tools.dosunit.tests.test_flat32_comparator_lane import DriverLane, _project
from tools.dosunit.tests.test_flat32_loop_calls import BASE, CALLEE, CALLER_SIZE, CODE

pytest_plugins = ["test_flat32_comparator_lane"]
CANDIDATE = BASE + 0x10000
RELOCATION = {CANDIDATE + 9: BASE + 9}


def _context(candidate_code: str = CODE) -> tuple[Any, Any, dict[str, tuple[int, int]], dict[str, tuple[int, int]]]:
    """Keep exact native caller/callee ranges for two relocated byte images."""
    return (
        _project(CODE, BASE), _project(candidate_code, CANDIDATE),
        {"main": (BASE, CALLER_SIZE), "callee": (BASE + CALLER_SIZE, len(bytes.fromhex(CALLEE)))},
        {"main": (CANDIDATE, CALLER_SIZE), "callee": (CANDIDATE + CALLER_SIZE, len(bytes.fromhex(CALLEE)))},
    )


@pytest.mark.parametrize("change", ["none", "callee", "guard", "wrong_map", "token_map"])
def test_relocated_loop_induction(lane: DriverLane, change: str) -> None:
    """Relocation proves only rewritten equality; effects and routing stay checked."""
    code = CODE.replace("43c3", "4bc3") if change == "callee" else CODE
    if change == "guard":
        code = code.replace("85c9", "85d2")
    oracle, candidate, orange, crange = _context(code)
    mapping = dict(RELOCATION)
    if change == "wrong_map":
        mapping[CANDIDATE + 9] = BASE + 10
    if change == "token_map":
        mapping[0] = 1
    result = compare_flat32_loop_calls(
        (oracle, candidate), orange["main"], crange["main"], lane.adapter.OUTPUT_REGS, 20000,
        oracle_functions=dict(orange.values()), candidate_functions=dict(crange.values()),
        candidate_normalization=mapping,
    )
    expected = "conditional" if change == "none" else "refused"
    assert result["status"] == expected, result
    if change == "none":
        assert result["proof_scope"] == "cutpoint_simulation"
        assert result["return_targets_proved"] == 2
        assert result["normalization_assumptions"]["proved"] is False
        assert result["normalization_assumptions"]["constant_map"] == {hex(CANDIDATE + 9): hex(BASE + 9)}
        assert result["assumptions"] == result["normalization_assumptions"]


def test_normalized_retry_reaches_loop_induction(lane: DriverLane) -> None:
    """A cyclic normalized composition reaches induction under the same map."""
    result = retry_function_proof(
        "main", {"status": "refused", "reason": "call_or_exception_boundary"},
        _context(), lane.adapter.OUTPUT_REGS, 20000, candidate_normalization=RELOCATION,
    )
    assert result["status"] == "conditional", result
    assert result["proof_method"] == "closed_call_loop_induction"
    assert result["additional_proof_attempts"]["calls"]["reason"] == "loop_requires_inductive_proof"
    assert "reblocked_cfg" not in result["additional_proof_attempts"]


def test_normalized_loop_without_calls(lane: DriverLane) -> None:
    """Complete loop induction does not require a CALL instruction as evidence."""
    oracle_code = "85c9 7408 bb00002000 49 ebf4 c3"
    candidate_code = "85c9 7408 bb00003000 49 ebf4 c3"
    context = (
        _project(oracle_code, BASE), _project(candidate_code, CANDIDATE),
        {"main": (BASE, CALLER_SIZE)}, {"main": (CANDIDATE, CALLER_SIZE)},
    )
    result = retry_function_proof(
        "main", {"status": "refused", "reason": "earlier_lane_unsupported"}, context,
        lane.adapter.OUTPUT_REGS, 20000, candidate_normalization={0x300000: 0x200000},
    )
    assert result["status"] == "conditional", result
    assert result["proof_method"] == "closed_call_loop_induction"
    assert result["oracle_inlined_calls"] == result["candidate_inlined_calls"] == 0


def test_relocated_loop_without_map_refuses(lane: DriverLane) -> None:
    """Different native return-slot bytes cannot silently become strict equality."""
    oracle, candidate, orange, crange = _context()
    result = compare_flat32_loop_calls(
        (oracle, candidate), orange["main"], crange["main"], lane.adapter.OUTPUT_REGS, 20000,
        oracle_functions=dict(orange.values()), candidate_functions=dict(crange.values()),
    )
    assert result["status"] == "refused", result
