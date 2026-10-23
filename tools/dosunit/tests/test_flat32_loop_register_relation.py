"""Complete call-loop proofs with solver-checked internal register correspondence."""
import json
from pathlib import Path

import pytest

from tools.dosunit.compare.flat32_loop_calls import compare_flat32_loop_calls
from tools.dosunit.tests.test_flat32_comparator_lane import DriverLane, _project

pytest_plugins = ["test_flat32_comparator_lane"]
BASE = 0x100000
# Aligned caller/callee bytes: the candidate swaps EAX/ECX internally and
# restores them before RET. Both loops call the real INC EBX; RET helper.
ORACLE = "9085c07408e8050000004875f890c343c3"
CANDIDATE = "9185c97408e8050000004975f891c343c3"


@pytest.mark.parametrize("relocated", [False, True])
@pytest.mark.parametrize("mutation", ["none", "no_restore", "increment", "guard", "callee"])
def test_loop_register_correspondence(lane: DriverLane, relocated: bool, mutation: str) -> None:
    """Initiation, every transition and restored returns must all discharge."""
    candidate = CANDIDATE
    if mutation == "no_restore":
        candidate = candidate.replace("91c3", "90c3")
    elif mutation == "increment":
        candidate = candidate.replace("4975", "4175")
    elif mutation == "guard":
        candidate = candidate.replace("85c9", "85db")
    elif mutation == "callee":
        candidate = candidate.replace("43c3", "4bc3")
    candidate_base = BASE + 0x10000 if relocated else BASE
    normalization = {candidate_base + 10: BASE + 10} if relocated else None
    result = compare_flat32_loop_calls(
        (_project(ORACLE, BASE), _project(candidate, candidate_base)),
        (BASE, 15), (candidate_base, 15), tuple(name for name, _ in lane.adapter.REG32.values()), 20000,
        oracle_functions={BASE: 15, BASE + 15: 2},
        candidate_functions={candidate_base: 15, candidate_base + 15: 2},
        candidate_normalization=normalization,
    )
    if mutation != "none":
        assert result["status"] == "refused", result
        return
    assert result["status"] == ("conditional" if relocated else "passed"), result
    assert result["register_relation"]
    assert result["relation_attempts"][0]["status"] == "unknown"
    assert result["relation_attempts"][-1]["status"] == ("conditional" if relocated else "proved")
    assert result["return_targets_proved"] >= 2
    if relocated:
        assert result["normalization_assumptions"]["proved"] is False


@pytest.mark.parametrize("mutation", ["none", "guard", "update", "live_output", "entry_read"])
def test_loop_constant_scratch_register(lane: DriverLane, mutation: str) -> None:
    """A derived invariant may hide only a dead oracle scratch coordinate."""
    original = "8b4424048b008078040075f8c3"
    rebuilt = "8b4424042bc98b0038480475f9c3"
    outputs = ("eax", "edx", "esp")
    if mutation == "guard":
        rebuilt = rebuilt.replace("384804", "384805")
    elif mutation == "update":
        rebuilt = "8b4424042bc98b004138480475f8c3"
    elif mutation == "live_output":
        outputs = (*outputs, "ecx")
    elif mutation == "entry_read":
        original = "8b44240401088b008078040075f8c3"
    result = compare_flat32_loop_calls(
        (_project(original, BASE), _project(rebuilt, BASE)),
        (BASE, len(bytes.fromhex(original))), (BASE, len(bytes.fromhex(rebuilt))), outputs, 5000,
    )
    assert result["status"] == ("passed" if mutation == "none" else "refused"), result
    if mutation == "none" and not result["constant_register_invariants"]:
        facts = result["native_constant_invariants"]["candidate"]
        assert any(values.get("ecx") == 0 for values in facts["entry_values"].values())
        assert all(edge["proof"]["status"] == "passed" for edge in facts["incoming_edge_proofs"])


@pytest.mark.parametrize("mutation", ["none", "first_constant", "second_constant", "observe_edx"])
def test_multiple_loop_constant_coordinates(lane: DriverLane, mutation: str, tmp_path: Path) -> None:
    """Sequential invariants must establish every hidden scratch coordinate."""
    original = "8b4424048b008078040075f88078050175f2c3"
    rebuilt = "8b442404b9010000002bd28b0038500475f938480575f4c3"
    outputs = ("eax", "esp")
    if mutation == "first_constant":
        rebuilt = rebuilt.replace("b901000000", "b902000000")
    elif mutation == "second_constant":
        rebuilt = rebuilt.replace("2bd2", "ba01000000")
    elif mutation == "observe_edx":
        outputs = (*outputs, "edx")
    result = compare_flat32_loop_calls(
        (_project(original, BASE), _project(rebuilt, BASE)),
        (BASE, len(bytes.fromhex(original))), (BASE, len(bytes.fromhex(rebuilt))), outputs, 5000,
    )
    (tmp_path / "loop-constant-result.json").write_text(json.dumps(result, default=str, indent=2))
    assert result["status"] == ("passed" if mutation == "none" else "refused"), result
    if mutation == "none":
        if result["constant_register_invariants"]:
            assert {item["register"] for item in result["constant_register_invariants"]} == {"ecx", "edx"}
        else:
            facts = result["native_constant_invariants"]["candidate"]
            assert any(values.get("ecx") == 1 and values.get("edx") == 0
                       for values in facts["entry_values"].values())
            assert all(edge["proof"]["status"] == "passed" for edge in facts["incoming_edge_proofs"])



@pytest.mark.parametrize("mutation", ["none", "return", "memory", "live_scratch"])
def test_scratch_swap_composes_with_frame_and_liveness(lane: DriverLane, mutation: str) -> None:
    """A retained pointer may change registers while dead scratch values differ."""
    original = "55 89e5 8b4508 89c2 85d2 7403 4a ebf9 c9 c3"
    candidate = "55 89e5 8b4d08 89ca 85d2 7403 4a ebf9 8bc1 5d c3"
    outputs = lane.adapter.OUTPUT_REGS
    if mutation == "return":
        candidate = candidate.replace("8bc1", "8bc2")
    elif mutation == "memory":
        candidate = candidate.replace("8bc1", "8bc1 8900")
    elif mutation == "live_scratch":
        outputs = (*outputs, "ecx")
    result = compare_flat32_loop_calls(
        (_project(original, BASE), _project(candidate, BASE)),
        (BASE, len(bytes.fromhex(original))), (BASE, len(bytes.fromhex(candidate))),
        outputs, 20000,
    )
    assert result["status"] == ("passed" if mutation == "none" else "refused"), result
    if mutation == "none":
        assert result["frame_invariants"]
        assert result["narrow_register_projection"]
        assert {(b["candidate"], b["oracle"]) for b in result["register_relation"]} == {
            ("eax", "ecx"), ("ecx", "eax")}
        assert result["relation_attempts"][-1]["composed_relation_attempts"]
