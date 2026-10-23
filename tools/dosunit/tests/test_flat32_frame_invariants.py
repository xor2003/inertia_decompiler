"""Positive and adversarial controls for proved interior stack-frame equality."""
import copy
import time
from typing import Any

import pytest

from tools.dosunit.compare.flat32_frame_invariants import frame_invariant_projection
from tools.dosunit.compare.flat32_loop_calls import compare_flat32_loop_calls
from tools.dosunit.tests.test_flat32_comparator_lane import DriverLane, _project

pytest_plugins = ["test_flat32_comparator_lane"]
BASE = 0x100000


def _input(name: str) -> dict[str, Any]:
    """Create an arbitrary full-width register."""
    return {"op": "input", "name": name, "width": 32}


def _literal(value: int) -> dict[str, Any]:
    """Create a literal control token."""
    return {"op": "const", "value": hex(value), "width": 32}


def _graph() -> dict[str, Any]:
    """Establish a frame, preserve it through a cycle, then observe the return."""
    functions = []
    for token in range(3):
        outputs = {"ebp": _input("esp" if token == 0 else "ebp"), "esp": _input("esp")}
        outputs["eip"] = _literal(1) if token == 0 else {
            "op": "ite", "width": 32, "args": [_input("ecx"), _literal(1), _literal(2)]}
        functions.append({"source": {"cutpoint_token": token,
                                      "jumpkind": "Ijk_Ret" if token == 2 else "Ijk_Boring"},
                          "outputs": outputs, "assignments": []})
    return {"functions": functions}


def test_all_edges_proved_and_all_outputs_preserved() -> None:
    """Specialization is justified on each side, including arbitrary root inputs."""
    graph = _graph()
    before = copy.deepcopy(graph)
    result = frame_invariant_projection(graph, graph, deadline=time.monotonic() + 10)
    assert result is not None
    assert graph == before
    for key in ("oracle_initiation_and_preservation", "candidate_initiation_and_preservation"):
        assert [proof["transition"] for proof in result[2][key]] == [0, 1]
    for original, specialized in zip(graph["functions"], result[0]["functions"], strict=True):
        assert original["outputs"].keys() == specialized["outputs"].keys()


@pytest.mark.parametrize("side", [0, 1])
@pytest.mark.parametrize("corruption", ["entry", "loop", "missing", "edge", "entry_backedge", "duplicate_entry", "normalization"])
def test_unsound_frame_proposals_rejected(side: int, corruption: str) -> None:
    """Missing, broken or differently normalized induction never becomes proof."""
    graphs = [_graph(), _graph()]
    graph = graphs[side]
    if corruption == "entry":
        graph["functions"][0]["outputs"]["ebp"] = _input("ebp")
    elif corruption == "loop":
        graph["functions"][1]["outputs"]["esp"] = _literal(0)
    elif corruption == "missing":
        del graph["functions"][1]["outputs"]["ebp"]
    elif corruption in {"edge", "entry_backedge"}:
        graph["functions"][1]["outputs"]["eip"] = _literal(99 if corruption == "edge" else 0)
    elif corruption == "duplicate_entry":
        graph["functions"][1]["source"]["cutpoint_token"] = 0
    else:
        graph["functions"][1]["_constant_normalization"] = {1: 2}
    assert frame_invariant_projection(*graphs, deadline=time.monotonic() + 10) is None


@pytest.mark.parametrize("changed", [False, True])
def test_native_leave_vs_pop(lane: DriverLane, changed: bool) -> None:
    """Different epilogues prove; a changed memory effect remains observable."""
    original = "55 89e5 85c9 7403 49 ebf9 c9 c3"
    candidate = "55 89e5 85c9 7403 49 ebf9 " + ("8900 " if changed else "") + "5d c3"
    result = compare_flat32_loop_calls(
        (_project(original, BASE), _project(candidate, BASE)),
        (BASE, len(bytes.fromhex(original))), (BASE, len(bytes.fromhex(candidate))),
        lane.adapter.OUTPUT_REGS, 20000,
    )
    assert result["status"] == ("refused" if changed else "passed"), result
    if not changed:
        assert result["frame_invariants"]["all_outputs_preserved"]


@pytest.mark.parametrize("offset", [4, 8, 0xFFFFFFFC])
@pytest.mark.parametrize("broken", [False, True])
def test_constant_frame_offset_is_proved(offset: int, broken: bool) -> None:
    """Derive modular offsets at entry and reject a loop that changes them."""
    graph = _graph()
    graph["functions"][0]["outputs"]["ebp"] = {
        "op": "add", "width": 32, "args": [_input("esp"), _literal(offset)]}
    candidate = copy.deepcopy(graph)
    if broken:
        candidate["functions"][1]["outputs"]["esp"] = {
            "op": "add", "width": 32, "args": [_input("esp"), _literal(4)]}
    result = frame_invariant_projection(graph, candidate, deadline=time.monotonic() + 10)
    assert (result is None) == broken
    if result is not None:
        assert result[2]["relation"]["offset"] == offset


@pytest.mark.parametrize("offset", [4, 8])
@pytest.mark.parametrize("changed", [False, True])
def test_native_local_frame_epilogues(lane: DriverLane, offset: int, changed: bool) -> None:
    """LEAVE and explicit local-stack teardown agree only for the proved offset."""
    prefix = f"55 89e5 83ec{offset:02x} 85c9 7403 49 ebf9 "
    original = prefix + "c9 c3"
    candidate = prefix + f"83c4{offset + (4 if changed else 0):02x} 5d c3"
    result = compare_flat32_loop_calls(
        (_project(original, BASE), _project(candidate, BASE)),
        (BASE, len(bytes.fromhex(original))), (BASE, len(bytes.fromhex(candidate))),
        lane.adapter.OUTPUT_REGS, 20000,
    )
    assert result["status"] == ("refused" if changed else "passed"), result
    if not changed:
        assert result["frame_invariants"]["relation"]["offset"] == offset


@pytest.mark.parametrize("changed", [False, True])
def test_literal_frame_proof_with_unused_relocation_map(lane: DriverLane, changed: bool) -> None:
    """An unrelated relocation proposal cannot disable a literal frame proof."""
    original = "55 89e5 85c9 7403 49 ebf9 c9 c3"
    candidate = "55 89e5 85c9 7403 49 ebf9 " + ("8900 " if changed else "") + "5d c3"
    result = compare_flat32_loop_calls(
        (_project(original, BASE), _project(candidate, BASE)),
        (BASE, len(bytes.fromhex(original))), (BASE, len(bytes.fromhex(candidate))),
        lane.adapter.OUTPUT_REGS, 20000,
        candidate_normalization={0x600000: 0x700000},
    )
    assert result["status"] == ("refused" if changed else "conditional"), result
    if not changed:
        assert result["frame_invariants"]["all_outputs_preserved"]
