"""A predecessor implication may remove control only, with complete entrances."""

import time
from dataclasses import replace
from typing import Any

import pytest

from tools.dosunit.compare import flat32_predecessor_edges as P
from tools.dosunit.compare.flat32_call_contracts import (
    CallCompositionLimits,
    _ComposeSession,
    _LiftedBlock,
    _register_widths,
)
from tools.dosunit.compare.flat32_loop_calls import compare_flat32_loop_calls
from tools.dosunit.tests.test_flat32_comparator_lane import DriverLane, _project

pytest_plugins = ["test_flat32_comparator_lane"]


def _const(value: int) -> dict[str, Any]:
    return {"op": "const", "width": 32, "value": hex(value)}


def _input(name: str) -> dict[str, Any]:
    return {"op": "input", "name": name, "width": 32}


def _branch(value: int, left: int, right: int) -> dict[str, Any]:
    predicate = {"op": "eq", "width": 1, "args": [_input("eax"), _const(value)]}
    return {"op": "ite", "width": 32, "args": [predicate, _const(left), _const(right)]}


def _blocks() -> dict[int, _LiftedBlock]:
    memory = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    store = {"op": "storele", "width": 0, "args": [memory, _const(0x4000), _const(7)]}
    outputs = [{"ip": _branch(0, 1, 2)}, {"ip": _branch(0, 2, 3), "memory": store},
               {"ip": _input("eax")}, {"ip": _input("eax")}]
    edges = [(1, 2), (2, 3), (), ()]
    return {i: _LiftedBlock(i, None, {"outputs": out, "assignments": []},
                           "Ijk_Boring" if i < 2 else "Ijk_Ret", edges[i], None, None)
            for i, out in enumerate(outputs)}


def _run(blocks: dict[int, _LiftedBlock], entry: int = 0) -> P.PredecessorEdgeResult:
    deadline = time.monotonic() + 5
    session = _ComposeSession(project=None, functions={entry: 4}, labels={},
                              limits=CallCompositionLimits(), reg_widths=_register_widths(),
                              compose_stats={"deadline": deadline})
    return P.prune_predecessor_edges(blocks, entry, session, deadline=deadline)


def test_sole_predecessor_proves_control_but_preserves_store() -> None:
    blocks = _blocks()
    result = _run(blocks)
    proof, = result.proofs
    assert (proof.predecessor, proof.block, proof.retained, proof.removed) == (0, 1, 2, (3,))
    assert result.blocks[1].successors == (2,)
    assert result.blocks[1].part["outputs"]["memory"] is blocks[1].part["outputs"]["memory"]
    assert blocks[1].successors == (2, 3)
    assert blocks[1].part["outputs"]["ip"]["op"] == "ite"
    assert proof.implication.path_conditioned
    assert not proof.implication.input_constraints


def test_mutated_branch_cannot_keep_the_previously_retained_target() -> None:
    blocks = _blocks()
    blocks[1].part["outputs"]["ip"] = _branch(1, 2, 3)
    result = _run(blocks)
    proof, = result.proofs
    assert proof.retained == 3
    assert result.blocks[1].successors != (2,)


@pytest.mark.parametrize("change", ["bypass", "root", "metadata", "call", "obligation", "io"])
def test_missing_local_admission_keeps_both_arms(change: str) -> None:
    blocks = _blocks()
    entry = 0
    if change == "bypass":
        blocks[2] = replace(blocks[2], jumpkind="Ijk_Boring", successors=(1,),
                            part={"outputs": {"ip": _const(1)}, "assignments": []})
    elif change == "root":
        entry = 1
    elif change == "metadata":
        blocks[0] = replace(blocks[0], successors=(2,))
    elif change == "call":
        blocks[0] = replace(blocks[0], jumpkind="Ijk_Call", call_target=99)
    elif change == "obligation":
        blocks[1].part["obligations"] = [{"kind": "pending_exception"}]
    elif change == "io":
        blocks[1].part["outputs"]["io"] = _input("io")
    result = _run(blocks, entry)
    assert result.blocks[1].successors == (2, 3)
    assert not result.proofs


def test_solver_unknown_keeps_native_control(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(P, "branch_under_path", lambda *_args, **_kwargs: None)
    blocks = _blocks()
    result = _run(blocks)
    assert not result.proofs
    assert result.blocks == blocks


def test_expired_deadline_keeps_original_map() -> None:
    blocks = _blocks()
    deadline = time.monotonic() - 1
    session = _ComposeSession(project=None, functions={0: 4}, labels={},
                              limits=CallCompositionLimits(), reg_widths=_register_widths(),
                              compose_stats={"deadline": deadline})
    result = P.prune_predecessor_edges(blocks, 0, session, deadline=deadline)
    assert not result.proofs
    assert result.blocks == blocks


@pytest.mark.parametrize("mutated", [False, True])
def test_native_repeated_condition_and_inverted_branch(lane: DriverLane, mutated: bool) -> None:
    """Actual JNZ under EAX==0 is redundant; replacing it with JZ changes the return."""
    original = "85c07406 b801000000 c3 85c0 " + ("74f6" if mutated else "75f6") + " b802000000 c3"
    candidate = "85c07406 b801000000 c3 b802000000 c3"
    base = 0x100000
    result = compare_flat32_loop_calls(
        (_project(original, base), _project(candidate, base)),
        (base, len(bytes.fromhex(original))), (base, len(bytes.fromhex(candidate))),
        lane.adapter.OUTPUT_REGS, 10000,
    )
    assert (result["status"] == "passed") is (not mutated), result
    if not mutated:
        assert result["predecessor_edge_pruning"]["oracle"]
        assert result["predecessor_edge_pruning"]["candidate"] == []
