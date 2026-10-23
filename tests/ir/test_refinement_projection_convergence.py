"""Stop refinement only when newly dead edges cannot change cone inputs."""

import time

import pytest

from inertia.ir import real16_edge_feasibility8616 as edge
from inertia.ir.core import IRBlock, IRCondition, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.ir.real16_path_memory8616 import PathMemory8616
from inertia.ir.ssa_function import build_x86_16_ir_predecessor_map

pytestmark = pytest.mark.decompiler


def constant(number: int) -> IRValue:
    """Construct one exact word literal."""
    return IRValue(MemSpace.CONST, const=number, size=2)


def branch(register: str, number: int, target: int, addr: int) -> IRInstr:
    """Construct one terminal equality branch with explicit word operands."""
    condition = IRCondition("eq", (IRValue(MemSpace.REG, name=register, size=2), constant(number)), width_bits=16)
    return IRInstr("CJMP", None, (condition, constant(target)), addr=addr)


def analyze(body: IRFunctionArtifact, live: frozenset[int], callsite: int) -> edge.Real16EdgeFeasibility8616:
    """Run the existing bounded must analysis on the explicitly selected cone."""
    return edge.invocation_feasible_scope_8616(
        artifact=body, dangerous=live, predecessor_map=build_x86_16_ir_predecessor_map(body),
        head_addr=0, call_block_addr=callsite, callsite_addr=callsite,
        seed={"ax": 0, "bx": 0}, seed_memory=PathMemory8616(),
        apply_service=lambda *_: False, iteration_limit=64,
        deadline=time.monotonic() + 5, work_limit=10000,
    )


def test_outside_cone_edge_does_not_repeat_complete_transfer(monkeypatch: pytest.MonkeyPatch) -> None:
    """A new external edge cannot alter any of the cone's predecessor meets."""
    body = IRFunctionArtifact(0, (
        IRBlock(0, (branch("ax", 0, 10, 0),), successor_addrs=(10, 20)),
        IRBlock(10), IRBlock(20),
    ))
    original = edge._kb_fixpoint_8616
    visits: list[None] = []

    def counted(*args: object, **kwargs: object) -> object:
        """Count full dataflow passes without altering their results."""
        visits.append(None)
        return original(*args, **kwargs)

    monkeypatch.setattr(edge, "_kb_fixpoint_8616", counted)
    result = analyze(body, frozenset({0, 10}), 10)
    assert result.converged
    assert result.infeasible_edges == ((0, 20),)
    assert result.live_blocks == frozenset({0, 10})
    assert result.evaluated_cjmps == 1
    assert len(visits) == 1


def test_internal_dead_edge_still_refines_an_unchanged_live_set() -> None:
    """Deleting an internal shortcut strengthens a meet and proves another edge."""
    body = IRFunctionArtifact(0, (
        IRBlock(0, (branch("ax", 0, 10, 0),), successor_addrs=(10, 20)),
        IRBlock(10, (IRInstr("MOV", IRValue(MemSpace.REG, name="bx", size=2), (constant(1),), size=2, addr=10),),
                successor_addrs=(20,)),
        IRBlock(20, (branch("bx", 1, 30, 20),), successor_addrs=(30, 40)),
        IRBlock(30, successor_addrs=(50,)), IRBlock(40, successor_addrs=(50,)), IRBlock(50),
    ))
    result = analyze(body, frozenset({0, 10, 20, 30, 40, 50}), 50)
    assert result.converged
    assert result.infeasible_edges == ((0, 20), (20, 40))
    assert result.live_blocks == frozenset({0, 10, 20, 30, 50})


@pytest.mark.parametrize("surviving,new_dead,changed", [
    (frozenset({0, 10}), frozenset({(0, 20)}), False),
    (frozenset({0, 10}), frozenset({(20, 10)}), False),
    (frozenset({0, 10}), frozenset({(0, 10)}), True),
    (frozenset({0}), frozenset({(0, 20)}), True),
])
def test_only_internal_edges_or_changed_blocks_require_transfer(
    surviving: frozenset[int], new_dead: frozenset[tuple[int, int]], changed: bool,
) -> None:
    """Incoming edges from outside the cone are excluded from its meets too."""
    budget = [10]
    result = edge._kb_refinement_inputs_changed_8616(
        frozenset({0, 10}), surviving, new_dead, time.monotonic() + 5, budget,
    )
    assert result is changed
    assert budget[0] < 10


@pytest.mark.parametrize("expired,work_limit", [(True, 10), (False, 0), (False, 1)])
def test_unfinished_selection_does_not_claim_projection_equality(expired: bool, work_limit: int) -> None:
    """Deadline and work stops are typed non-results, with no renewed budget."""
    budget = [work_limit]
    deadline = time.monotonic() - 1 if expired else time.monotonic() + 5
    assert edge._kb_refinement_inputs_changed_8616(
        frozenset({0, 10}), frozenset({0, 10}), frozenset({(0, 20)}), deadline, budget,
    ) is None
    assert budget[0] <= work_limit
