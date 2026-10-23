"""Branch observations from a pure transfer must equal fresh snapshot replay."""

import time
from dataclasses import replace

import pytest

from inertia.ir import real16_edge_feasibility8616 as owner
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.ir.real16_path_memory8616 import PathMemory8616
from inertia.ir.ssa_function import build_x86_16_ir_predecessor_map
from tests.ir.test_x86_16_invocation_edge_refinement import _branch, _live_source_diamond, _value

pytestmark = pytest.mark.decompiler


def _run(artifact, *, pure=False, work=10000, iterations=64, **kwargs):
    return owner.invocation_feasible_scope_8616(
        artifact=artifact,
        dangerous=frozenset(block.addr for block in artifact.blocks),
        predecessor_map=build_x86_16_ir_predecessor_map(artifact),
        head_addr=0, call_block_addr=40, callsite_addr=40,
        seed={"ax": 0, "cx": 0}, seed_memory=PathMemory8616(),
        apply_service=lambda *_: False, iteration_limit=iterations,
        deadline=time.monotonic() + 5, work_limit=work,
        branch_snapshot_replay=(owner.BranchSnapshotReplay8616.PURE_TRANSFER
                                if pure else owner.BranchSnapshotReplay8616.OBSERVABLE),
        **kwargs,
    )


def _observations(result):
    # Early entry pruning changes how many branch observations are needed,
    # while these published proof results must remain identical.
    return (result.live_blocks, result.infeasible_edges,
            result.proven_edges, result.converged, result.call_cut)


def _long_branch():
    rows = tuple(IRInstr("MOV", IRValue(MemSpace.REG, name="cx", size=2),
                        (_value(i),), size=2, addr=i) for i in range(30))
    return IRFunctionArtifact(0, (
        IRBlock(0, (*rows, _branch(30, "bx", 0, 35)), successor_addrs=(35, 40)),
        IRBlock(35, (IRInstr("NOP", None, (), addr=35),), successor_addrs=(40,)),
        IRBlock(40, (IRInstr("RET", None, (), addr=40),)),
    ))


def test_pure_branch_transfer_fits_budget_without_reexecuting_rows():
    artifact = _long_branch()
    baseline = _run(artifact)
    actual = _run(artifact, pure=True, work=45)
    assert actual.converged
    assert _observations(actual) == _observations(baseline)
    assert actual.work_units < baseline.work_units
    assert not _run(artifact, work=45).converged


def test_refinement_uses_latest_round_branch_states():
    artifact = _live_source_diamond()
    baseline = _run(artifact)
    actual = _run(artifact, pure=True)
    assert _observations(actual) == _observations(baseline)
    assert actual.infeasible_edges == ((0, 20), (20, 30))
    assert 0 < actual.evaluated_cjmps <= baseline.evaluated_cjmps


@pytest.mark.parametrize("budget", [0, 1, 8, 20])
def test_incomplete_transfer_never_publishes_provisional_branches(budget):
    result = _run(_long_branch(), pure=True, work=budget)
    assert not result.converged
    assert not result.infeasible_edges


def test_unconverged_fixpoint_cannot_publish_collected_branch():
    result = _run(_live_source_diamond(), pure=True, iterations=1)
    assert not result.converged
    assert not result.infeasible_edges


def test_observable_call_handler_keeps_fresh_replay():
    artifact = IRFunctionArtifact(0, (
        IRBlock(0, (IRInstr("CALL", None, (_value(100),), addr=0),
                    _branch(1, "ax", 1, 35)), successor_addrs=(35, 40)),
        IRBlock(35, (IRInstr("NOP", None, (), addr=35),), successor_addrs=(40,)),
        IRBlock(40, (IRInstr("RET", None, (), addr=40),)),
    ))
    calls = []

    def apply_call(instruction, registers, memory):
        calls.append(instruction.addr)
        return False

    baseline = _run(artifact, apply_call=apply_call)
    expected_calls = len(calls)
    calls.clear()
    actual = _run(artifact, pure=True, apply_call=apply_call)
    assert len(calls) == expected_calls and expected_calls >= 2
    assert actual == baseline


def test_native_callee_keeps_identical_effects_with_less_charged_work(tmp_path, monkeypatch):
    from inertia.ir import real16_invocation_domain as domain
    from tests.ir.test_callee_local_feasibility import SHARED, native, world

    ctx, proof = world(tmp_path, bytes.fromhex("b80000") * 20 + SHARED)
    baseline_ctx = replace(ctx, work_units=0, accounted_work_units=0,
                           raw_facts=set(), normalized_facts=set(), classified_facts=set(),
                           materialized_facts=set(), checked_stores=0, failures=0)
    ctx.work_units = ctx.accounted_work_units = 0
    seed = domain._PathState8616(
        {"cs": native.LOAD_SEGMENT, "ss": native.LOAD_SEGMENT + 0x10, "esp": 0x100},
        PathMemory8616(),
    )
    actual = domain._simulate_callee_8616(ctx, proof, seed)
    assert isinstance(actual, dict), actual
    feasible = domain.invocation_feasible_scope_8616

    def fresh_replay(**kwargs):
        kwargs["branch_snapshot_replay"] = owner.BranchSnapshotReplay8616.OBSERVABLE
        return feasible(**kwargs)

    monkeypatch.setattr(domain, "invocation_feasible_scope_8616", fresh_replay)
    baseline = domain._simulate_callee_8616(baseline_ctx, proof, seed)
    assert actual == baseline
    assert ctx.raw_facts == ctx.normalized_facts == ctx.classified_facts == ctx.materialized_facts
    assert ctx.raw_facts == baseline_ctx.raw_facts
    assert ctx.failures == baseline_ctx.failures == 0
    assert ctx.work_units < baseline_ctx.work_units


def _guarded_expensive_loop():
    """Entry guards exclude a large error loop without assuming loop state."""
    expensive = tuple(IRInstr("NOP", None, (), addr=20) for _ in range(200))
    return IRFunctionArtifact(0, (
        IRBlock(0, (_branch(0, "cx", 0, 10),), successor_addrs=(10, 20)),
        IRBlock(10, (_branch(10, "ax", 0, 40),), successor_addrs=(20, 40)),
        IRBlock(20, (*expensive, IRInstr("JMP", None, (_value(20),), addr=20)),
                successor_addrs=(20,)),
        IRBlock(40, (IRInstr("RET", None, (), addr=40),)),
    ))


def test_pure_entry_chain_excludes_expensive_dead_loop_before_fixpoint():
    """Two stable entry guards need not transfer their unreachable error loop."""
    artifact = _guarded_expensive_loop()
    baseline = _run(artifact)
    assert baseline.converged
    assert baseline.live_blocks == frozenset({0, 10, 40})
    actual = _run(artifact, pure=True, work=100)
    assert actual.converged
    assert _observations(actual) == _observations(baseline)
    assert actual.work_units < 100


def test_completed_entry_pruning_does_not_repeat_the_same_fixpoint():
    """A round already run on its final pruned CFG needs no identical retry."""
    import sys

    artifact = _guarded_expensive_loop()
    calls = []
    code = owner._kb_fixpoint_8616.__code__

    def profile(frame, event, _argument):
        if event == "call" and frame.f_code is code:
            calls.append(1)

    previous = sys.getprofile()
    sys.setprofile(profile)
    try:
        actual = _run(artifact, pure=True)
    finally:
        sys.setprofile(previous)
    assert _observations(actual) == _observations(_run(artifact))
    assert calls == [1]


@pytest.mark.parametrize("work", [0, 1, 8, 20])
def test_entry_chain_exhaustion_never_publishes_early_edges(work):
    """Partial prefix/cone evaluation cannot publish its provisional guards."""
    actual = _run(_guarded_expensive_loop(), pure=True, work=work)
    assert not actual.converged
    assert not actual.infeasible_edges


def test_entry_chain_backedge_requires_the_original_must_meet():
    """An initially true entry condition can change on a reachable backedge."""
    artifact = _guarded_expensive_loop()
    head = artifact.blocks[0]
    changing = IRBlock(20, (
        IRInstr("MOV", IRValue(MemSpace.REG, name="cx", size=2), (_value(1),), addr=20),
    ), successor_addrs=(0, 40))
    loop = replace(artifact, blocks=(head, artifact.blocks[1], changing, artifact.blocks[3]))
    baseline = _run(loop)
    actual = _run(loop, pure=True)
    assert _observations(actual) == _observations(baseline)
    assert (0, 20) not in actual.infeasible_edges


@pytest.mark.parametrize("producer,method", [
    (owner._BranchTransferCollector8616, "__init__"),
    (owner._BranchTransferCollector8616, "__call__"),
    (owner._BranchTransferObservation8616, "__init__"),
    (owner, "_kb_entry_chain_edges_8616"),
    (owner, "_kb_entry_chain_scope_8616"),
])
def test_replaced_collector_keeps_native_callee_on_fresh_replay(tmp_path, monkeypatch, producer, method):
    from inertia.ir import real16_invocation_domain as domain
    from tests.ir.test_callee_local_feasibility import SHARED, native, world

    ctx, proof = world(tmp_path, SHARED)

    def untrusted(*_args, **_kwargs):
        raise AssertionError("A changed observation producer cannot authorize pure replay")

    monkeypatch.setattr(producer, method, untrusted)
    seed = domain._PathState8616(
        {"cs": native.LOAD_SEGMENT, "ss": native.LOAD_SEGMENT + 0x10, "esp": 0x100, "ax": 0},
        PathMemory8616(),
    )
    actual = domain._simulate_callee_8616(ctx, proof, seed)
    assert isinstance(actual, dict), actual
    assert actual[proof.callee.return_block_addrs[0]].registers["ax"] == 1
